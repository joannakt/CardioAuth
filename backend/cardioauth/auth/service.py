"""Authentication service: password login, TOTP second factor, server-side sessions.

Policy this module implements, and where each rule comes from:

===========================  ====================================================
Rule                         Source
===========================  ====================================================
Argon2id, rehash on login    DESIGN.md §7.1
5 failures → 15 min lock,    DESIGN.md §7.1 ("exponential thereafter" is implemented
doubling to a 24 h cap       with ``lockout_stage``; the 24 h cap is this build's
                             choice — the design gives no ceiling)
15 min idle / 8 h absolute   DESIGN.md §7.2, §11 Q4, both server-authoritative
5 min step-up window         DESIGN.md §7.2
TOTP: 6 digits, 30 s, ±1     DESIGN.md §7.1
Rotation on authentication   DESIGN.md §7.1 (fixation defence)
and on 2FA step-up
Session tokens hashed at     DESIGN.md §2.1, §7.1
rest, 256-bit opaque
2FA required for             DESIGN.md §7.1; enrol-at-first-login with a prompt (not a
physician/admin              block) for coordinators (§11 Q4)
===========================  ====================================================

The service owns its transaction boundary for *refusals*: a failed login commits the
attempt counter, the lockout and the audit row before it returns, so a refused request
cannot roll back the evidence that it happened.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cardioauth.audit.chain import AuditEntry
from cardioauth.audit.service import record as audit_record
from cardioauth.db.models import AppUser, TotpUsedCode, UserRecoveryCode, UserSession
from cardioauth.security import crypto, passwords, tokens, totp as totp_module
from cardioauth.settings import Settings, get_settings

logger = logging.getLogger(__name__)

EMAIL_MAX_LENGTH = 254


class InvalidEmailError(ValueError):
    """The submitted address is not usable as an account identifier (message is safe)."""


#: Reason codes that may appear in an audit ``detail``. Deliberately coarse and free of any
#: value the user typed — the audit log is visible to practice admins (§7.4).
class Reason(str, Enum):
    unknown_account = "unknown_account"
    bad_password = "bad_password"
    locked = "locked"
    inactive = "inactive"
    expired_idle = "expired_idle"
    expired_absolute = "expired_absolute"
    revoked = "revoked"
    unknown_token = "unknown_token"
    user_inactive = "user_inactive"
    signed_out = "signed_out"
    rotated = "rotated"
    revoked_by_user = "revoked_by_user"
    revoked_all = "revoked_all"
    invalid_code = "invalid_code"
    replayed_code = "replayed_code"
    not_enrolled = "not_enrolled"
    no_enrolment_in_progress = "no_enrolment_in_progress"
    second_factor_required = "second_factor_required"
    fresh_password_required = "fresh_password_required"


class LoginStatus(str, Enum):
    authenticated = "authenticated"
    totp_required = "totp_required"
    totp_enrolment_required = "totp_enrolment_required"
    invalid_credentials = "invalid_credentials"
    locked = "locked"
    inactive = "inactive"


@dataclass(frozen=True)
class RequestContext:
    """Request metadata that is safe to store hashed and to audit as identifiers only."""

    request_id: str | None = None
    ip: str | None = None
    user_agent: str | None = None


@dataclass
class LoginResult:
    status: LoginStatus
    user: AppUser | None = None
    raw_token: str | None = None
    session_row: UserSession | None = None
    lockout_minutes: int | None = None


@dataclass
class IssuedSession:
    raw_token: str
    row: UserSession


@dataclass
class SessionLookup:
    row: UserSession | None = None
    user: AppUser | None = None
    reason: Reason | None = None

    @property
    def ok(self) -> bool:
        return self.row is not None and self.reason is None


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Email normalisation
# ---------------------------------------------------------------------------
def normalize_email(value: str) -> str:
    """Normalise an account identifier: strip, NFKC, casefold the whole address.

    The database column is ``citext`` and the unique index is on the normalised value, so
    ``Ada@Example.ORG `` and ``ada@example.org`` are the same account and cannot both be
    created. Over-normalising (casefolding the local part) is deliberate: this is an
    internal tool where two accounts differing only in case would be an operator error, not
    a feature. No provider-specific rule (gmail dots, plus-addressing) is applied.
    """
    import unicodedata

    candidate = unicodedata.normalize("NFKC", value or "").strip().casefold()
    if not candidate or len(candidate) > EMAIL_MAX_LENGTH:
        raise InvalidEmailError("enter a valid email address")
    local, _, domain = candidate.partition("@")
    if not local or not domain or "." not in domain or " " in candidate or "@" in domain:
        raise InvalidEmailError("enter a valid email address")
    return candidate


def find_user(session: Session, email: str) -> AppUser | None:
    return session.execute(select(AppUser).where(AppUser.email == email)).scalar_one_or_none()


# ---------------------------------------------------------------------------
# Lockout
# ---------------------------------------------------------------------------
def lockout_minutes(stage: int, settings: Settings) -> int:
    """Backoff for the *next* lockout. ``stage`` = lockouts already completed.

    ``base * 2**stage`` capped at ``auth_lockout_max_minutes``: 15, 30, 60, … 1440 minutes.
    Per-user (not per-IP) per §7.1; the endpoint-level per-IP rate limit the design also
    requires is not part of this milestone.
    """
    minutes = settings.auth_lockout_base_minutes * (2 ** max(stage, 0))
    return min(minutes, settings.auth_lockout_max_minutes)


def _register_failure(session: Session, user: AppUser, settings: Settings, context: RequestContext) -> int | None:
    """Count a failed password attempt. Returns the lock duration in minutes, or None.

    Commits (with its audit entry) before returning: the attempt counter must survive the
    refused request.
    """
    user.failed_login_count += 1
    if user.failed_login_count < settings.auth_lockout_threshold:
        audit_record(
            session,
            AuditEntry(
                action="auth.login_failed",
                object_type="app_user",
                object_id=user.id,
                practice_id=user.practice_id,
                actor_user_id=user.id,
                actor_role=user.role,
                outcome="denied",
                request_id=context.request_id,
                detail={
                    "reason": Reason.bad_password.value,
                    "failed_login_count": user.failed_login_count,
                    "threshold": settings.auth_lockout_threshold,
                },
            ),
        )
        session.commit()
        return None

    minutes = lockout_minutes(user.lockout_stage, settings)
    user.failed_login_count = 0
    user.lockout_stage += 1
    user.locked_until = utcnow() + timedelta(minutes=minutes)
    audit_record(
        session,
        AuditEntry(
            action="auth.account_locked",
            object_type="app_user",
            object_id=user.id,
            practice_id=user.practice_id,
            actor_user_id=user.id,
            actor_role=user.role,
            outcome="denied",
            request_id=context.request_id,
            detail={
                "reason": Reason.locked.value,
                "lockout_stage": user.lockout_stage,
                "lock_minutes": minutes,
                "threshold": settings.auth_lockout_threshold,
            },
        ),
    )
    session.commit()
    return minutes


# ---------------------------------------------------------------------------
# Password login
# ---------------------------------------------------------------------------
def authenticate(
    session: Session,
    *,
    email: str,
    password: str,
    context: RequestContext | None = None,
    settings: Settings | None = None,
) -> LoginResult:
    """Verify a password and decide what the session may do next."""
    settings = settings or get_settings()
    context = context or RequestContext()
    normalized = normalize_email(email)
    user = find_user(session, normalized)

    if user is None:
        # Same work as a real verification: an unknown account must not be distinguishable
        # from a wrong password by response time.
        passwords.verify_password(_dummy_hash(settings), password, settings=settings)
        audit_record(
            session,
            AuditEntry(
                action="auth.login_failed",
                object_type="app_user",
                outcome="denied",
                request_id=context.request_id,
                detail={"reason": Reason.unknown_account.value},
            ),
        )
        session.commit()
        return LoginResult(status=LoginStatus.invalid_credentials)

    if user.locked_until is not None and user.locked_until > utcnow():
        remaining = int((user.locked_until - utcnow()).total_seconds() // 60) + 1
        audit_record(
            session,
            AuditEntry(
                action="auth.login_failed",
                object_type="app_user",
                object_id=user.id,
                practice_id=user.practice_id,
                actor_user_id=user.id,
                actor_role=user.role,
                outcome="denied",
                request_id=context.request_id,
                detail={"reason": Reason.locked.value, "lock_minutes_remaining": remaining},
            ),
        )
        session.commit()
        return LoginResult(status=LoginStatus.locked, user=user, lockout_minutes=remaining)

    if not user.is_active:
        audit_record(
            session,
            AuditEntry(
                action="auth.login_failed",
                object_type="app_user",
                object_id=user.id,
                practice_id=user.practice_id,
                actor_user_id=user.id,
                actor_role=user.role,
                outcome="denied",
                request_id=context.request_id,
                detail={"reason": Reason.inactive.value},
            ),
        )
        session.commit()
        return LoginResult(status=LoginStatus.inactive, user=user)

    check = passwords.verify_password(user.password_hash, password, settings=settings)
    if not check.ok:
        minutes = _register_failure(session, user, settings, context)
        if minutes is not None:
            return LoginResult(status=LoginStatus.locked, user=user, lockout_minutes=minutes)
        return LoginResult(status=LoginStatus.invalid_credentials, user=user)

    # Successful password: clear the failure state, rehash if the parameters moved on.
    user.failed_login_count = 0
    user.lockout_stage = 0
    user.locked_until = None
    if check.needs_rehash:
        user.password_hash = passwords.hash_password(password, settings=settings)

    enrolled = user.totp_secret_enc is not None and user.totp_enrolled_at is not None
    requires_factor = user.role in settings.totp_required_role_set

    if enrolled:
        status = LoginStatus.totp_required
        issued = start_session(session, user, context=context, settings=settings)
    elif requires_factor:
        # A physician/admin may not operate without a second factor; the password-accepted
        # session exists only to let them enrol one (§7.1, §11 Q4).
        status = LoginStatus.totp_enrolment_required
        issued = start_session(session, user, context=context, settings=settings)
    else:
        # Coordinator without a factor: allowed in, flagged for the admin view (§11 Q4).
        # ``two_factor_verified_at`` stays NULL — it means "a second factor was verified in
        # this session", never "we decided you do not need one".
        status = LoginStatus.authenticated
        issued = start_session(session, user, context=context, settings=settings)

    audit_record(
        session,
        AuditEntry(
            action="auth.login_succeeded",
            object_type="app_user",
            object_id=user.id,
            practice_id=user.practice_id,
            actor_user_id=user.id,
            actor_role=user.role,
            session_id=issued.row.id,
            request_id=context.request_id,
            detail={
                "role": user.role,
                "second_factor": (
                    ("pending" if requires_factor or enrolled else "not_enrolled")
                ),
                "two_factor_verified": issued.row.two_factor_verified_at is not None,
            },
        ),
    )
    session.commit()
    return LoginResult(status=status, user=user, raw_token=issued.raw_token, session_row=issued.row)


def _dummy_hash(settings: Settings) -> str:
    """A hash of a random throwaway value, used to equalise unknown-account timing."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        import secrets

        _DUMMY_HASH = passwords.hash_password(secrets.token_urlsafe(32), settings=settings)
    return _DUMMY_HASH


_DUMMY_HASH: str | None = None


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
def start_session(
    session: Session,
    user: AppUser,
    *,
    context: RequestContext | None = None,
    two_factor_verified: bool = False,
    reauth: bool = False,
    settings: Settings | None = None,
) -> IssuedSession:
    """Create a server-side session. The raw token is returned once and never stored.

    ``two_factor_verified`` and ``reauth`` are booleans, not timestamps, on purpose: the
    moment the session is issued *is* the moment the criterion was met (that is what rotation
    immediately after a verification means). Deriving both inside this function keeps
    ``two_factor_verified_at == issued_at`` by construction, which is the ordering the
    database constraint ``ck_session_totp_after_issue`` requires — passing a timestamp
    computed a few microseconds earlier by the caller is exactly the bug that constraint
    exists to catch.
    """
    settings = settings or get_settings()
    context = context or RequestContext()
    now = utcnow()
    raw_token = tokens.new_session_token()
    two_factor_verified_at = now if two_factor_verified else None
    reauth_at = now if reauth else None
    row = UserSession(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=tokens.hash_session_token(raw_token),
        issued_at=now,
        last_seen_at=now,
        absolute_expires_at=now + timedelta(hours=settings.session_absolute_hours),
        idle_expires_at=now + timedelta(minutes=settings.session_idle_minutes),
        ip_hash=crypto.hash_request_fingerprint(context.ip, settings=settings),
        user_agent_hash=crypto.hash_request_fingerprint(context.user_agent, settings=settings),
        two_factor_verified_at=two_factor_verified_at,
        reauth_at=reauth_at,
    )
    session.add(row)
    session.flush()
    return IssuedSession(raw_token=raw_token, row=row)


def rotate_session(
    session: Session,
    old: UserSession,
    *,
    context: RequestContext | None = None,
    two_factor_verified: bool = False,
    reauth: bool = False,
    reason: Reason = Reason.rotated,
    settings: Settings | None = None,
) -> IssuedSession:
    """Revoke *old* and issue a new session — session fixation defence (§7.1).

    A privilege change must not keep a token that an attacker may already hold.
    """
    user = session.get(AppUser, old.user_id)
    assert user is not None  # FK guarantees it
    now = utcnow()
    if old.revoked_at is None:
        old.revoked_at = now
    issued = start_session(
        session,
        user,
        context=context,
        two_factor_verified=two_factor_verified,
        reauth=reauth,
        settings=settings,
    )
    audit_record(
        session,
        AuditEntry(
            action="auth.session_revoked",
            object_type="user_session",
            object_id=old.id,
            practice_id=user.practice_id,
            actor_user_id=user.id,
            actor_role=user.role,
            session_id=issued.row.id,
            request_id=(context or RequestContext()).request_id,
            detail={"reason": reason.value, "rotated_into": str(issued.row.id)},
        ),
    )
    return issued


def load_session(
    session: Session,
    *,
    raw_token: str,
    settings: Settings | None = None,
    now: datetime | None = None,
) -> SessionLookup:
    """Resolve a raw cookie value to a live session, or explain why it is not usable.

    Idle and absolute timeouts are evaluated here, server-side, from the stored timestamps
    — never from anything the client sends (§7.2).
    """
    settings = settings or get_settings()
    now = now or utcnow()
    row = session.execute(
        select(UserSession).where(UserSession.token_hash == tokens.hash_session_token(raw_token))
    ).scalar_one_or_none()
    if row is None:
        return SessionLookup(reason=Reason.unknown_token)
    if row.revoked_at is not None:
        return SessionLookup(row=row, reason=Reason.revoked)
    if now >= row.absolute_expires_at:
        return SessionLookup(row=row, reason=Reason.expired_absolute)
    if now >= row.idle_expires_at:
        return SessionLookup(row=row, reason=Reason.expired_idle)
    user = session.get(AppUser, row.user_id)
    if user is None or not user.is_active:
        return SessionLookup(row=row, reason=Reason.user_inactive)
    return SessionLookup(row=row, user=user)


def touch_session(
    session: Session, row: UserSession, *, settings: Settings | None = None, now: datetime | None = None
) -> None:
    """Slide the idle window on an authenticated request (never past the absolute cap)."""
    settings = settings or get_settings()
    now = now or utcnow()
    row.last_seen_at = now
    slid = now + timedelta(minutes=settings.session_idle_minutes)
    row.idle_expires_at = min(slid, row.absolute_expires_at)


def expire_session(session: Session, row: UserSession, *, reason: Reason, context: RequestContext | None = None) -> None:
    """Mark a session that has already timed out (so the session list cannot show it)."""
    if row.revoked_at is None:
        row.revoked_at = utcnow()
    user = session.get(AppUser, row.user_id)
    audit_record(
        session,
        AuditEntry(
            action="auth.session_expired",
            object_type="user_session",
            object_id=row.id,
            practice_id=user.practice_id if user else None,
            actor_user_id=row.user_id,
            actor_role=user.role if user else None,
            session_id=row.id,
            request_id=(context or RequestContext()).request_id,
            detail={"reason": reason.value},
        ),
    )


def revoke_session(
    session: Session,
    row: UserSession,
    *,
    reason: Reason,
    context: RequestContext | None = None,
) -> None:
    if row.revoked_at is None:
        row.revoked_at = utcnow()
    user = session.get(AppUser, row.user_id)
    audit_record(
        session,
        AuditEntry(
            action="auth.session_revoked",
            object_type="user_session",
            object_id=row.id,
            practice_id=user.practice_id if user else None,
            actor_user_id=user.id if user else row.user_id,
            actor_role=user.role if user else None,
            session_id=row.id,
            request_id=(context or RequestContext()).request_id,
            detail={"reason": reason.value},
        ),
    )


def revoke_all_sessions(
    session: Session,
    *,
    user: AppUser,
    reason: Reason,
    except_session_id: uuid.UUID | None = None,
    context: RequestContext | None = None,
) -> int:
    """Revoke every live session of *user*, optionally sparing one. Returns the count."""
    now = utcnow()
    stmt = (
        update(UserSession)
        .where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    if except_session_id is not None:
        stmt = stmt.where(UserSession.id != except_session_id)
    result = session.execute(stmt)
    count = int(result.rowcount or 0)
    audit_record(
        session,
        AuditEntry(
            action="auth.sessions_revoked_all",
            object_type="app_user",
            object_id=user.id,
            practice_id=user.practice_id,
            actor_user_id=user.id,
            actor_role=user.role,
            session_id=except_session_id,
            request_id=(context or RequestContext()).request_id,
            detail={"reason": reason.value, "sessions_revoked": count, "kept_current": except_session_id is not None},
        ),
    )
    return count


def list_sessions(
    session: Session, *, user_id: uuid.UUID, settings: Settings | None = None, now: datetime | None = None
) -> list[UserSession]:
    """Live sessions only: not revoked and not timed out, newest first."""
    now = now or utcnow()
    return list(
        session.execute(
            select(UserSession)
            .where(
                UserSession.user_id == user_id,
                UserSession.revoked_at.is_(None),
                UserSession.idle_expires_at > now,
                UserSession.absolute_expires_at > now,
            )
            .order_by(UserSession.issued_at.desc())
        ).scalars()
    )


def count_live_sessions(session: Session, *, user_id: uuid.UUID, now: datetime | None = None) -> int:
    now = now or utcnow()
    return int(
        session.execute(
            select(func.count())
            .select_from(UserSession)
            .where(
                UserSession.user_id == user_id,
                UserSession.revoked_at.is_(None),
                UserSession.absolute_expires_at > now,
            )
        ).scalar_one()
    )


# ---------------------------------------------------------------------------
# Second factor: TOTP and recovery codes
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FactorResult:
    ok: bool
    reason: Reason | None = None
    method: str | None = None  # 'totp' | 'recovery_code'


def _consume_totp_code(session: Session, user: AppUser, code: str, settings: Settings) -> bool:
    """True when the code is valid *and* had not been used in that time step before."""
    if user.totp_secret_enc is None:
        return False
    secret = crypto.decrypt_secret(user.totp_secret_enc, settings=settings)
    verification = totp_module.verify_code(secret, code, settings=settings)
    if not verification.ok:
        return False
    digest = crypto.fingerprint_totp_code(code, settings=settings)
    try:
        with session.begin_nested():
            session.add(
                TotpUsedCode(
                    id=uuid.uuid4(),
                    user_id=user.id,
                    code_hash=digest,
                    time_step=int(verification.time_step or 0),
                )
            )
            session.flush()
    except IntegrityError:
        # The unique constraint refused the row: this (code, step) pair was already used.
        return False
    return True


def _consume_recovery_code(session: Session, user: AppUser, code: str, settings: Settings) -> bool:
    digest = crypto.fingerprint_recovery_code(code, settings=settings)
    row = session.execute(
        select(UserRecoveryCode).where(
            UserRecoveryCode.user_id == user.id,
            UserRecoveryCode.code_hash == digest,
            UserRecoveryCode.used_at.is_(None),
            UserRecoveryCode.revoked_at.is_(None),
        )
    ).scalar_one_or_none()
    if row is None:
        return False
    row.used_at = utcnow()
    return True


def verify_second_factor(
    session: Session,
    user: AppUser,
    *,
    code: str,
    context: RequestContext | None = None,
    settings: Settings | None = None,
    audit_failure: bool = True,
) -> FactorResult:
    """Accept a TOTP code or a one-time recovery code, consuming it exactly once."""
    settings = settings or get_settings()
    context = context or RequestContext()
    if user.totp_secret_enc is None and user.totp_enrolled_at is None:
        return FactorResult(ok=False, reason=Reason.not_enrolled)

    if totp_module.looks_like_recovery_code(code, settings=settings):
        used_recovery = _consume_recovery_code(session, user, code, settings)
        if used_recovery:
            audit_record(
                session,
                AuditEntry(
                    action="auth.recovery_code_used",
                    object_type="app_user",
                    object_id=user.id,
                    practice_id=user.practice_id,
                    actor_user_id=user.id,
                    actor_role=user.role,
                    request_id=context.request_id,
                    detail={"method": "recovery_code"},
                ),
            )
            return FactorResult(ok=True, method="recovery_code")
        return _factor_failed(session, user, context, reason=Reason.invalid_code, settings=settings,
                              audit_failure=audit_failure)

    if _consume_totp_code(session, user, code, settings):
        return FactorResult(ok=True, method="totp")

    # Distinguish "wrong code" from "already used" for the audit trail only; the API answer
    # is identical for both (401), so a replayed code tells the caller nothing extra.
    reason = Reason.invalid_code
    secret = crypto.decrypt_secret(user.totp_secret_enc, settings=settings) if user.totp_secret_enc else None
    if secret is not None and totp_module.verify_code(secret, code, settings=settings).ok:
        reason = Reason.replayed_code
    return _factor_failed(session, user, context, reason=reason, settings=settings, audit_failure=audit_failure)


def _factor_failed(
    session: Session,
    user: AppUser,
    context: RequestContext,
    *,
    reason: Reason,
    settings: Settings,
    audit_failure: bool = True,
) -> FactorResult:
    if audit_failure:
        audit_record(
            session,
            AuditEntry(
                action="auth.totp_failed",
                object_type="app_user",
                object_id=user.id,
                practice_id=user.practice_id,
                actor_user_id=user.id,
                actor_role=user.role,
                outcome="denied",
                request_id=context.request_id,
                detail={"reason": reason.value},
            ),
        )
    return FactorResult(ok=False, reason=reason)


def complete_second_factor(
    session: Session,
    *,
    pending: UserSession,
    user: AppUser,
    code: str,
    context: RequestContext | None = None,
    settings: Settings | None = None,
) -> tuple[FactorResult, IssuedSession | None]:
    """Verify the factor and rotate the pending session into a fully authenticated one."""
    settings = settings or get_settings()
    context = context or RequestContext()
    result = verify_second_factor(session, user, code=code, context=context, settings=settings)
    if not result.ok:
        session.commit()  # keep the failure evidence
        return result, None

    # Note: ``reauth_at`` is deliberately NOT set here. A login is an authentication, not a
    # step-up: sensitive actions (§7.2) still require an explicit re-authentication through
    # POST /api/auth/step-up, which is the stricter reading of "re-auth within a short
    # recent window".
    issued = rotate_session(session, pending, context=context, two_factor_verified=True, settings=settings)
    audit_record(
        session,
        AuditEntry(
            action="auth.totp_succeeded",
            object_type="app_user",
            object_id=user.id,
            practice_id=user.practice_id,
            actor_user_id=user.id,
            actor_role=user.role,
            session_id=issued.row.id,
            request_id=context.request_id,
            detail={"method": result.method or "totp"},
        ),
    )
    session.commit()
    return result, issued


# ---------------------------------------------------------------------------
# Enrolment, disable, recovery codes
# ---------------------------------------------------------------------------
def begin_enrolment(session: Session, user: AppUser, *, settings: Settings | None = None) -> dict[str, object]:
    """Create (or replace) a pending TOTP secret and return the enrolment payload.

    The secret is stored **encrypted** immediately and ``totp_enrolled_at`` stays NULL until a
    code proves possession, so an interrupted enrolment never leaves a factor that can be
    bypassed or a session that looks verified.
    """
    settings = settings or get_settings()
    secret = totp_module.generate_secret()
    user.totp_secret_enc = crypto.encrypt_secret(secret, settings=settings)
    user.totp_enrolled_at = None
    account = user.email
    payload = totp_module.otpauth_payload(secret, account=account, settings=settings)
    session.flush()
    return payload


def activate_enrolment(
    session: Session,
    user: AppUser,
    *,
    code: str,
    context: RequestContext | None = None,
    settings: Settings | None = None,
) -> list[str]:
    """Prove possession of the pending secret; issue recovery codes once. Returns plaintext."""
    settings = settings or get_settings()
    context = context or RequestContext()
    if user.totp_secret_enc is None:
        raise FactorNotEnrolled(Reason.no_enrolment_in_progress)
    if not _consume_totp_code(session, user, code, settings):
        _factor_failed(session, user, context, reason=Reason.invalid_code, settings=settings)
        session.commit()
        raise FactorFailed(Reason.invalid_code)

    user.totp_enrolled_at = utcnow()
    codes = issue_recovery_codes(session, user, context=context, settings=settings, audit=True)
    audit_record(
        session,
        AuditEntry(
            action="auth.totp_enrolled",
            object_type="app_user",
            object_id=user.id,
            practice_id=user.practice_id,
            actor_user_id=user.id,
            actor_role=user.role,
            request_id=context.request_id,
            detail={"recovery_code_count": len(codes), "digits": settings.totp_digits,
                    "period_seconds": settings.totp_period_seconds, "drift_steps": settings.totp_drift_steps},
        ),
    )
    return codes


def issue_recovery_codes(
    session: Session,
    user: AppUser,
    *,
    context: RequestContext | None = None,
    settings: Settings | None = None,
    audit: bool = False,
) -> list[str]:
    """Revoke existing unused codes and issue a fresh set. Plaintext is returned once."""
    settings = settings or get_settings()
    context = context or RequestContext()
    now = utcnow()
    session.execute(
        update(UserRecoveryCode)
        .where(UserRecoveryCode.user_id == user.id, UserRecoveryCode.used_at.is_(None),
               UserRecoveryCode.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    plaintext = totp_module.generate_recovery_codes(settings=settings)
    for code in plaintext:
        session.add(
            UserRecoveryCode(
                id=uuid.uuid4(),
                user_id=user.id,
                code_hash=crypto.fingerprint_recovery_code(code, settings=settings),
            )
        )
    if audit:
        audit_record(
            session,
            AuditEntry(
                action="auth.recovery_codes_issued",
                object_type="app_user",
                object_id=user.id,
                practice_id=user.practice_id,
                actor_user_id=user.id,
                actor_role=user.role,
                request_id=context.request_id,
                detail={"recovery_code_count": len(plaintext)},
            ),
        )
    return plaintext


def count_unused_recovery_codes(session: Session, *, user_id: uuid.UUID) -> int:
    return int(
        session.execute(
            select(func.count())
            .select_from(UserRecoveryCode)
            .where(
                UserRecoveryCode.user_id == user_id,
                UserRecoveryCode.used_at.is_(None),
                UserRecoveryCode.revoked_at.is_(None),
            )
        ).scalar_one()
    )


class FactorFailed(RuntimeError):
    def __init__(self, reason: Reason) -> None:
        super().__init__(reason.value)
        self.reason = reason


class FactorNotEnrolled(RuntimeError):
    def __init__(self, reason: Reason = Reason.not_enrolled) -> None:
        super().__init__(reason.value)
        self.reason = reason


class FreshCheckFailed(RuntimeError):
    """A sensitive operation was refused because the caller did not re-prove identity."""

    def __init__(self, reason: Reason) -> None:
        super().__init__(reason.value)
        self.reason = reason


def require_fresh_identity(
    session: Session,
    user: AppUser,
    *,
    password: str,
    code: str | None = None,
    context: RequestContext | None = None,
    settings: Settings | None = None,
) -> None:
    """Password (and the factor, when enrolled) again — the precondition for disable,
    re-enrol and recovery-code rotation, and the body of a step-up (§7.2).

    Raises :class:`FreshCheckFailed` and audits ``auth.step_up_failed`` on refusal.
    """
    settings = settings or get_settings()
    context = context or RequestContext()
    ok = passwords.verify_password(user.password_hash, password, settings=settings).ok
    method = "password"
    if ok and user.totp_secret_enc is not None and user.totp_enrolled_at is not None:
        if not code:
            _audit_step_up_failure(session, user, context, reason=Reason.second_factor_required)
            raise FreshCheckFailed(Reason.second_factor_required)
        factor = verify_second_factor(session, user, code=code, context=context, settings=settings)
        ok = factor.ok
        method = factor.method or "totp"
    if not ok:
        _audit_step_up_failure(
            session,
            user,
            context,
            reason=Reason.bad_password if not passwords.verify_password(
                user.password_hash, password, settings=settings
            ).ok else Reason.invalid_code,
        )
        raise FreshCheckFailed(Reason.bad_password)
    audit_record(
        session,
        AuditEntry(
            action="auth.step_up_succeeded",
            object_type="app_user",
            object_id=user.id,
            practice_id=user.practice_id,
            actor_user_id=user.id,
            actor_role=user.role,
            request_id=context.request_id,
            detail={"method": method},
        ),
    )


def _audit_step_up_failure(
    session: Session, user: AppUser, context: RequestContext, *, reason: Reason
) -> None:
    audit_record(
        session,
        AuditEntry(
            action="auth.step_up_failed",
            object_type="app_user",
            object_id=user.id,
            practice_id=user.practice_id,
            actor_user_id=user.id,
            actor_role=user.role,
            outcome="denied",
            request_id=context.request_id,
            detail={"reason": reason.value},
        ),
    )


def disable_second_factor(
    session: Session,
    user: AppUser,
    *,
    password: str,
    code: str | None,
    context: RequestContext | None = None,
    settings: Settings | None = None,
) -> None:
    """Remove the second factor after a fresh password+factor check (§7.1, task item 2)."""
    settings = settings or get_settings()
    context = context or RequestContext()
    require_fresh_identity(session, user, password=password, code=code, context=context, settings=settings)
    user.totp_secret_enc = None
    user.totp_enrolled_at = None
    session.execute(
        update(UserRecoveryCode)
        .where(UserRecoveryCode.user_id == user.id, UserRecoveryCode.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
    audit_record(
        session,
        AuditEntry(
            action="auth.totp_disabled",
            object_type="app_user",
            object_id=user.id,
            practice_id=user.practice_id,
            actor_user_id=user.id,
            actor_role=user.role,
            request_id=context.request_id,
            detail={"role": user.role},
        ),
    )


def rotate_recovery_codes(
    session: Session,
    user: AppUser,
    *,
    password: str,
    code: str | None,
    context: RequestContext | None = None,
    settings: Settings | None = None,
) -> list[str]:
    settings = settings or get_settings()
    context = context or RequestContext()
    require_fresh_identity(session, user, password=password, code=code, context=context, settings=settings)
    return issue_recovery_codes(session, user, context=context, settings=settings, audit=True)


def step_up(
    session: Session,
    *,
    row: UserSession,
    user: AppUser,
    password: str,
    code: str | None,
    context: RequestContext | None = None,
    settings: Settings | None = None,
) -> IssuedSession:
    """Re-authenticate and record it on the (rotated) session as ``reauth_at``."""
    settings = settings or get_settings()
    context = context or RequestContext()
    try:
        require_fresh_identity(session, user, password=password, code=code, context=context, settings=settings)
    except FreshCheckFailed:
        session.commit()  # the failed attempt must be recorded even though we refuse
        raise
    issued = rotate_session(
        session,
        row,
        context=context,
        two_factor_verified=row.two_factor_verified_at is not None,
        reauth=True,
        settings=settings,
    )
    session.commit()
    return issued


def mark_logout(
    session: Session, *, row: UserSession, user: AppUser, context: RequestContext | None = None
) -> None:
    """Revoke the presented session server-side and record it (§7.1, task item 3)."""
    context = context or RequestContext()
    row.revoked_at = row.revoked_at or utcnow()
    audit_record(
        session,
        AuditEntry(
            action="auth.logout",
            object_type="user_session",
            object_id=row.id,
            practice_id=user.practice_id,
            actor_user_id=user.id,
            actor_role=user.role,
            session_id=row.id,
            request_id=context.request_id,
            detail={"reason": Reason.signed_out.value},
        ),
    )


def is_recent_reauth(row: UserSession, *, settings: Settings | None = None, now: datetime | None = None) -> bool:
    """True when this session re-authenticated inside the step-up window (§7.2: 5 minutes)."""
    settings = settings or get_settings()
    if row.reauth_at is None:
        return False
    now = now or utcnow()
    return now - row.reauth_at <= timedelta(minutes=settings.session_reauth_minutes)


def session_meets_factor_policy(
    row: UserSession, user: AppUser, *, settings: Settings | None = None
) -> bool:
    """Whether this session may reach protected routes, given the user's role and enrolment.

    * a session whose second factor was verified in-place: yes;
    * a user with no factor enrolled whose role does not require one (coordinator): yes;
    * anything else (pending factor, or a role that must have a factor and has none): no.
    """
    settings = settings or get_settings()
    if row.two_factor_verified_at is not None:
        return True
    enrolled = user.totp_secret_enc is not None and user.totp_enrolled_at is not None
    return not enrolled and user.role not in settings.totp_required_role_set


__all__ = [
    "FactorFailed",
    "FactorNotEnrolled",
    "FactorResult",
    "FreshCheckFailed",
    "InvalidEmailError",
    "IssuedSession",
    "LoginResult",
    "LoginStatus",
    "Reason",
    "RequestContext",
    "SessionLookup",
    "activate_enrolment",
    "authenticate",
    "begin_enrolment",
    "complete_second_factor",
    "count_live_sessions",
    "count_unused_recovery_codes",
    "disable_second_factor",
    "expire_session",
    "find_user",
    "is_recent_reauth",
    "issue_recovery_codes",
    "list_sessions",
    "load_session",
    "lockout_minutes",
    "mark_logout",
    "normalize_email",
    "require_fresh_identity",
    "revoke_all_sessions",
    "revoke_session",
    "rotate_recovery_codes",
    "rotate_session",
    "start_session",
    "step_up",
    "touch_session",
    "utcnow",
    "verify_second_factor",
]
