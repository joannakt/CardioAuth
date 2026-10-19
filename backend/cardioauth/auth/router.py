"""``/api/auth`` — login, second factor, sessions, step-up (task scope items 5 and 4).

Endpoint map:

=========================================  ==========================  =====================
Endpoint                                    Auth required               Audited as
=========================================  ==========================  =====================
POST /api/auth/login                        none                        auth.login_succeeded /
                                                                        auth.login_failed /
                                                                        auth.account_locked
POST /api/auth/2fa/verify                   live session (may be       auth.totp_succeeded /
                                            pending 2FA)                auth.totp_failed /
                                                                        auth.recovery_code_used
POST /api/auth/logout                       live session (incl. pending) auth.logout
GET  /api/auth/me                           live session                —
GET  /api/auth/sessions                     authenticated               —
POST /api/auth/sessions/{id}/revoke         authenticated               auth.session_revoked
POST /api/auth/sessions/revoke-all          authenticated               auth.sessions_revoked_all
POST /api/auth/step-up                      live session                auth.step_up_succeeded /
                                                                        auth.step_up_failed
POST /api/auth/totp/enrol                   live session                —
POST /api/auth/totp/activate                live session (pending 2FA)  auth.totp_enrolled /
                                                                        auth.recovery_codes_issued
POST /api/auth/totp/disable                 authenticated + step-up     auth.totp_disabled
POST /api/auth/totp/recovery-codes          authenticated + step-up     auth.recovery_codes_issued
=========================================  ==========================  =====================

The cookie is opaque, ``HttpOnly``, ``SameSite`` per settings, ``Secure`` outside dev and
``Path=/`` (§7.1). Every login and every successful second-factor verification **rotates**
the session: the previous token is revoked server-side and a new one is issued.
"""

from __future__ import annotations

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from cardioauth.auth import service
from cardioauth.auth.deps import (
    AuthContext,
    current_auth,
    get_db,
    request_context,
    require_authenticated,
)
from cardioauth.auth.schemas import (
    AuthStateOut,
    CodeRequest,
    DisableTotpRequest,
    LoginRequest,
    MessageOut,
    RecoveryCodesOut,
    RevokeAllOut,
    RevokeAllRequest,
    SessionListView,
    SessionOut,
    StepUpRequest,
)
from cardioauth.db.models import AppUser, UserSession
from cardioauth.settings import Settings, get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Cookie helpers
# ---------------------------------------------------------------------------
def set_session_cookie(response: Response, raw_token: str, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    response.set_cookie(
        key=settings.session_cookie_name,
        value=raw_token,
        httponly=True,
        samesite=settings.session_cookie_samesite,
        secure=settings.cookie_secure,
        path="/",
        max_age=settings.session_absolute_hours * 3600,
    )


def clear_session_cookie(response: Response, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
        httponly=True,
        samesite=settings.session_cookie_samesite,
        secure=settings.cookie_secure,
    )


def _error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})


def _state(
    state: str,
    user: AppUser,
    row: UserSession | None,
    *,
    settings: Settings,
    session: Session | None = None,
) -> AuthStateOut:
    enrolled = user.totp_secret_enc is not None and user.totp_enrolled_at is not None
    return AuthStateOut(
        status=state,
        user_id=user.id,
        role=user.role,
        practice_id=user.practice_id,
        totp_enrolled=enrolled,
        two_factor_verified=bool(row and row.two_factor_verified_at is not None),
        totp_enrolment_required=(not enrolled) and user.role in settings.totp_required_role_set,
        recovery_codes_remaining=(
            service.count_unused_recovery_codes(session, user_id=user.id) if (session and enrolled) else None
        ),
        reauth_at=row.reauth_at if row else None,
        reauth_required=(not service.is_recent_reauth(row, settings=settings)) if row else True,
    )


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
@router.post("/login", response_model=AuthStateOut)
def login(
    payload: LoginRequest,
    response: Response,
    session: Annotated[Session, Depends(get_db)],
    context: Annotated[service.RequestContext, Depends(request_context)],
) -> AuthStateOut:
    settings = get_settings()
    try:
        result = service.authenticate(
            session, email=payload.email, password=payload.password, context=context, settings=settings
        )
    except service.InvalidEmailError:
        # Identical answer to a wrong password: the shape of the address is not an oracle for
        # which accounts exist.
        raise _error(status.HTTP_401_UNAUTHORIZED, "invalid_credentials", "email or password is incorrect") from None

    if result.status is service.LoginStatus.invalid_credentials:
        raise _error(status.HTTP_401_UNAUTHORIZED, "invalid_credentials", "email or password is incorrect")
    if result.status is service.LoginStatus.locked:
        headers = {"Retry-After": str((result.lockout_minutes or 1) * 60)}
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail={
                "code": "account_locked",
                "message": "too many failed attempts; this account is temporarily locked",
                "retry_after_minutes": result.lockout_minutes,
            },
            headers=headers,
        )
    if result.status is service.LoginStatus.inactive:
        raise _error(status.HTTP_403_FORBIDDEN, "account_inactive", "this account is not active")

    assert result.user is not None and result.raw_token is not None and result.session_row is not None
    set_session_cookie(response, result.raw_token, settings)
    return _state(result.status.value, result.user, result.session_row, settings=settings, session=session)


# ---------------------------------------------------------------------------
# Second factor
# ---------------------------------------------------------------------------
@router.post("/2fa/verify", response_model=AuthStateOut)
def verify_second_factor(
    payload: CodeRequest,
    response: Response,
    auth: Annotated[AuthContext, Depends(current_auth)],
) -> AuthStateOut:
    if service.session_meets_factor_policy(auth.row, auth.user, settings=auth.settings):
        raise _error(
            status.HTTP_409_CONFLICT,
            "second_factor_not_required",
            "this session has already completed two-factor authentication",
        )
    if auth.user.totp_secret_enc is None or auth.user.totp_enrolled_at is None:
        raise _error(
            status.HTTP_400_BAD_REQUEST,
            "totp_not_enrolled",
            "no authenticator app is enrolled for this account; enrol one to continue",
        )

    result, issued = service.complete_second_factor(
        auth.session,
        pending=auth.row,
        user=auth.user,
        code=payload.code,
        context=auth.context,
        settings=auth.settings,
    )
    if not result.ok or issued is None:
        raise _error(
            status.HTTP_401_UNAUTHORIZED,
            "invalid_code",
            "that code is not valid (it may have expired or already been used)",
        )
    set_session_cookie(response, issued.raw_token, auth.settings)
    return _state("authenticated", auth.user, issued.row, settings=auth.settings, session=auth.session)


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
def _session_out(row: UserSession, current: UserSession) -> SessionOut:
    return SessionOut(
        id=row.id,
        issued_at=row.issued_at,
        last_seen_at=row.last_seen_at,
        idle_expires_at=row.idle_expires_at,
        absolute_expires_at=row.absolute_expires_at,
        two_factor_verified=row.two_factor_verified_at is not None,
        reauth_at=row.reauth_at,
        current=row.id == current.id,
        request_fingerprint=(row.ip_hash.hex()[:12] if row.ip_hash else None),
    )


@router.get("/sessions", response_model=SessionListView)
def list_sessions(auth: Annotated[AuthContext, Depends(require_authenticated)]) -> SessionListView:
    rows = service.list_sessions(auth.session, user_id=auth.user.id, settings=auth.settings)
    return SessionListView(
        sessions=[_session_out(row, auth.row) for row in rows],
        count=len(rows),
    )


@router.post("/sessions/{session_id}/revoke", response_model=MessageOut)
def revoke_session(
    session_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require_authenticated)],
) -> MessageOut:
    row = auth.session.get(UserSession, session_id)
    if row is None or row.user_id != auth.user.id:
        # Not an oracle for other users' session ids: a foreign id is a 404, same as unknown.
        raise _error(status.HTTP_404_NOT_FOUND, "session_not_found", "no such session")
    if row.revoked_at is not None:
        raise _error(status.HTTP_409_CONFLICT, "session_already_revoked", "that session was already revoked")
    service.revoke_session(
        auth.session, row, reason=service.Reason.revoked_by_user, context=auth.context
    )
    auth.session.commit()
    return MessageOut(status="revoked", detail="session revoked")


@router.post("/sessions/revoke-all", response_model=RevokeAllOut)
def revoke_all_sessions(
    payload: RevokeAllRequest,
    response: Response,
    auth: Annotated[AuthContext, Depends(require_authenticated)],
) -> RevokeAllOut:
    kept = None if payload.include_current else auth.row.id
    count = service.revoke_all_sessions(
        auth.session,
        user=auth.user,
        reason=service.Reason.revoked_all,
        except_session_id=kept,
        context=auth.context,
    )
    auth.session.commit()
    if payload.include_current:
        clear_session_cookie(response, auth.settings)
    return RevokeAllOut(sessions_revoked=count, kept_current=not payload.include_current)


@router.post("/logout", response_model=MessageOut)
def logout(
    response: Response,
    auth: Annotated[AuthContext, Depends(current_auth)],
) -> MessageOut:
    service.mark_logout(auth.session, row=auth.row, user=auth.user, context=auth.context)
    auth.session.commit()
    clear_session_cookie(response, auth.settings)
    return MessageOut(status="signed_out")


@router.get("/me", response_model=AuthStateOut)
def me(auth: Annotated[AuthContext, Depends(current_auth)]) -> AuthStateOut:
    complete = service.session_meets_factor_policy(auth.row, auth.user, settings=auth.settings)
    return _state(
        "authenticated" if complete else "second_factor_required",
        auth.user,
        auth.row,
        settings=auth.settings,
        session=auth.session,
    )


# ---------------------------------------------------------------------------
# Step-up re-authentication
# ---------------------------------------------------------------------------
@router.post("/step-up", response_model=AuthStateOut)
def step_up(
    payload: StepUpRequest,
    response: Response,
    auth: Annotated[AuthContext, Depends(current_auth)],
) -> AuthStateOut:
    """Re-prove identity (password + second factor) and mark the session (§7.2, 5 minutes).

    The session is rotated as part of the step-up, so the token that existed before the
    privilege change cannot be reused (fixation defence).
    """
    try:
        issued = service.step_up(
            auth.session,
            row=auth.row,
            user=auth.user,
            password=payload.password,
            code=payload.code,
            context=auth.context,
            settings=auth.settings,
        )
    except service.FreshCheckFailed as exc:
        raise _error(
            status.HTTP_401_UNAUTHORIZED,
            exc.reason.value,
            "re-authentication failed; check your password and second factor",
        ) from None
    set_session_cookie(response, issued.raw_token, auth.settings)
    return _state("authenticated", auth.user, issued.row, settings=auth.settings, session=auth.session)


# ---------------------------------------------------------------------------
# TOTP enrolment and management
# ---------------------------------------------------------------------------
@router.post("/totp/enrol")
def begin_totp_enrolment(auth: Annotated[AuthContext, Depends(current_auth)]) -> dict[str, object]:
    """Create a pending secret and return the ``otpauth`` payload (secret shown once here).

    Allowed from a pending-2FA session: that is exactly how a physician/admin without a
    factor enrols one during first login.
    """
    payload = service.begin_enrolment(auth.session, auth.user, settings=auth.settings)
    auth.session.commit()
    return {"status": "enrolment_started", "otpauth": payload}


@router.post("/totp/activate", response_model=RecoveryCodesOut)
def activate_totp_enrolment(
    payload: CodeRequest,
    response: Response,
    auth: Annotated[AuthContext, Depends(current_auth)],
) -> RecoveryCodesOut:
    """Prove possession of the pending secret; issue recovery codes and rotate the session."""
    try:
        codes = service.activate_enrolment(
            auth.session, auth.user, code=payload.code, context=auth.context, settings=auth.settings
        )
    except service.FactorNotEnrolled as exc:
        raise _error(
            status.HTTP_400_BAD_REQUEST,
            exc.reason.value,
            "start enrolment before activating a second factor",
        ) from None
    except service.FactorFailed as exc:
        raise _error(
            status.HTTP_401_UNAUTHORIZED,
            exc.reason.value,
            "that code is not valid for the pending secret",
        ) from None

    # Rotation on privilege change (§7.1): the enrolment changes what this account can do, so
    # every other session is revoked and this one is rotated into a verified session.
    service.revoke_all_sessions(
        auth.session,
        user=auth.user,
        reason=service.Reason.revoked_all,
        except_session_id=auth.row.id,
        context=auth.context,
    )
    issued = service.rotate_session(
        auth.session,
        auth.row,
        context=auth.context,
        two_factor_verified=True,
        settings=auth.settings,
    )
    auth.session.commit()
    set_session_cookie(response, issued.raw_token, auth.settings)
    return RecoveryCodesOut(recovery_codes=codes)


@router.post("/totp/disable", response_model=MessageOut)
def disable_totp(
    payload: DisableTotpRequest,
    response: Response,
    auth: Annotated[AuthContext, Depends(require_authenticated)],
) -> MessageOut:
    """Remove the second factor after a fresh password + factor check (§7.1).

    Every session of the account is invalidated and the caller gets a fresh one, because the
    account's authentication strength just changed. For a role that must have a factor
    (physician/admin) the new session is a *pending* one: the account cannot operate without
    a second factor, so the next step is enrolling a new one.
    """
    try:
        service.disable_second_factor(
            auth.session,
            auth.user,
            password=payload.password,
            code=payload.code,
            context=auth.context,
            settings=auth.settings,
        )
    except service.FreshCheckFailed as exc:
        raise _error(
            status.HTTP_401_UNAUTHORIZED,
            exc.reason.value,
            "re-authentication failed; check your password and second factor",
        ) from None

    service.revoke_all_sessions(
        auth.session,
        user=auth.user,
        reason=service.Reason.revoked_all,
        except_session_id=auth.row.id,
        context=auth.context,
    )
    still_requires = auth.user.role in auth.settings.totp_required_role_set
    issued = service.rotate_session(
        auth.session,
        auth.row,
        context=auth.context,
        two_factor_verified=not still_requires,
        settings=auth.settings,
    )
    auth.session.commit()
    set_session_cookie(response, issued.raw_token, auth.settings)
    return MessageOut(
        status="totp_disabled",
        detail="second factor removed; enrol a new one to continue" if still_requires else None,
    )


@router.post("/totp/recovery-codes", response_model=RecoveryCodesOut)
def rotate_recovery_codes(
    payload: DisableTotpRequest,
    auth: Annotated[AuthContext, Depends(require_authenticated)],
) -> RecoveryCodesOut:
    """Issue a fresh set of recovery codes (fresh password + factor check required)."""
    try:
        codes = service.rotate_recovery_codes(
            auth.session,
            auth.user,
            password=payload.password,
            code=payload.code,
            context=auth.context,
            settings=auth.settings,
        )
    except service.FreshCheckFailed as exc:
        raise _error(
            status.HTTP_401_UNAUTHORIZED,
            exc.reason.value,
            "re-authentication failed; check your password and second factor",
        ) from None
    auth.session.commit()
    return RecoveryCodesOut(recovery_codes=codes)


__all__ = ["clear_session_cookie", "router", "set_session_cookie"]
