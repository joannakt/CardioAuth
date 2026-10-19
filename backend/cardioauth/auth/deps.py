"""FastAPI dependencies: database session, request context, session authentication, step-up.

What protected routes will use:

.. code-block:: python

    @router.post("/cases/{case_id}/letters/{letter_id}/export")
    def export_letter(
        case_id: uuid.UUID,
        auth: AuthContext = Depends(require_recent_reauth()),   # export needs a step-up
    ) -> ...:
        ...

* :func:`current_auth` — any live session, including one that still owes a second factor.
  Used by the endpoints that *complete* authentication (2FA verify, enrolment, logout).
* :func:`require_authenticated` — a live session that satisfies the factor policy.
* :func:`require_recent_reauth` — :func:`require_authenticated` plus a re-authentication
  inside the step-up window (§7.2: 5 minutes).
* :func:`require_roles` — role gate for the RBAC matrix (§7.3). Denials are audited with
  ``outcome='denied'``.

Rejected sessions: an *expired* session is audited once (``auth.session_expired``) and then
revoked, so a cookie that keeps being replayed cannot keep writing audit rows. A *revoked*
or *unknown* cookie is refused with a WARNING log and no audit row — the revocation is
already in the chain, and letting an arbitrary cookie append rows would hand an attacker a
cheap way to grow the log.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from cardioauth import db
from cardioauth.auth import service
from cardioauth.audit.chain import AuditEntry
from cardioauth.audit.service import record as audit_record
from cardioauth.db.models import AppUser, UserSession
from cardioauth.settings import Settings, get_settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Infrastructure dependencies
# ---------------------------------------------------------------------------
def get_db() -> Iterator[Session]:
    """One transaction per request; committed on success, rolled back on an exception."""
    with db.session_scope() as session:
        yield session


def get_settings_dep() -> Settings:  # pragma: no cover - trivial, exercised indirectly
    return get_settings()


def request_context(request: Request) -> service.RequestContext:
    """Request identifiers only. The raw IP and user-agent are never logged or audited."""
    return service.RequestContext(
        request_id=request.headers.get("x-request-id"),
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


def _error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})


def _session_cookie_value(request: Request, settings: Settings) -> str | None:
    return request.cookies.get(settings.session_cookie_name)


# ---------------------------------------------------------------------------
# Session authentication
# ---------------------------------------------------------------------------
@dataclass
class AuthContext:
    session: Session
    row: UserSession
    user: AppUser
    context: service.RequestContext
    settings: Settings

    @property
    def user_id(self) -> uuid.UUID:
        return self.user.id

    @property
    def role(self) -> str:
        return self.user.role

    @property
    def practice_id(self) -> uuid.UUID | None:
        return self.user.practice_id

    def requires_step_up(self) -> bool:
        return not service.is_recent_reauth(self.row, settings=self.settings)


def current_auth(
    request: Request,
    session: Annotated[Session, Depends(get_db)],
    context: Annotated[service.RequestContext, Depends(request_context)],
) -> AuthContext:
    """Resolve the session cookie to a live session, or raise 401."""

    settings = get_settings()
    raw = _session_cookie_value(request, settings)
    if not raw:
        raise _error(status.HTTP_401_UNAUTHORIZED, "not_authenticated", "sign in to continue")

    lookup = service.load_session(session, raw_token=raw, settings=settings)
    if not lookup.ok:
        if lookup.reason in {service.Reason.expired_idle, service.Reason.expired_absolute} and lookup.row:
            service.expire_session(session, lookup.row, reason=lookup.reason, context=context)
            session.commit()
        else:
            # No audit row (see the module docstring): the reason code is all we log.
            logger.warning(
                "auth.session_rejected", extra={"reason": lookup.reason.value if lookup.reason else "unknown"}
            )
        raise _error(status.HTTP_401_UNAUTHORIZED, lookup.reason.value if lookup.reason else "not_authenticated",
                     "your session is no longer valid; sign in again")

    assert lookup.row is not None and lookup.user is not None
    # Sliding idle window, committed with the request's own transaction (§7.2).
    service.touch_session(session, lookup.row, settings=settings)
    return AuthContext(session=session, row=lookup.row, user=lookup.user, context=context, settings=settings)


def current_auth_optional(
    request: Request,
    session: Annotated[Session, Depends(get_db)],
    context: Annotated[service.RequestContext, Depends(request_context)],
) -> AuthContext | None:
    """Like :func:`current_auth`, but ``None`` instead of an exception.

    Used only where a refusal has to be *attributed* to an actor — the deny-by-default guard
    for a route that declared no permission (:mod:`cardioauth.authz.policy`). It never
    raises, never slides the idle window and never writes an audit row: a caller that is not
    authenticated cannot be named in the log, and an unknown cookie must not be able to append
    rows (§7.5). A pending-second-factor session resolves here (it is *someone*), but it is
    still refused downstream because every permission check starts from
    :func:`require_authenticated`.
    """
    settings = get_settings()
    raw = _session_cookie_value(request, settings)
    if not raw:
        return None
    lookup = service.load_session(session, raw_token=raw, settings=settings)
    if not lookup.ok or lookup.row is None or lookup.user is None:
        return None
    return AuthContext(session=session, row=lookup.row, user=lookup.user, context=context, settings=settings)


def require_authenticated(auth: Annotated[AuthContext, Depends(current_auth)]) -> AuthContext:
    """A session that satisfies the second-factor policy for this user's role."""
    if not service.session_meets_factor_policy(auth.row, auth.user, settings=auth.settings):
        raise _error(
            status.HTTP_403_FORBIDDEN,
            "second_factor_required",
            "finish two-factor authentication (or enrol a second factor) to continue",
        )
    return auth


def require_recent_reauth(
    *, minutes: int | None = None, action: str | None = None
) -> Callable[[AuthContext], AuthContext]:
    """Dependency factory: the caller must have re-authenticated recently (§7.2).

    ``action`` names the sensitive action for the denial audit entry; it defaults to
    ``auth.step_up_failed`` because the *attempt* is what is being refused.
    """

    def dependency(auth: Annotated[AuthContext, Depends(require_authenticated)]) -> AuthContext:
        window = minutes if minutes is not None else auth.settings.session_reauth_minutes
        if auth.row.reauth_at is None:
            ok = False
        else:
            from datetime import timedelta

            ok = service.utcnow() - auth.row.reauth_at <= timedelta(minutes=window)
        if not ok:
            audit_record(
                auth.session,
                AuditEntry(
                    action="auth.step_up_failed",
                    object_type="user_session",
                    object_id=auth.row.id,
                    practice_id=auth.practice_id,
                    actor_user_id=auth.user.id,
                    actor_role=auth.role,
                    outcome="denied",
                    session_id=auth.row.id,
                    request_id=auth.context.request_id,
                    detail={"reason": "reauth_required", "window_minutes": window, "action": action or "unspecified"},
                ),
            )
            auth.session.commit()
            raise _error(
                status.HTTP_403_FORBIDDEN,
                "reauth_required",
                "re-authenticate to continue (password and second factor)",
            )
        return auth

    return dependency


def require_roles(*roles: str) -> Callable[[AuthContext], AuthContext]:
    """Dependency factory: role gate for the RBAC matrix (§7.3), audited when it refuses."""

    allowed = frozenset(roles)

    def dependency(auth: Annotated[AuthContext, Depends(require_authenticated)]) -> AuthContext:
        if auth.role not in allowed:
            audit_record(
                auth.session,
                AuditEntry(
                    action="auth.step_up_failed",  # a refused privilege use (§7.3 outcome='denied')
                    object_type="app_user",
                    object_id=auth.user.id,
                    practice_id=auth.practice_id,
                    actor_user_id=auth.user.id,
                    actor_role=auth.role,
                    outcome="denied",
                    session_id=auth.row.id,
                    request_id=auth.context.request_id,
                    detail={"reason": "role_denied", "required_roles": sorted(allowed)},
                ),
            )
            auth.session.commit()
            raise _error(status.HTTP_403_FORBIDDEN, "role_denied", "your role may not perform this action")
        return auth

    return dependency


__all__ = [
    "AuthContext",
    "current_auth",
    "current_auth_optional",
    "get_db",
    "get_settings_dep",
    "request_context",
    "require_authenticated",
    "require_recent_reauth",
    "require_roles",
]
