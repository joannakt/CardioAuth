"""FastAPI dependencies that enforce the §7.3 matrix — deny by default.

* :func:`require_permission` — the role/step-up/precondition gate for an endpoint.
* :func:`authorize_object` — the same gate *plus* the practice test against a loaded row, so
  a user of practice A cannot read or mutate an object of practice B whatever they put in a
  path or body parameter.
* :func:`deny_undeclared_route` — the guard a route gets when it declares no policy at all
  (:mod:`cardioauth.authz.policy`), so an endpoint cannot be silently reachable.

Every refusal goes through :func:`audit_denial`: one ``authz.denied`` row carrying the actor,
the required permission, the object type and a reason code. The ``detail`` payload holds
identifiers, codes and booleans only — never document text, fact values, a reason a clinician
typed, or anything else a patient appears in (§7.4, INV-5).

A denial is committed before the exception is raised: ``get_db`` rolls the request's
transaction back on the way out, and a refusal that vanished with it would be exactly the
record §7.3 wants ("every denial is audited with outcome='denied', which makes privilege
probing visible").
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any, NoReturn

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from cardioauth.audit.service import record_denied
from cardioauth.auth import service
from cardioauth.auth.deps import (
    AuthContext,
    current_auth_optional,
    get_db,
    require_authenticated,
)
from cardioauth.authz import objects as object_registry
from cardioauth.authz.permissions import (
    Decision,
    DenialReason,
    Permission,
    evaluate,
    spec_for,
)
from cardioauth.security.identifiers import UNMATCHED_ROUTE

logger = logging.getLogger(__name__)

PERMISSION_DENIED = "permission_denied"
REAUTH_REQUIRED = "reauth_required"
NOT_FOUND = "not_found"
PERMISSION_NOT_DECLARED = "permission_not_declared"

Facts = Mapping[str, object] | Callable[[Request], Mapping[str, object]] | None


def _error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})


def reauth_is_fresh(auth: AuthContext) -> bool:
    """Whether this session re-authenticated inside the §7.2 window.

    Reuses the M1b-1 mechanism verbatim (``user_session.reauth_at`` against
    ``settings.session_reauth_minutes``); there is no second step-up path.
    """
    return service.is_recent_reauth(auth.row, settings=auth.settings)


def audit_denial(
    auth: AuthContext,
    *,
    reason: DenialReason,
    permission: Permission | None,
    object_type: str,
    object_id: uuid.UUID | None = None,
    case_id: uuid.UUID | None = None,
    step_up_required: bool = False,
) -> None:
    """Append the ``authz.denied`` row and commit it, so the refusal survives the rollback.

    ``detail`` is deliberately narrow: a reason code, the permission name, the role and a
    boolean. The permission name is a code from a closed enum, not free text, and no value
    the caller supplied (a path id, a body field, a reason a user typed) is ever copied in.
    """
    record_denied(
        auth.session,
        action="authz.denied",
        object_type=object_type,
        object_id=object_id,
        case_id=case_id,
        practice_id=auth.practice_id,
        actor_user_id=auth.user.id,
        actor_role=auth.role,
        session_id=auth.row.id,
        request_id=auth.context.request_id,
        detail={
            "reason": str(reason),
            "permission": str(permission) if permission is not None else "none",
            "role": auth.role,
            "step_up_required": step_up_required,
        },
    )
    auth.session.commit()


def _resolve_facts(facts: Facts, request: Request) -> Mapping[str, object]:
    if facts is None:
        return {}
    if callable(facts):
        return facts(request) or {}
    return facts


def _deny(auth: AuthContext, decision: Decision, *, object_type: str) -> NoReturn:
    audit_denial(
        auth,
        reason=decision.reason,
        permission=decision.permission,
        object_type=object_type,
        step_up_required=decision.step_up_required,
    )
    if decision.reason is DenialReason.STEP_UP_REQUIRED:
        raise _error(
            status.HTTP_403_FORBIDDEN,
            REAUTH_REQUIRED,
            "re-authenticate to continue (password and second factor)",
        )
    raise _error(
        status.HTTP_403_FORBIDDEN,
        PERMISSION_DENIED,
        "your role may not perform this action",
    )


# ---------------------------------------------------------------------------
# Endpoint-level gate
# ---------------------------------------------------------------------------
def require_permission(
    permission: Permission,
    *,
    object_type: str | None = None,
    facts: Facts = None,
) -> Callable[..., AuthContext]:
    """Dependency factory: this endpoint requires ``permission``.

    ``facts`` supplies the values a constrained grant needs (``letter_kind``, or
    ``reason_present`` for an action that must record why). A fact that is not supplied is a
    denial, never an implicit allow.
    """
    spec = spec_for(permission)
    resolved_object_type = object_type or spec.object_type

    def dependency(
        request: Request,
        auth: Annotated[AuthContext, Depends(require_authenticated)],
    ) -> AuthContext:
        decision = evaluate(
            auth.role,
            permission,
            facts=_resolve_facts(facts, request),
            reauth_fresh=reauth_is_fresh(auth),
        )
        if not decision.allowed:
            _deny(auth, decision, object_type=resolved_object_type)
        return auth

    dependency.__name__ = f"require_permission_{str(permission).replace('.', '_')}"
    return dependency


# ---------------------------------------------------------------------------
# Object-level gate
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class AuthorizedObject:
    """A row that has passed both the role gate and the practice test."""

    object_type: str
    object_id: uuid.UUID
    row: Any


def _parse_object_id(raw: object) -> uuid.UUID | None:
    if isinstance(raw, uuid.UUID):
        return raw
    if not isinstance(raw, str):
        return None
    try:
        return uuid.UUID(raw)
    except ValueError:
        return None


def authorize_object(
    *,
    permission: Permission,
    object_type: str | None = None,
    id_param: str = "object_id",
    facts: Facts = None,
    case_id_param: str | None = None,
) -> Callable[..., AuthorizedObject]:
    """Dependency factory: load the object named by ``id_param`` and authorise *that* row.

    Order of checks, each with its own audit reason:

    1. the role/step-up/precondition gate (403 — a statement about the actor's role, identical
       for every object, so it discloses nothing);
    2. the object exists (404 ``not_found``);
    3. the object belongs to the actor's practice (404 ``not_found``, **not** 403: a 403 would
       confirm that the id is real somewhere, so a cross-practice attempt is indistinguishable
       from an id that does not exist);
    4. the grant's scope reaches it (404 ``not_found`` for ``own_actions`` misses).

    A body parameter can never widen any of this: the id comes from the path/query and the
    practice comes from the row, not from the request.
    """
    spec = spec_for(permission)
    resolved_object_type = object_type or spec.object_type
    object_spec = object_registry.spec_for_object_type(resolved_object_type)

    def dependency(
        request: Request,
        auth: Annotated[AuthContext, Depends(require_authenticated)],
    ) -> AuthorizedObject:
        decision = evaluate(
            auth.role,
            permission,
            facts=_resolve_facts(facts, request),
            reauth_fresh=reauth_is_fresh(auth),
        )
        if not decision.allowed:
            _deny(auth, decision, object_type=resolved_object_type)

        case_id = _parse_object_id(request.path_params.get(case_id_param)) if case_id_param else None
        object_id = _parse_object_id(
            request.path_params.get(id_param, request.query_params.get(id_param))
        )
        if object_id is None:
            audit_denial(
                auth,
                reason=DenialReason.OBJECT_NOT_FOUND,
                permission=permission,
                object_type=resolved_object_type,
                case_id=case_id,
            )
            raise _error(status.HTTP_404_NOT_FOUND, NOT_FOUND, "no such object")

        row = object_registry.load_object(auth.session, resolved_object_type, object_id)
        if row is None:
            audit_denial(
                auth,
                reason=DenialReason.OBJECT_NOT_FOUND,
                permission=permission,
                object_type=resolved_object_type,
                object_id=object_id,
                case_id=case_id,
            )
            raise _error(status.HTTP_404_NOT_FOUND, NOT_FOUND, "no such object")

        row_practice = object_registry.practice_of(auth.session, resolved_object_type, row)
        if row_practice is None:
            # A shared-library row (a global criteria set). Readable, never writable.
            if not object_registry.unscoped_object_allowed(
                practice_id=None, read_only=spec.read_only
            ):
                audit_denial(
                    auth,
                    reason=DenialReason.SHARED_OBJECT_NOT_WRITABLE,
                    permission=permission,
                    object_type=resolved_object_type,
                    object_id=object_id,
                    case_id=case_id,
                )
                raise _error(
                    status.HTTP_403_FORBIDDEN,
                    PERMISSION_DENIED,
                    "this shared object cannot be changed here",
                )
        elif row_practice != auth.practice_id:
            # Same response as "does not exist": the actor learns nothing about whether the
            # id is real in another practice.
            audit_denial(
                auth,
                reason=DenialReason.CROSS_PRACTICE_DENIED,
                permission=permission,
                object_type=resolved_object_type,
                object_id=object_id,
                case_id=case_id,
            )
            raise _error(status.HTTP_404_NOT_FOUND, NOT_FOUND, "no such object")

        if not object_registry.scope_allows(
            scope=decision.scope, actor_user_id=auth.user.id, spec=object_spec, row=row
        ):
            audit_denial(
                auth,
                reason=DenialReason.SCOPE_VIOLATION,
                permission=permission,
                object_type=resolved_object_type,
                object_id=object_id,
                case_id=case_id,
            )
            raise _error(status.HTTP_404_NOT_FOUND, NOT_FOUND, "no such object")

        return AuthorizedObject(
            object_type=resolved_object_type, object_id=object_id, row=row
        )

    dependency.__name__ = f"authorize_object_{str(permission).replace('.', '_')}"
    return dependency


# ---------------------------------------------------------------------------
# Route-level guard: a route that declares no policy is refused
# ---------------------------------------------------------------------------
def deny_undeclared_route(
    request: Request,
    auth: Annotated[AuthContext | None, Depends(current_auth_optional)],
    session: Annotated[Session, Depends(get_db)],
) -> NoReturn:
    """Refuse a request to a route that declared no policy.

    This is the deny-by-default backstop: it is attached by
    :class:`cardioauth.authz.policy.PolicyRoute` to any route whose endpoint is not in the
    policy registry, so forgetting to declare a permission fails closed at request time
    instead of quietly opening the endpoint to every authenticated user. ``create_app`` also
    fails at import time when it finds such a route.
    """
    route = request.scope.get("route")
    route_template = getattr(route, "path", None)
    if auth is not None:
        audit_denial(
            auth,
            reason=DenialReason.PERMISSION_NOT_DECLARED,
            permission=None,
            object_type="route",
        )
    else:  # pragma: no cover - unauthenticated caller: nothing to attribute the row to
        logger.warning(
            # The route template, never the requested URL: an unmatched path is caller-supplied
            # free text (cardioauth.security.identifiers, §7.5).
            "authz.undeclared_route_unauthenticated",
            extra={"route": route_template or UNMATCHED_ROUTE, "method": request.method},
        )
    raise _error(
        status.HTTP_403_FORBIDDEN,
        PERMISSION_NOT_DECLARED,
        "this endpoint declares no permission and is therefore refused",
    )


__all__ = [
    "AuthorizedObject",
    "Facts",
    "audit_denial",
    "authorize_object",
    "deny_undeclared_route",
    "reauth_is_fresh",
    "require_permission",
]
