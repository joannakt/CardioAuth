"""Route policies — every endpoint must declare what it needs, or it is refused.

FastAPI's default is that an endpoint with no dependency is reachable by anyone. That is the
opposite of what §7.3 wants, and "we remembered to add the check" is not a control. So:

* :data:`ROUTE_POLICIES` is the one table that says, per endpoint, whether it is public,
  self-service (authenticated but not a practice action), or gated by a
  :class:`~cardioauth.authz.permissions.Permission`;
* :class:`PolicyRoute` reads that table when a route is built and attaches the matching
  dependency — the endpoint body never has to remember;
* a route whose endpoint is **not** in the table gets :func:`cardioauth.authz.deps.
  deny_undeclared_route`, so it fails closed at request time;
* :func:`find_undeclared_routes` lets ``create_app`` refuse to start at all when one exists,
  and is what the test suite asserts against.

Adding an endpoint therefore has two outcomes only: declared, or dead.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

from fastapi import Depends
from fastapi.routing import APIRoute

from cardioauth.auth.deps import current_auth, require_authenticated
from cardioauth.authz.deps import Facts, deny_undeclared_route, require_permission
from cardioauth.authz.permissions import Permission


class PolicyKind(StrEnum):
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    PERMISSION = "permission"


@dataclass(frozen=True, slots=True)
class RoutePolicy:
    """What one endpoint requires before its body runs."""

    kind: PolicyKind
    #: ``AUTHENTICATED``/``PERMISSION`` only: the object type a denial is recorded against.
    object_type: str = "route"
    permission: Permission | None = None
    #: ``AUTHENTICATED`` only: also require the second-factor policy (``require_authenticated``
    #: rather than ``current_auth``). The endpoints that *complete* authentication must not
    #: require it, or a pending session could never finish signing in.
    require_factor: bool = True
    #: Why this route needs no permission. Mandatory for the non-permission kinds, so
    #: "public" and "self-service" are always an argument someone wrote down.
    justification: str = ""
    #: ``PERMISSION`` only: the values a constrained grant needs (the letter kind, or
    #: ``reason_present`` for an action that must record why). A fact the caller does not
    #: supply is a denial, never an implicit allow.
    facts: Facts = None

    def __post_init__(self) -> None:
        if self.kind is PolicyKind.PERMISSION and self.permission is None:
            raise ValueError("a permission policy needs a Permission")
        if self.kind is not PolicyKind.PERMISSION and not self.justification:
            raise ValueError(f"a {self.kind} route policy must state its justification")

    @classmethod
    def public(cls, *, justification: str) -> RoutePolicy:
        return cls(kind=PolicyKind.PUBLIC, justification=justification)

    @classmethod
    def self_service(
        cls, *, object_type: str, require_factor: bool = True, justification: str
    ) -> RoutePolicy:
        """Authenticated, but about the caller's own identity — not a practice object."""
        return cls(
            kind=PolicyKind.AUTHENTICATED,
            object_type=object_type,
            require_factor=require_factor,
            justification=justification,
        )

    @classmethod
    def for_permission(
        cls,
        permission: Permission,
        *,
        object_type: str | None = None,
        facts: Facts = None,
    ) -> RoutePolicy:
        from cardioauth.authz.permissions import spec_for

        return cls(
            kind=PolicyKind.PERMISSION,
            permission=permission,
            object_type=object_type or spec_for(permission).object_type,
            facts=facts,
        )

    def dependencies(self) -> list[Any]:
        """The dependencies this policy attaches to the route."""
        if self.kind is PolicyKind.PUBLIC:
            return []
        if self.kind is PolicyKind.AUTHENTICATED:
            gate = require_authenticated if self.require_factor else current_auth
            return [Depends(gate)]
        assert self.permission is not None
        return [
            Depends(
                require_permission(
                    self.permission, object_type=self.object_type, facts=self.facts
                )
            )
        ]


def route_key(endpoint: Callable[..., Any]) -> str:
    """``module:qualname`` — stable across imports, readable in the table below."""
    return f"{endpoint.__module__}:{endpoint.__qualname__}"


#: Endpoint -> policy. One line per endpoint; a missing line is a refused endpoint.
ROUTE_POLICIES: Final[Mapping[str, RoutePolicy]] = MappingProxyType(
    {
        # -- health: liveness only, no data ------------------------------------------------
        "cardioauth.api.health:health": RoutePolicy.public(
            justification="liveness/readiness probe; returns no practice or patient data"
        ),
        # -- auth: identity self-service (§7.1). §7.3 governs practice objects, and these
        #    endpoints act only on the caller's own credentials and sessions. Managing
        #    *other* users is user.manage, below.
        "cardioauth.auth.router:login": RoutePolicy.public(
            justification="sign-in itself; the caller has no session yet"
        ),
        "cardioauth.auth.router:verify_second_factor": RoutePolicy.self_service(
            object_type="user_session",
            require_factor=False,
            justification="completes a pending session's second factor; must accept a pending session",
        ),
        "cardioauth.auth.router:me": RoutePolicy.self_service(
            object_type="app_user",
            require_factor=False,
            justification="the caller's own session state; a pending session must be able to read it",
        ),
        "cardioauth.auth.router:logout": RoutePolicy.self_service(
            object_type="user_session",
            require_factor=False,
            justification="ends the caller's own session; must work for a pending session",
        ),
        "cardioauth.auth.router:step_up": RoutePolicy.self_service(
            object_type="user_session",
            require_factor=False,
            justification="performs the step-up every sensitive permission depends on",
        ),
        "cardioauth.auth.router:begin_totp_enrolment": RoutePolicy.self_service(
            object_type="app_user",
            require_factor=False,
            justification="the caller enrols its own second factor (required by policy)",
        ),
        "cardioauth.auth.router:activate_totp_enrolment": RoutePolicy.self_service(
            object_type="app_user",
            require_factor=False,
            justification="the caller activates its own second factor",
        ),
        "cardioauth.auth.router:list_sessions": RoutePolicy.self_service(
            object_type="user_session",
            justification="lists the caller's own sessions only",
        ),
        "cardioauth.auth.router:revoke_session": RoutePolicy.self_service(
            object_type="user_session",
            justification="revokes one of the caller's own sessions (foreign ids are 404)",
        ),
        "cardioauth.auth.router:revoke_all_sessions": RoutePolicy.self_service(
            object_type="user_session",
            justification="revokes the caller's own sessions only",
        ),
        "cardioauth.auth.router:disable_totp": RoutePolicy.self_service(
            object_type="app_user",
            justification="removes the caller's own second factor after a fresh password check",
        ),
        "cardioauth.auth.router:rotate_recovery_codes": RoutePolicy.self_service(
            object_type="app_user",
            justification="regenerates the caller's own recovery codes",
        ),
    }
)


def policy_for(endpoint: Callable[..., Any]) -> RoutePolicy | None:
    """The policy for an endpoint: an explicit attribute, else the registry, else ``None``."""
    attached = getattr(endpoint, "__cardioauth_policy__", None)
    if isinstance(attached, RoutePolicy):
        return attached
    return ROUTE_POLICIES.get(route_key(endpoint))


def declare_policy(policy: RoutePolicy) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Attach a policy to an endpoint function directly.

    Used by endpoints that are generated (the test-only permission probes) rather than written
    one per line; production endpoints belong in :data:`ROUTE_POLICIES` so they can be reviewed
    in one place.
    """

    def decorate(endpoint: Callable[..., Any]) -> Callable[..., Any]:
        endpoint.__cardioauth_policy__ = policy  # type: ignore[attr-defined]
        return endpoint

    return decorate


#: Set on an endpoint function once its policy dependencies have been attached, so that
#: ``include_router`` (which re-adds every route and copies its dependencies) cannot attach a
#: second copy of the same gate — two copies would mean two audit rows for one denial.
_INJECTED = "__cardioauth_policy_injected__"


class PolicyRoute(APIRoute):
    """An ``APIRoute`` that refuses to exist without a declared policy."""

    def __init__(self, path: str, endpoint: Callable[..., Any], **kwargs: Any) -> None:
        policy = policy_for(endpoint)
        dependencies: Sequence[Any] = list(kwargs.pop("dependencies", None) or [])
        if not getattr(endpoint, _INJECTED, False):
            if policy is None:
                dependencies = [*dependencies, Depends(deny_undeclared_route)]
            else:
                dependencies = [*dependencies, *policy.dependencies()]
            try:
                setattr(endpoint, _INJECTED, True)
            except (AttributeError, TypeError):  # pragma: no cover - exotic callables
                pass
        self.policy: RoutePolicy | None = policy
        super().__init__(path, endpoint, dependencies=list(dependencies), **kwargs)


def iter_api_routes(container: Any, _seen: set[int] | None = None) -> list[APIRoute]:
    """Every :class:`APIRoute` reachable from ``container``.

    ``FastAPI.include_router`` does not flatten routes into ``app.routes`` in every version:
    current releases keep an ``_IncludedRouter`` handle instead, so a guard that only looks at
    the top level would inspect nothing and pass. This walks into included routers (and
    mounted apps) so the deny-by-default check sees the routes that actually serve requests.
    """
    seen = _seen if _seen is not None else set()
    found: list[APIRoute] = []
    for route in getattr(container, "routes", []) or []:
        if isinstance(route, APIRoute):
            found.append(route)
            continue
        for attribute in ("router", "app"):
            inner = getattr(route, attribute, None)
            if inner is None or id(inner) in seen:
                continue
            seen.add(id(inner))
            found.extend(iter_api_routes(inner, seen))
    return found


def find_undeclared_routes(*containers: Any) -> list[str]:
    """Every API route reachable from ``containers`` that declares no policy.

    Pass the app *and* the routers it includes: some FastAPI releases keep included routers
    behind an opaque handle on ``app.routes``, so the routers are the reliable place to look.
    Empty means every route is declared.
    """
    offenders: list[str] = []
    routes = [route for container in containers for route in iter_api_routes(container)]
    for route in routes:
        policy = getattr(route, "policy", None)
        if policy is None:
            policy = policy_for(route.endpoint)
        if policy is None:
            offenders.append(f"{route.path} [{','.join(sorted(route.methods or []))}]")
    return offenders


def assert_routes_declared(*containers: Any) -> None:
    """Fail application startup if any endpoint declares no policy (deny by default)."""
    offenders = find_undeclared_routes(*containers)
    if offenders:
        raise RuntimeError(
            "these endpoints declare no authorisation policy and would be unreachable; add "
            "them to cardioauth.authz.policy.ROUTE_POLICIES: " + ", ".join(sorted(offenders))
        )


__all__ = [
    "ROUTE_POLICIES",
    "PolicyKind",
    "PolicyRoute",
    "RoutePolicy",
    "assert_routes_declared",
    "declare_policy",
    "find_undeclared_routes",
    "iter_api_routes",
    "policy_for",
    "route_key",
]
