"""Test-only endpoints that exercise the authorisation dependencies end to end.

These routes exist only in the test process. They are built with the *same* machinery the
real routers use — :class:`~cardioauth.authz.policy.PolicyRoute` plus
:func:`~cardioauth.authz.policy.declare_policy` — so what a test observes here is what an
endpoint in the application would do, not a simulation of it.

Two families:

* one ``GET /api/test/authz/{permission}`` per §7.3 permission, so the whole role × permission
  matrix can be walked over HTTP rather than only against the pure function;
* a handful of object routes that go through ``authorize_object``, so practice scoping and
  referenced-object authorisation are exercised against real rows in the real database.

Nothing here returns clinical data: the object probes return the object's id and type only.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request

from cardioauth.auth.deps import AuthContext, require_authenticated
from cardioauth.authz.deps import authorize_object
from cardioauth.authz.permissions import Permission
from cardioauth.authz.policy import PolicyRoute, RoutePolicy, declare_policy

PROBE_PREFIX = "/api/test/authz"

#: (permission, object type, path under the prefix, HTTP method)
OBJECT_ROUTES: tuple[tuple[Permission, str, str, str], ...] = (
    (Permission.CASE_READ, "case", "/objects/case/{object_id}", "GET"),
    (Permission.CASE_WRITE, "case", "/objects/case/{object_id}/write", "POST"),
    (Permission.CRITERIA_READ, "criteria_set_version", "/objects/criteria_set_version/{object_id}", "GET"),
    (
        Permission.CRITERIA_WRITE,
        "criteria_set_version",
        "/objects/criteria_set_version/{object_id}/write",
        "POST",
    ),
    (Permission.USER_MANAGE, "app_user", "/objects/app_user/{object_id}", "GET"),
)


def facts_from_query(request: Request) -> dict[str, Any]:
    """Turn the probe's query string into the ``facts`` a constrained grant needs."""
    facts: dict[str, Any] = {}
    letter_kind = request.query_params.get("letter_kind")
    if letter_kind:
        facts["letter_kind"] = letter_kind
    for flag in ("signer_npi_present", "covering_physician_attestation", "reason_present"):
        if request.query_params.get(flag) == "true":
            facts[flag] = True
    return facts


def _permission_probe(permission: Permission) -> Callable[..., dict[str, str]]:
    @declare_policy(RoutePolicy.for_permission(permission, facts=facts_from_query))
    def endpoint(auth: Annotated[AuthContext, Depends(require_authenticated)]) -> dict[str, str]:
        # If the body runs at all, the gate passed. Return no practice data.
        return {"permission": str(permission), "role": auth.role}

    endpoint.__name__ = f"probe_{str(permission).replace('.', '_')}"
    endpoint.__qualname__ = endpoint.__name__
    return endpoint


def _object_probe(permission: Permission, object_type: str) -> Callable[..., dict[str, str]]:
    dependency = authorize_object(permission=permission, object_type=object_type)

    def endpoint(loaded: Any = Depends(dependency)) -> dict[str, str]:  # noqa: B008
        return {"object_type": loaded.object_type, "object_id": str(loaded.object_id)}

    endpoint.__name__ = f"probe_object_{object_type}_{str(permission).replace('.', '_')}"
    endpoint.__qualname__ = endpoint.__name__
    declare_policy(RoutePolicy.for_permission(permission, object_type=object_type))(endpoint)
    return endpoint


def build_probe_router() -> APIRouter:
    router = APIRouter(prefix=PROBE_PREFIX, tags=["test-only"], route_class=PolicyRoute)

    for permission in Permission:
        router.add_api_route(
            f"/{permission.value}",
            _permission_probe(permission),
            methods=["GET"],
            name=f"probe_{str(permission).replace('.', '_')}",
        )

    for permission, object_type, path, method in OBJECT_ROUTES:
        router.add_api_route(
            path,
            _object_probe(permission, object_type),
            methods=[method],
            name=f"probe_object_{object_type}_{str(permission).replace('.', '_')}",
        )

    # A route that declares no policy at all: the deny-by-default backstop must refuse it.
    def undeclared(auth: Annotated[AuthContext, Depends(require_authenticated)]) -> dict[str, str]:
        return {"this": "should never run"}

    undeclared.__name__ = "probe_undeclared"
    undeclared.__qualname__ = "probe_undeclared"
    router.add_api_route("/undeclared", undeclared, methods=["GET"], name="probe_undeclared")
    return router


def build_probe_app() -> Any:
    """The real application plus the probe routes (a fresh app per test)."""
    from cardioauth.api.main import create_app

    app = create_app()
    app.include_router(build_probe_router())
    return app


__all__ = ["OBJECT_ROUTES", "PROBE_PREFIX", "build_probe_app", "build_probe_router", "facts_from_query"]
