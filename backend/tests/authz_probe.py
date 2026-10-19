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

from fastapi import APIRouter, Body, Depends, Request

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


# ---------------------------------------------------------------------------
# PHI sentinel probes (tests/test_no_phi_in_denials.py)
# ---------------------------------------------------------------------------
#: The header the sentinel test puts a sentinel in. The ``{note}`` path segment is free text on
#: purpose: the question these routes answer is whether a request carrying free text in a path
#: segment — a URL someone pasted, a search term, a patient name — can write that text into a
#: log line or the audit chain while the request is being *handled* (200), or while it is being
#: *refused* (403 role denial, 403 undeclared route, 404 cross-practice).
PHI_SENTINEL_HEADER = "x-sentinel-probe"
PHI_PROBE_PATH = "/phi/{note}"


def _received(request: Request, note: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    """What the endpoint actually saw. The positive control for the sentinel test: it proves the
    sentinel travelled through the whole stack instead of the test asserting nothing happened."""
    return {
        "path_note": note,
        "query_note": request.query_params.get("note"),
        "body_note": (payload or {}).get("note"),
        "header_note": request.headers.get(PHI_SENTINEL_HEADER),
    }


def _phi_permitted_probe() -> Callable[..., dict[str, Any]]:
    @declare_policy(RoutePolicy.for_permission(Permission.CASE_READ))
    def endpoint(
        request: Request,
        note: str,
        payload: Annotated[dict[str, Any] | None, Body()] = None,
    ) -> dict[str, Any]:
        return _received(request, note, payload)

    endpoint.__name__ = "probe_phi_permitted"
    endpoint.__qualname__ = endpoint.__name__
    return endpoint


def _phi_role_denied_probe() -> Callable[..., dict[str, Any]]:
    """A permission the coordinator role does not hold: reaches the role gate and is refused."""

    @declare_policy(RoutePolicy.for_permission(Permission.USER_MANAGE))
    def endpoint(
        request: Request,
        note: str,
        payload: Annotated[dict[str, Any] | None, Body()] = None,
    ) -> dict[str, Any]:
        return {"this": "should never run"}

    endpoint.__name__ = "probe_phi_role_denied"
    endpoint.__qualname__ = endpoint.__name__
    return endpoint


def _phi_object_probe() -> Callable[..., dict[str, Any]]:
    """``authorize_object`` with a real object id: practice A asking for practice B's case."""
    dependency = authorize_object(permission=Permission.CASE_READ, object_type="case")

    def endpoint(
        request: Request,
        note: str,
        payload: Annotated[dict[str, Any] | None, Body()] = None,
        loaded: Any = Depends(dependency),  # noqa: B008
    ) -> dict[str, Any]:
        return {"this": "should never run"}

    endpoint.__name__ = "probe_phi_object_cross_practice"
    endpoint.__qualname__ = endpoint.__name__
    declare_policy(RoutePolicy.for_permission(Permission.CASE_READ, object_type="case"))(endpoint)
    return endpoint


def _phi_undeclared_probe() -> Callable[..., dict[str, Any]]:
    """No policy at all: the deny-by-default backstop refuses it (``permission_not_declared``).

    The path is ``/no-policy`` rather than ``/undeclared`` so that it does not collide with the
    route-name assertions the existing policy tests make about ``.../undeclared``.
    """

    def endpoint(
        request: Request,
        note: str,
        payload: Annotated[dict[str, Any] | None, Body()] = None,
    ) -> dict[str, Any]:
        return {"this": "should never run"}

    endpoint.__name__ = "probe_phi_no_policy"
    endpoint.__qualname__ = endpoint.__name__
    return endpoint


#: (method, path, endpoint *factory*, route name) — see tests/test_no_phi_in_denials.py.
#:
#: The factories are called per router build, never once at import: ``PolicyRoute`` marks an
#: endpoint whose policy dependencies it has attached (``_INJECTED``) so that including the same
#: route twice cannot attach two copies of the gate, which means a module-level endpoint object
#: would silently lose its gate in the second and every later app built in the same process.
PHI_PROBE_ROUTES: tuple[tuple[str, str, Callable[[], Callable[..., Any]], str], ...] = (
    ("POST", f"{PHI_PROBE_PATH}/permitted", _phi_permitted_probe, "probe_phi_permitted"),
    ("POST", f"{PHI_PROBE_PATH}/denied", _phi_role_denied_probe, "probe_phi_role_denied"),
    ("POST", f"{PHI_PROBE_PATH}/no-policy", _phi_undeclared_probe, "probe_phi_no_policy"),
    (
        "POST",
        f"{PHI_PROBE_PATH}/objects/case/{{object_id}}",
        _phi_object_probe,
        "probe_phi_object_cross_practice",
    ),
)


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

    for method, path, make_endpoint, name in PHI_PROBE_ROUTES:
        router.add_api_route(path, make_endpoint(), methods=[method], name=name)
    return router


def build_probe_app() -> Any:
    """The real application plus the probe routes (a fresh app per test)."""
    from cardioauth.api.main import create_app

    app = create_app()
    app.include_router(build_probe_router())
    return app


__all__ = [
    "OBJECT_ROUTES",
    "PHI_PROBE_PATH",
    "PHI_PROBE_ROUTES",
    "PHI_SENTINEL_HEADER",
    "PROBE_PREFIX",
    "build_probe_app",
    "build_probe_router",
    "facts_from_query",
]
