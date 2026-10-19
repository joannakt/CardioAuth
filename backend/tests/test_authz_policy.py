"""Deny by default: an endpoint with no declared permission must be refused, not reachable.

§7.3 says RBAC is enforced "server-side at the router dependency level". The risk that
creates is the endpoint someone adds on a Friday without the check. These tests pin the three
mechanisms that make that impossible:

1. every route in the real application carries a policy (and every table entry has a route, so
   the table cannot rot into fiction);
2. a route built without a policy gets :func:`~cardioauth.authz.deps.deny_undeclared_route`
   and is refused with a 403 and an audit row;
3. ``create_app`` fails at import time when it finds such a route, so the failure is a deploy
   error rather than a quiet hole.

The self-service routes (login, 2FA, step-up, the caller's own sessions) are declared with a
written justification instead of a permission, and this file asserts that justification is
always present — "public" is never an accident.
"""

from __future__ import annotations

import pytest
from fastapi import APIRouter, Depends, FastAPI

from cardioauth.auth.deps import AuthContext, require_authenticated
from cardioauth.authz.policy import (
    ROUTE_POLICIES,
    PolicyKind,
    PolicyRoute,
    RoutePolicy,
    assert_routes_declared,
    find_undeclared_routes,
)
from tests.authz_probe import PROBE_PREFIX
from tests.authz_support import audit_rows, sign_in

pytestmark = pytest.mark.db


def _real_app():  # noqa: ANN202
    from cardioauth.api.main import create_app

    return create_app()


# ---------------------------------------------------------------------------
# The application itself declares everything
# ---------------------------------------------------------------------------
def _real_routers():  # noqa: ANN202
    from cardioauth.api.health import router as health_router
    from cardioauth.auth.router import router as auth_router

    return health_router, auth_router


def test_every_route_of_the_real_application_declares_a_policy() -> None:
    app = _real_app()
    health_router, auth_router = _real_routers()
    assert find_undeclared_routes(app, health_router, auth_router) == [], (
        "an endpoint would be reachable without a policy"
    )
    assert_routes_declared(app, health_router, auth_router)  # must not raise


def test_the_route_policy_table_has_no_dead_entries() -> None:
    """A table entry for an endpoint that no longer exists is a lie waiting to be trusted."""
    import importlib

    dead = []
    for key in ROUTE_POLICIES:
        module_name, _, qualname = key.partition(":")
        try:
            target = importlib.import_module(module_name)
            for part in qualname.split("."):
                target = getattr(target, part)
        except (ImportError, AttributeError):
            dead.append(key)
    assert dead == [], f"ROUTE_POLICIES names endpoints that do not exist: {dead}"


def test_every_api_route_of_the_real_application_resolves_to_a_policy() -> None:
    from cardioauth.authz.policy import iter_api_routes, policy_for

    health_router, auth_router = _real_routers()
    api_routes = iter_api_routes(health_router) + iter_api_routes(auth_router)
    assert len(api_routes) >= 13, f"only {len(api_routes)} API routes found"
    undeclared = [route.path for route in api_routes if policy_for(route.endpoint) is None]
    assert undeclared == [], f"routes with no policy: {undeclared}"


def test_every_non_permission_route_states_why_it_needs_no_permission() -> None:
    for key, policy in ROUTE_POLICIES.items():
        if policy.kind is PolicyKind.PERMISSION:
            assert policy.permission is not None, key
            continue
        assert policy.justification.strip(), f"{key} is public/self-service with no argument"
        assert policy.object_type, key


def test_the_only_public_routes_are_health_and_login() -> None:
    public = {key for key, policy in ROUTE_POLICIES.items() if policy.kind is PolicyKind.PUBLIC}
    assert public == {"cardioauth.api.health:health", "cardioauth.auth.router:login"}


def test_auth_endpoints_that_complete_authentication_do_not_require_a_factor() -> None:
    """A pending session must be able to finish signing in, or nobody could ever sign in."""
    for endpoint in (
        "cardioauth.auth.router:verify_second_factor",
        "cardioauth.auth.router:begin_totp_enrolment",
        "cardioauth.auth.router:activate_totp_enrolment",
        "cardioauth.auth.router:step_up",
        "cardioauth.auth.router:me",
        "cardioauth.auth.router:logout",
    ):
        policy = ROUTE_POLICIES[endpoint]
        assert policy.kind is PolicyKind.AUTHENTICATED, endpoint
        assert policy.require_factor is False, endpoint


def test_a_policy_without_a_justification_is_a_construction_error() -> None:
    with pytest.raises(ValueError, match="justification"):
        RoutePolicy(kind=PolicyKind.PUBLIC)
    with pytest.raises(ValueError, match="justification"):
        RoutePolicy(kind=PolicyKind.AUTHENTICATED, object_type="app_user")


def test_a_permission_policy_without_a_permission_is_a_construction_error() -> None:
    with pytest.raises(ValueError, match="needs a Permission"):
        RoutePolicy(kind=PolicyKind.PERMISSION)


# ---------------------------------------------------------------------------
# A route that declares nothing is refused
# ---------------------------------------------------------------------------
def test_an_undeclared_route_is_refused_for_an_authenticated_user(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    account = world.account("a", "admin")
    sign_in(probe_client, account, totp_clock)

    response = probe_client.get(f"{PROBE_PREFIX}/undeclared")
    assert response.status_code == 403, "an endpoint without a declared permission was reachable"
    assert response.json()["detail"]["code"] == "permission_not_declared"

    rows = audit_rows(world_engine(), actor_user_id=account.user_id)
    assert len(rows) == 1
    assert rows[0]["object_type"] == "route"
    assert rows[0]["detail"]["reason"] == "permission_not_declared"
    assert rows[0]["detail"]["permission"] == "none"


def test_an_undeclared_route_is_refused_for_an_unauthenticated_user(probe_client) -> None:  # noqa: ANN001
    response = probe_client.get(f"{PROBE_PREFIX}/undeclared")
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "permission_not_declared"


def test_the_undeclared_route_carries_the_deny_dependency() -> None:
    """The refusal is structural: the route object itself holds the guard."""
    from tests.authz_probe import build_probe_router

    router = build_probe_router()
    undeclared = [route for route in router.routes if route.path.endswith("/undeclared")]
    assert len(undeclared) == 1
    route = undeclared[0]
    assert isinstance(route, PolicyRoute)
    assert route.policy is None
    calls = {getattr(dep.call, "__name__", "") for dep in route.dependant.dependencies}
    assert "deny_undeclared_route" in calls


def test_startup_refuses_an_application_with_an_undeclared_route() -> None:
    """A plain router (no PolicyRoute) is exactly the accident this guards against."""
    app = FastAPI()
    router = APIRouter()

    @router.get("/oops")
    def oops(auth: AuthContext = Depends(require_authenticated)) -> dict[str, str]:  # noqa: B008
        return {"this": "should never be reachable"}

    app.include_router(router)
    # The routers are passed alongside the app on purpose: current FastAPI keeps included
    # routers behind an opaque handle on ``app.routes``, so a check that only inspects the app
    # would look at nothing and pass — the exact failure mode this test guards against.
    assert find_undeclared_routes(app, router) == ["/oops [GET]"]
    with pytest.raises(RuntimeError, match="declare no authorisation policy"):
        assert_routes_declared(app, router)


def world_engine():  # noqa: ANN201
    from cardioauth.db import get_engine

    return get_engine()
