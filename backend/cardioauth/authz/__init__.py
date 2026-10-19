"""Authorisation: the §7.3 RBAC matrix as data, plus the dependencies that enforce it.

* :mod:`cardioauth.authz.permissions` — roles, permissions, the grant table, ``evaluate()``.
* :mod:`cardioauth.authz.objects` — how to load a case / criteria version / user and find the
  practice that owns it.
* :mod:`cardioauth.authz.deps` — ``require_permission``, ``authorize_object``, audited denials.
* :mod:`cardioauth.authz.policy` — the endpoint → policy table and the deny-by-default route.

Nothing here reads a criterion, a letter or a document. This module decides *who may ask*;
the services decide what the answer contains.
"""

from __future__ import annotations

from cardioauth.authz.deps import (
    AuthorizedObject,
    audit_denial,
    authorize_object,
    deny_undeclared_route,
    reauth_is_fresh,
    require_permission,
)
from cardioauth.authz.permissions import (
    DECIDED_CELLS,
    GRANTS,
    PERMISSION_SPECS,
    Decision,
    DenialReason,
    Grant,
    Permission,
    PermissionSpec,
    Role,
    Scope,
    evaluate,
    grant_for,
    sensitive_permissions,
)
from cardioauth.authz.policy import (
    ROUTE_POLICIES,
    PolicyKind,
    PolicyRoute,
    RoutePolicy,
    assert_routes_declared,
    find_undeclared_routes,
)

__all__ = [
    "DECIDED_CELLS",
    "GRANTS",
    "PERMISSION_SPECS",
    "ROUTE_POLICIES",
    "AuthorizedObject",
    "Decision",
    "DenialReason",
    "Grant",
    "Permission",
    "PermissionSpec",
    "PolicyKind",
    "PolicyRoute",
    "Role",
    "RoutePolicy",
    "Scope",
    "assert_routes_declared",
    "audit_denial",
    "authorize_object",
    "deny_undeclared_route",
    "evaluate",
    "find_undeclared_routes",
    "grant_for",
    "reauth_is_fresh",
    "require_permission",
    "sensitive_permissions",
]
