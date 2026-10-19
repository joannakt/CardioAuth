"""The permission model — DESIGN.md §7.3, expressed as data.

Two declarative tables and one pure function:

* :data:`PERMISSION_SPECS` — what each permission *is*: the object type it acts on, whether
  it is read-only (it only reads the object), whether §7.3 marks it "audited", and the §7.3
  row it implements (so a reviewer can check the code against the design row by row).
* :data:`GRANTS` — which role holds which permission, and under what conditions
  (a fresh step-up, a constraint on a fact such as the letter kind, a precondition the
  caller must assert such as "a reason was supplied").
* :func:`evaluate` — the only place a role is compared to a permission. Nothing else in the
  application branches on ``role``.

Adding a permission later is an edit to these tables, not a new ``if role == ...`` anywhere.

Deny by default, in three layers:

1. A ``(role, permission)`` pair that is absent from :data:`GRANTS` is **denied**. A role
   string that is not one of §7.3's three roles (the schema also permits ``platform_admin``
   for platform operations) is **denied everything** — §7.3 does not grant it any clinical
   permission, so the restrictive reading is that it has none.
2. A constrained grant denies unless the caller supplies the fact that satisfies the
   constraint. A missing fact is a denial, never an implicit allow.
3. A sensitive grant denies unless the session re-authenticated inside the step-up window
   (§7.2, the M1b-1 ``user_session.reauth_at`` mechanism — there is no second mechanism).

Cells the design does not state are recorded in :data:`DECIDED_CELLS` with the reasoning, so
a reviewer can find every judgement call in one place.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Final


# ---------------------------------------------------------------------------
# Roles — §7.3 [FIXED]. Do not add one without a design revision.
# ---------------------------------------------------------------------------
class Role(StrEnum):
    """The three roles §7.3 defines. ``platform_admin`` is deliberately absent (see module
    docstring): it exists in the schema for platform operations, and §7.3 grants it nothing."""

    COORDINATOR = "coordinator"
    PHYSICIAN = "physician"
    ADMIN = "admin"


class Scope(StrEnum):
    """How far an object-scoped grant reaches inside the actor's own practice."""

    #: Any object belonging to the actor's practice.
    PRACTICE = "practice"
    #: Only rows the actor produced (used by "view audit log — physician: own actions").
    OWN_ACTIONS = "own_actions"


class DenialReason(StrEnum):
    """Why :func:`evaluate` returned what it returned. Recorded verbatim in the audit row."""

    GRANTED = "granted"
    ROLE_NOT_IN_MATRIX = "role_not_in_matrix"
    ROLE_NOT_PERMITTED = "role_not_permitted"
    STEP_UP_REQUIRED = "step_up_required"
    CONSTRAINT_NOT_SATISFIED = "constraint_not_satisfied"
    PRECONDITION_NOT_SATISFIED = "precondition_not_satisfied"
    # Object-level outcomes (cardioauth.authz.deps.authorize_object):
    OBJECT_NOT_FOUND = "object_not_found"
    CROSS_PRACTICE_DENIED = "cross_practice_denied"
    SCOPE_VIOLATION = "scope_violation"
    SHARED_OBJECT_NOT_WRITABLE = "shared_object_not_writable"
    # Route-level: an endpoint that declares no policy at all.
    PERMISSION_NOT_DECLARED = "permission_not_declared"


# ---------------------------------------------------------------------------
# Permissions — one per §7.3 row (plus the two §7.2 step-up actions §7.3 implies)
# ---------------------------------------------------------------------------
class Permission(StrEnum):
    CASE_WRITE = "case.write"
    DOCUMENT_UPLOAD = "document.upload"
    CASE_READ = "case.read"
    EXTRACTION_RUN = "extraction.run"
    DOCUMENT_VIEW = "document.view"
    DOCUMENT_EXPORT = "document.export"
    LETTER_GENERATE = "letter.generate"
    LETTER_EDIT = "letter.edit"
    LETTER_SIGN = "letter.sign"
    LETTER_EXPORT = "letter.export"
    CASE_TRANSITION = "case.transition"
    GAP_WAIVE = "gap.waive"
    GAP_RESOLVE = "gap.resolve"
    CRITERIA_READ = "criteria.read"
    CRITERIA_WRITE = "criteria.write"
    CRITERIA_REPIN = "criteria.repin"
    USER_MANAGE = "user.manage"
    AUDIT_READ = "audit.read"
    CASE_REDACT = "case.redact"


@dataclass(frozen=True, slots=True)
class PermissionSpec:
    """What a permission means, independent of who holds it."""

    permission: Permission
    object_type: str
    #: ``True`` for permissions that only read the object they name. Used to decide whether a
    #: library object with no owning practice (a global criteria set) is reachable.
    read_only: bool
    #: §7.3 marks the cell "⚠️ audited": the action must write its own audit row when it is
    #: performed (the action names are in :mod:`cardioauth.audit.actions`). The router cannot
    #: verify that from a dependency, so each endpoint that performs one owes the row; the
    #: matrix test pins which permissions carry the flag.
    audited: bool
    #: The §7.3 row this permission implements, verbatim, for review.
    design_row: str


_SPECS: Final[tuple[PermissionSpec, ...]] = (
    PermissionSpec(
        Permission.CASE_WRITE, "case", False, False,
        "Create/edit case, upload documents",
    ),
    PermissionSpec(
        Permission.DOCUMENT_UPLOAD, "document", False, False,
        "Create/edit case, upload documents",
    ),
    PermissionSpec(
        Permission.CASE_READ, "case", True, False,
        "View case, documents, checklist, gaps",
    ),
    PermissionSpec(
        Permission.EXTRACTION_RUN, "extraction_run", False, False,
        "Run/cancel extraction, evaluation",
    ),
    PermissionSpec(
        Permission.DOCUMENT_VIEW, "document", True, False,
        "View documents in the browser",
    ),
    PermissionSpec(
        Permission.DOCUMENT_EXPORT, "document", False, True,
        "Download/export documents (⚠️ audited)",
    ),
    PermissionSpec(
        Permission.LETTER_GENERATE, "letter", False, False,
        "Generate letters (LMN/appeal/P2P)",
    ),
    PermissionSpec(
        Permission.LETTER_EDIT, "letter_version", False, False,
        "Edit letters",
    ),
    PermissionSpec(
        Permission.LETTER_SIGN, "letter_version", False, True,
        "Sign a letter",
    ),
    PermissionSpec(
        Permission.LETTER_EXPORT, "letter_version", False, True,
        "Export PDF/DOCX (⚠️ step-up)",
    ),
    PermissionSpec(
        Permission.CASE_TRANSITION, "case", False, False,
        "Record payer decision / status transitions",
    ),
    PermissionSpec(
        Permission.GAP_WAIVE, "gap_item", False, True,
        "Waive a blocking gap (⚠️ reason required)",
    ),
    PermissionSpec(
        Permission.GAP_RESOLVE, "gap_item", False, False,
        "Resolving a gap (⚠️ step-up, §7.2)",
    ),
    PermissionSpec(
        Permission.CRITERIA_READ, "criteria_set_version", True, False,
        "Criteria library read",
    ),
    PermissionSpec(
        Permission.CRITERIA_WRITE, "criteria_set_version", False, True,
        "Criteria library create/edit/publish",
    ),
    PermissionSpec(
        Permission.CRITERIA_REPIN, "case", False, True,
        "Re-pinning criteria (§7.2 step-up; role cell decided — see DECIDED_CELLS)",
    ),
    PermissionSpec(
        Permission.USER_MANAGE, "app_user", False, True,
        "User management (within practice)",
    ),
    PermissionSpec(
        Permission.AUDIT_READ, "audit_log", True, True,
        "View audit log",
    ),
    PermissionSpec(
        Permission.CASE_REDACT, "case", False, True,
        "Delete/redact a case (⚠️ soft-redact with mandatory reason)",
    ),
)

PERMISSION_SPECS: Final[Mapping[Permission, PermissionSpec]] = MappingProxyType(
    {spec.permission: spec for spec in _SPECS}
)
if len(PERMISSION_SPECS) != len(_SPECS):  # pragma: no cover - import-time guard
    raise RuntimeError("duplicate Permission in PERMISSION_SPECS")


# ---------------------------------------------------------------------------
# Grants — the §7.3 matrix
# ---------------------------------------------------------------------------
#: The letter kinds §8.2 defines. "🔎 (may generate a P2P summary)" for the physician is a
#: constraint on ``letter.generate``, not a separate permission.
LETTER_KINDS: Final[frozenset[str]] = frozenset({"lmn", "appeal", "p2p_summary"})


@dataclass(frozen=True, slots=True)
class Grant:
    """A role holds a permission, subject to these conditions.

    ``requires_facts`` constrains a fact the caller must supply to the value set; a fact that
    is absent denies. ``requires_true`` names boolean facts the caller must assert as ``True``
    (a reason was supplied, an NPI is on file, …). Both are checked against the ``facts``
    mapping passed to :func:`evaluate`; nothing is inferred.
    """

    step_up: bool = False
    scope: Scope = Scope.PRACTICE
    requires_facts: Mapping[str, frozenset[str]] = field(default_factory=dict)
    requires_true: frozenset[str] = frozenset()


#: A plain allow inside the actor's practice.
ALLOW: Final[Grant] = Grant()
#: Allowed, but only with a step-up inside the §7.2 window.
STEP_UP: Final[Grant] = Grant(step_up=True)
#: A precondition the endpoint must assert (a reason, an NPI, an attestation).
def _with_precondition(*keys: str, step_up: bool = False, scope: Scope = Scope.PRACTICE) -> Grant:
    return Grant(step_up=step_up, scope=scope, requires_true=frozenset(keys))


#: fact name -> allowed values
_LETTER_ANY: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {"letter_kind": LETTER_KINDS}
)
_LETTER_P2P_ONLY: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {"letter_kind": frozenset({"p2p_summary"})}
)

#: permission -> {role: grant}. A role missing from a row is denied that permission.
_MATRIX: Final[Mapping[Permission, Mapping[Role, Grant]]] = MappingProxyType(
    {
        # | Create/edit case, upload documents | ✅ | ⬜ | ✅ |
        Permission.CASE_WRITE: {Role.COORDINATOR: ALLOW, Role.ADMIN: ALLOW},
        Permission.DOCUMENT_UPLOAD: {Role.COORDINATOR: ALLOW, Role.ADMIN: ALLOW},
        # | View case, documents, checklist, gaps | ✅ (own practice) | ✅ | ✅ |
        Permission.CASE_READ: {
            Role.COORDINATOR: ALLOW,
            Role.PHYSICIAN: ALLOW,
            Role.ADMIN: ALLOW,
        },
        # | Run/cancel extraction, evaluation | ✅ | ⬜ | ✅ |
        Permission.EXTRACTION_RUN: {Role.COORDINATOR: ALLOW, Role.ADMIN: ALLOW},
        # | View documents in the browser | ✅ | ✅ | ✅ |
        Permission.DOCUMENT_VIEW: {
            Role.COORDINATOR: ALLOW,
            Role.PHYSICIAN: ALLOW,
            Role.ADMIN: ALLOW,
        },
        # | Download/export documents | ⚠️ audited ×3 |
        # §7.2's step-up list names "exporting PDF/DOCX" (letters); downloading a source
        # document is audited but not step-up, so this row is an allow carrying the audited
        # flag on its spec.
        Permission.DOCUMENT_EXPORT: {
            Role.COORDINATOR: ALLOW,
            Role.PHYSICIAN: ALLOW,
            Role.ADMIN: ALLOW,
        },
        # | Generate letters | ✅ | 🔎 (may generate a P2P summary) | ✅ |
        Permission.LETTER_GENERATE: {
            Role.COORDINATOR: Grant(requires_facts=_LETTER_ANY),
            Role.PHYSICIAN: Grant(requires_facts=_LETTER_P2P_ONLY),
            Role.ADMIN: Grant(requires_facts=_LETTER_ANY),
        },
        # | Edit letters | ✅ | ✅ (may edit before signing) | ✅ |
        Permission.LETTER_EDIT: {
            Role.COORDINATOR: ALLOW,
            Role.PHYSICIAN: ALLOW,
            Role.ADMIN: ALLOW,
        },
        # | Sign a letter | ⬜ | ✅ (physician NPI required) |
        #   ⚠️ admin only with a covering-physician attestation |
        Permission.LETTER_SIGN: {
            Role.PHYSICIAN: _with_precondition("signer_npi_present", step_up=True),
            Role.ADMIN: _with_precondition("covering_physician_attestation", step_up=True),
        },
        # | Export PDF/DOCX | ⚠️ step-up ×3 |
        Permission.LETTER_EXPORT: {
            Role.COORDINATOR: STEP_UP,
            Role.PHYSICIAN: STEP_UP,
            Role.ADMIN: STEP_UP,
        },
        # | Record payer decision / status transitions | ✅ per §6.2 ×3 |
        Permission.CASE_TRANSITION: {
            Role.COORDINATOR: ALLOW,
            Role.PHYSICIAN: ALLOW,
            Role.ADMIN: ALLOW,
        },
        # | Waive a blocking gap | ⚠️ reason required | ⬜ | ⚠️ reason required |
        Permission.GAP_WAIVE: {
            Role.COORDINATOR: _with_precondition("reason_present", step_up=True),
            Role.ADMIN: _with_precondition("reason_present", step_up=True),
        },
        # | (resolving a gap — §7.2 requires a step-up; §7.3 is silent on the role cell) |
        Permission.GAP_RESOLVE: {Role.COORDINATOR: STEP_UP, Role.ADMIN: STEP_UP},
        # | Criteria library read | 🔎 | 🔎 | ✅ |
        Permission.CRITERIA_READ: {
            Role.COORDINATOR: ALLOW,
            Role.PHYSICIAN: ALLOW,
            Role.ADMIN: ALLOW,
        },
        # | Criteria library create/edit/publish | ⬜ | ⬜ | ✅ |
        Permission.CRITERIA_WRITE: {Role.ADMIN: STEP_UP},
        # | (re-pinning criteria — §7.2 step-up; §7.3 is silent on the role cell) |
        Permission.CRITERIA_REPIN: {Role.ADMIN: STEP_UP},
        # | User management | ⬜ | ⬜ | ✅ (within practice) |
        Permission.USER_MANAGE: {Role.ADMIN: STEP_UP},
        # | View audit log | ⬜ | 🔎 own actions | ✅ (practice scope) |
        Permission.AUDIT_READ: {
            Role.PHYSICIAN: Grant(step_up=True, scope=Scope.OWN_ACTIONS),
            Role.ADMIN: STEP_UP,
        },
        # | Delete/redact a case | ⬜ | ⬜ | ⚠️ soft-redact, mandatory reason |
        # §7.2's step-up list does not name redaction, so this is reason-only; recorded in
        # DECIDED_CELLS.
        Permission.CASE_REDACT: {Role.ADMIN: _with_precondition("reason_present")},
    }
)

GRANTS: Final[Mapping[tuple[Role, Permission], Grant]] = MappingProxyType(
    {
        (role, permission): grant
        for permission, row in _MATRIX.items()
        for role, grant in row.items()
    }
)

if set(_MATRIX) != set(Permission):  # pragma: no cover - import-time guard
    raise RuntimeError("every Permission needs a §7.3 row in _MATRIX")


#: Cells §7.3 does not state, and the restrictive reading this milestone implemented.
DECIDED_CELLS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "platform_admin": (
            "app_user.role also permits 'platform_admin'. §7.3 defines three roles and grants "
            "none of them to platform_admin, so it holds no permission at all: every "
            "evaluate('platform_admin', …) denies with role_not_in_matrix."
        ),
        "criteria.repin": (
            "§7.2 requires a step-up to re-pin criteria but §7.3 has no row for it. Most "
            "restrictive reading: admin only, with step-up. (Re-pinning is arguably part of "
            "'create/edit case', which coordinators hold; flagged for the lead.)"
        ),
        "gap.resolve": (
            "§7.2 requires a step-up to resolve or waive a gap; §7.3 only lists waiving. "
            "Resolving is the coordinator's normal loop, so coordinator and admin hold it with "
            "a step-up and the physician does not (mirroring the waive row)."
        ),
        "case.redact": (
            "§7.3 marks redaction ⚠️ 'with mandatory reason'; §7.2's step-up list does not "
            "include it. Implemented as admin-only with a mandatory reason and no step-up."
        ),
        "document.export": (
            "§7.3 says '⚠️ audited' and §7.2's step-up list covers PDF/DOCX letter export, "
            "not source-document download. Implemented as an audited allow without step-up."
        ),
        "letter.generate(physician)": (
            "'🔎 may generate a P2P summary' is a constraint on the letter kind, not a "
            "separate permission: physician + letter_kind=p2p_summary is allowed, lmn/appeal "
            "deny with constraint_not_satisfied."
        ),
        "letter.sign(admin)": (
            "'⚠️ only with an explicit covering physician attestation' is modelled as the "
            "precondition fact covering_physician_attestation; the sign-off row that stores "
            "the attestation text arrives with the sign-off milestone."
        ),
        "letter.sign(physician)": (
            "'physician NPI required' is the precondition fact signer_npi_present, backed by "
            "signoff.signer_npi / app_user.npi which already exist in the schema."
        ),
    }
)


# ---------------------------------------------------------------------------
# Evaluation — the only role comparison in the application
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Decision:
    permission: Permission
    role: str
    allowed: bool
    reason: DenialReason
    grant: Grant | None

    @property
    def step_up_required(self) -> bool:
        return self.grant is not None and self.grant.step_up

    @property
    def scope(self) -> Scope:
        return self.grant.scope if self.grant is not None else Scope.PRACTICE


def spec_for(permission: Permission) -> PermissionSpec:
    return PERMISSION_SPECS[permission]


def grant_for(role: str | Role, permission: Permission) -> Grant | None:
    """The grant this role holds for this permission, or ``None`` (denied)."""
    try:
        role_enum = Role(role)
    except ValueError:
        return None
    return GRANTS.get((role_enum, permission))


def evaluate(
    role: str | Role,
    permission: Permission,
    *,
    facts: Mapping[str, object] | None = None,
    reauth_fresh: bool = False,
) -> Decision:
    """Decide one ``(role, permission)`` cell. Pure: no I/O, no session, no clock.

    ``reauth_fresh`` is whether the session re-authenticated inside the §7.2 step-up window;
    it defaults to ``False`` so a caller that forgets to pass it gets a denial, never a pass.
    """
    if not isinstance(permission, Permission):
        raise TypeError(f"evaluate() needs a Permission, got {type(permission).__name__}")
    facts = facts or {}
    role_value = role.value if isinstance(role, Role) else str(role)

    try:
        role_enum = Role(role_value)
    except ValueError:
        return Decision(permission, role_value, False, DenialReason.ROLE_NOT_IN_MATRIX, None)

    grant = GRANTS.get((role_enum, permission))
    if grant is None:
        return Decision(permission, role_enum.value, False, DenialReason.ROLE_NOT_PERMITTED, None)

    if grant.step_up and not reauth_fresh:
        return Decision(permission, role_enum.value, False, DenialReason.STEP_UP_REQUIRED, grant)

    for fact_name, allowed_values in grant.requires_facts.items():
        if facts.get(fact_name) not in allowed_values:
            return Decision(
                permission, role_enum.value, False, DenialReason.CONSTRAINT_NOT_SATISFIED, grant
            )

    for fact_name in grant.requires_true:
        if facts.get(fact_name) is not True:
            return Decision(
                permission, role_enum.value, False, DenialReason.PRECONDITION_NOT_SATISFIED, grant
            )

    return Decision(permission, role_enum.value, True, DenialReason.GRANTED, grant)


def sensitive_permissions() -> frozenset[Permission]:
    """Every permission that needs a step-up for at least one role (§7.2)."""
    return frozenset(p for (_, p), grant in GRANTS.items() if grant.step_up)


def matrix_rows() -> tuple[tuple[Permission, Mapping[Role, Grant]], ...]:
    """The matrix in §7.3 order, for docs, the admin UI and the table-driven test."""
    return tuple((permission, _MATRIX[permission]) for permission in Permission)


__all__ = [
    "ALLOW",
    "DECIDED_CELLS",
    "GRANTS",
    "LETTER_KINDS",
    "PERMISSION_SPECS",
    "STEP_UP",
    "Decision",
    "DenialReason",
    "Grant",
    "Permission",
    "PermissionSpec",
    "Role",
    "Scope",
    "evaluate",
    "grant_for",
    "matrix_rows",
    "sensitive_permissions",
    "spec_for",
]
