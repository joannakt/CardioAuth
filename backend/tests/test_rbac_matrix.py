"""The §7.3 matrix, table-driven — the implementation is checked against the design, not
against itself.

``EXPECTED`` below is a hand transcription of the table in DESIGN.md §7.3 (legend: ✅ allowed,
🔎 read-only, ⬜ denied, ⚠️ allowed with step-up or an extra precondition). It is deliberately
written out in full rather than derived from ``cardioauth.authz``: a test that reads the
answer from the code it is testing cannot fail. Every one of the 19 permissions × 3 roles = 57
cells is asserted, so a cell that is missing from the implementation raises ``KeyError`` or a
denial rather than quietly passing.

The second half walks the same matrix over HTTP through the real dependency, so the wiring
(not just the pure function) is proven: for every role, every permission, the status code is
compared with the design.

Synthetic accounts only; nothing clinical appears in this file.
"""

from __future__ import annotations

from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from cardioauth.authz.permissions import (
    DECIDED_CELLS,
    GRANTS,
    PERMISSION_SPECS,
    DenialReason,
    Permission,
    Role,
    Scope,
    evaluate,
    sensitive_permissions,
)
from tests.authz_probe import PROBE_PREFIX
from tests.authz_support import (
    ROLES,
    SATISFYING_FACTS,
    audit_rows,
    chain_verifies,
    sign_in,
    step_up,
)

pytestmark = pytest.mark.db

ALLOWED, DENIED = True, False

#: DESIGN.md §7.3, transcribed row by row.
EXPECTED: dict[Permission, dict[Role, bool]] = {
    # | Create/edit case, upload documents | ✅ | ⬜ | ✅ |
    Permission.CASE_WRITE: {Role.COORDINATOR: ALLOWED, Role.PHYSICIAN: DENIED, Role.ADMIN: ALLOWED},
    Permission.DOCUMENT_UPLOAD: {
        Role.COORDINATOR: ALLOWED,
        Role.PHYSICIAN: DENIED,
        Role.ADMIN: ALLOWED,
    },
    # | View case, documents, checklist, gaps | ✅ (own practice) | ✅ | ✅ |
    Permission.CASE_READ: {Role.COORDINATOR: ALLOWED, Role.PHYSICIAN: ALLOWED, Role.ADMIN: ALLOWED},
    # | Run/cancel extraction, evaluation | ✅ | ⬜ | ✅ |
    Permission.EXTRACTION_RUN: {Role.COORDINATOR: ALLOWED, Role.PHYSICIAN: DENIED, Role.ADMIN: ALLOWED},
    # | View documents in the browser | ✅ | ✅ | ✅ |
    Permission.DOCUMENT_VIEW: {
        Role.COORDINATOR: ALLOWED,
        Role.PHYSICIAN: ALLOWED,
        Role.ADMIN: ALLOWED,
    },
    # | Download/export documents | ⚠️ audited ×3 |
    Permission.DOCUMENT_EXPORT: {
        Role.COORDINATOR: ALLOWED,
        Role.PHYSICIAN: ALLOWED,
        Role.ADMIN: ALLOWED,
    },
    # | Generate letters | ✅ | 🔎 (may generate a P2P summary) | ✅ |
    Permission.LETTER_GENERATE: {
        Role.COORDINATOR: ALLOWED,
        Role.PHYSICIAN: ALLOWED,
        Role.ADMIN: ALLOWED,
    },
    # | Edit letters | ✅ | ✅ (may edit before signing) | ✅ |
    Permission.LETTER_EDIT: {Role.COORDINATOR: ALLOWED, Role.PHYSICIAN: ALLOWED, Role.ADMIN: ALLOWED},
    # | Sign a letter | ⬜ | ✅ (physician NPI required) | ⚠️ covering physician attestation |
    Permission.LETTER_SIGN: {
        Role.COORDINATOR: DENIED,
        Role.PHYSICIAN: ALLOWED,
        Role.ADMIN: ALLOWED,
    },
    # | Export PDF/DOCX | ⚠️ step-up ×3 |
    Permission.LETTER_EXPORT: {
        Role.COORDINATOR: ALLOWED,
        Role.PHYSICIAN: ALLOWED,
        Role.ADMIN: ALLOWED,
    },
    # | Record payer decision / status transitions | ✅ per §6.2 ×3 |
    Permission.CASE_TRANSITION: {
        Role.COORDINATOR: ALLOWED,
        Role.PHYSICIAN: ALLOWED,
        Role.ADMIN: ALLOWED,
    },
    # | Waive a blocking gap | ⚠️ reason required | ⬜ | ⚠️ reason required |
    Permission.GAP_WAIVE: {Role.COORDINATOR: ALLOWED, Role.PHYSICIAN: DENIED, Role.ADMIN: ALLOWED},
    # | (resolving a gap — §7.2 step-up; role cell decided, see DECIDED_CELLS) |
    Permission.GAP_RESOLVE: {Role.COORDINATOR: ALLOWED, Role.PHYSICIAN: DENIED, Role.ADMIN: ALLOWED},
    # | Criteria library read | 🔎 | 🔎 | ✅ |
    Permission.CRITERIA_READ: {
        Role.COORDINATOR: ALLOWED,
        Role.PHYSICIAN: ALLOWED,
        Role.ADMIN: ALLOWED,
    },
    # | Criteria library create/edit/publish | ⬜ | ⬜ | ✅ |
    Permission.CRITERIA_WRITE: {
        Role.COORDINATOR: DENIED,
        Role.PHYSICIAN: DENIED,
        Role.ADMIN: ALLOWED,
    },
    # | (re-pinning criteria — §7.2 step-up; role cell decided) |
    Permission.CRITERIA_REPIN: {
        Role.COORDINATOR: DENIED,
        Role.PHYSICIAN: DENIED,
        Role.ADMIN: ALLOWED,
    },
    # | User management | ⬜ | ⬜ | ✅ (within practice) |
    Permission.USER_MANAGE: {Role.COORDINATOR: DENIED, Role.PHYSICIAN: DENIED, Role.ADMIN: ALLOWED},
    # | View audit log | ⬜ | 🔎 own actions | ✅ (practice scope) |
    Permission.AUDIT_READ: {
        Role.COORDINATOR: DENIED,
        Role.PHYSICIAN: ALLOWED,
        Role.ADMIN: ALLOWED,
    },
    # | Delete/redact a case | ⬜ | ⬜ | ⚠️ soft-redact with mandatory reason |
    Permission.CASE_REDACT: {Role.COORDINATOR: DENIED, Role.PHYSICIAN: DENIED, Role.ADMIN: ALLOWED},
}

#: §7.2's step-up list, transcribed: "signing a letter, exporting PDF/DOCX, resolving/waiving
#: a gap, editing the criteria library, changing users or roles, viewing the audit log, and
#: re-pinning criteria".
EXPECTED_STEP_UP = frozenset(
    {
        Permission.LETTER_SIGN,
        Permission.LETTER_EXPORT,
        Permission.GAP_WAIVE,
        Permission.GAP_RESOLVE,
        Permission.CRITERIA_WRITE,
        Permission.CRITERIA_REPIN,
        Permission.USER_MANAGE,
        Permission.AUDIT_READ,
    }
)


# ---------------------------------------------------------------------------
# The table itself
# ---------------------------------------------------------------------------
def test_the_expected_table_covers_every_permission_and_every_role() -> None:
    assert set(EXPECTED) == set(Permission), "the design table and the enum disagree"
    for permission, row in EXPECTED.items():
        assert set(row) == set(Role), f"{permission} is missing a role column"
    assert sum(len(row) for row in EXPECTED.values()) == len(Permission) * len(Role) == 57


def test_every_permission_is_described_once_and_has_a_matrix_row() -> None:
    assert set(PERMISSION_SPECS) == set(Permission)
    for permission in Permission:
        assert any(p == permission for (_, p) in GRANTS), f"{permission} has no grant row at all"


@pytest.mark.parametrize("permission", list(Permission), ids=lambda p: p.value)
def test_each_role_matches_the_design_cell(permission: Permission) -> None:
    """One test per §7.3 row; all three role cells asserted, so a missing cell fails."""
    row = EXPECTED[permission]
    for role in Role:
        decision = evaluate(role, permission, facts=SATISFYING_FACTS, reauth_fresh=True)
        assert decision.allowed is row[role], (
            f"§7.3 says {role.value} {'may' if row[role] else 'may not'} {permission.value}, "
            f"implementation said {decision.allowed} ({decision.reason})"
        )
        if not row[role]:
            assert decision.reason is DenialReason.ROLE_NOT_PERMITTED


def test_no_extra_grants_exist_beyond_the_design_table() -> None:
    """A grant for a cell the design denies would be a silent widening of the matrix."""
    for (role, permission), _grant in GRANTS.items():
        assert EXPECTED[permission][role] is ALLOWED, (
            f"implementation grants {permission.value} to {role.value}, §7.3 denies it"
        )


def test_platform_admin_holds_no_permission() -> None:
    """The schema allows a platform_admin role; §7.3 grants it nothing. Restrictive reading."""
    for permission in Permission:
        decision = evaluate("platform_admin", permission, facts=SATISFYING_FACTS, reauth_fresh=True)
        assert decision.allowed is False
        assert decision.reason is DenialReason.ROLE_NOT_IN_MATRIX


def test_step_up_set_matches_section_7_2() -> None:
    assert sensitive_permissions() == EXPECTED_STEP_UP


@pytest.mark.parametrize("permission", sorted(EXPECTED_STEP_UP, key=str), ids=lambda p: p.value)
def test_sensitive_permission_is_denied_without_a_fresh_step_up(permission: Permission) -> None:
    for role in Role:
        decision = evaluate(role, permission, facts=SATISFYING_FACTS, reauth_fresh=False)
        if EXPECTED[permission][role] is DENIED:
            continue  # role denial is the earlier, more informative reason
        assert decision.allowed is False
        assert decision.reason is DenialReason.STEP_UP_REQUIRED
        assert decision.step_up_required is True


def test_step_up_defaults_to_not_fresh() -> None:
    """A caller that forgets to say it stepped up gets a denial, never a pass."""
    assert evaluate(Role.ADMIN, Permission.LETTER_EXPORT).allowed is False


# ---------------------------------------------------------------------------
# The constraints the ⚠️ cells carry
# ---------------------------------------------------------------------------
def test_physician_may_generate_only_a_p2p_summary() -> None:
    for kind in ("lmn", "appeal"):
        decision = evaluate(
            Role.PHYSICIAN, Permission.LETTER_GENERATE, facts={"letter_kind": kind}, reauth_fresh=True
        )
        assert decision.allowed is False
        assert decision.reason is DenialReason.CONSTRAINT_NOT_SATISFIED
    allowed = evaluate(
        Role.PHYSICIAN, Permission.LETTER_GENERATE, facts={"letter_kind": "p2p_summary"}, reauth_fresh=True
    )
    assert allowed.allowed is True
    # A coordinator may generate every kind.
    for kind in ("lmn", "appeal", "p2p_summary"):
        assert evaluate(
            Role.COORDINATOR, Permission.LETTER_GENERATE, facts={"letter_kind": kind}, reauth_fresh=True
        ).allowed


def test_a_missing_constraint_fact_denies() -> None:
    """No letter kind supplied is a denial, not "any kind will do"."""
    decision = evaluate(Role.COORDINATOR, Permission.LETTER_GENERATE, reauth_fresh=True)
    assert decision.allowed is False
    assert decision.reason is DenialReason.CONSTRAINT_NOT_SATISFIED


def test_signing_requires_the_physician_npi_and_the_admin_attestation() -> None:
    no_npi = evaluate(Role.PHYSICIAN, Permission.LETTER_SIGN, facts={}, reauth_fresh=True)
    assert no_npi.allowed is False and no_npi.reason is DenialReason.PRECONDITION_NOT_SATISFIED
    with_npi = evaluate(
        Role.PHYSICIAN, Permission.LETTER_SIGN, facts={"signer_npi_present": True}, reauth_fresh=True
    )
    assert with_npi.allowed is True

    no_attestation = evaluate(Role.ADMIN, Permission.LETTER_SIGN, facts={}, reauth_fresh=True)
    assert no_attestation.allowed is False
    assert no_attestation.reason is DenialReason.PRECONDITION_NOT_SATISFIED
    attested = evaluate(
        Role.ADMIN,
        Permission.LETTER_SIGN,
        facts={"covering_physician_attestation": True},
        reauth_fresh=True,
    )
    assert attested.allowed is True


@pytest.mark.parametrize("permission", [Permission.GAP_WAIVE, Permission.CASE_REDACT])
def test_reason_required_actions_refuse_a_missing_reason(permission: Permission) -> None:
    role = Role.ADMIN
    denied = evaluate(role, permission, facts={}, reauth_fresh=True)
    assert denied.allowed is False and denied.reason is DenialReason.PRECONDITION_NOT_SATISFIED
    allowed = evaluate(role, permission, facts={"reason_present": True}, reauth_fresh=True)
    assert allowed.allowed is True


def test_a_truthy_string_is_not_a_precondition() -> None:
    """Preconditions are asserted as booleans; a non-empty string is not an assertion."""
    decision = evaluate(
        Role.ADMIN, Permission.CASE_REDACT, facts={"reason_present": "yes"}, reauth_fresh=True
    )
    assert decision.allowed is False


def test_audit_read_scope_is_own_actions_for_the_physician_and_practice_for_the_admin() -> None:
    physician = evaluate(Role.PHYSICIAN, Permission.AUDIT_READ, reauth_fresh=True)
    admin = evaluate(Role.ADMIN, Permission.AUDIT_READ, reauth_fresh=True)
    assert physician.scope is Scope.OWN_ACTIONS
    assert admin.scope is Scope.PRACTICE


def test_every_decided_cell_is_documented() -> None:
    """Judgement calls §7.3 does not state are written down, not left implicit."""
    assert set(DECIDED_CELLS) == {
        "platform_admin",
        "criteria.repin",
        "gap.resolve",
        "case.redact",
        "document.export",
        "letter.generate(physician)",
        "letter.sign(admin)",
        "letter.sign(physician)",
    }
    assert all(reason.strip() for reason in DECIDED_CELLS.values())


# ---------------------------------------------------------------------------
# The same matrix, over HTTP, through the real dependency
# ---------------------------------------------------------------------------
@contextmanager
def _signed_in(app, users, practice: str, role: str, clock):  # noqa: ANN001, ANN201
    """A client holding a fully authenticated, freshly stepped-up session for one account."""
    with TestClient(app) as client:
        sign_in(client, users.account(practice, role), clock)
        step_up(client, users.account(practice, role), clock)
        yield client


def _facts_as_query() -> dict[str, str]:
    """The satisfying facts as query parameters for the probe endpoints."""
    return {key: ("true" if value is True else str(value)) for key, value in SATISFYING_FACTS.items()}


def test_http_walks_the_whole_matrix_for_every_role(probe_app, world, totp_clock) -> None:  # noqa: ANN001
    """57 requests: every role × every permission, compared with §7.3."""
    mismatches: list[str] = []
    for role in ROLES:
        with _signed_in(probe_app, world, "a", role, totp_clock) as client:
            for permission in Permission:
                response = client.get(
                    f"{PROBE_PREFIX}/{permission.value}", params=_facts_as_query()
                )
                expected_status = 200 if EXPECTED[permission][Role(role)] else 403
                if response.status_code != expected_status:
                    mismatches.append(
                        f"{role}/{permission.value}: expected {expected_status}, "
                        f"got {response.status_code} {response.text}"
                    )
    assert not mismatches, "\n".join(mismatches)


def test_http_denied_role_is_refused_and_audited(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    account = world.account("a", "physician")
    sign_in(probe_client, account, totp_clock)
    step_up(probe_client, account, totp_clock)

    response = probe_client.get(f"{PROBE_PREFIX}/case.write")
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "permission_denied"

    rows = audit_rows(world_engine(probe_client), actor_user_id=account.user_id)
    assert len(rows) == 1, f"expected exactly one denial, got {rows}"
    assert rows[0]["outcome"] == "denied"
    assert rows[0]["object_type"] == "case"
    assert rows[0]["detail"]["permission"] == "case.write"
    assert rows[0]["detail"]["reason"] == "role_not_permitted"
    assert rows[0]["detail"]["role"] == "physician"
    assert rows[0]["actor_role"] == "physician"


def test_http_sensitive_permission_without_step_up_is_refused(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    """Signed in but not stepped up: letter.export is allowed to the role, refused to this session."""
    account = world.account("a", "coordinator")
    sign_in(probe_client, account, totp_clock)

    response = probe_client.get(f"{PROBE_PREFIX}/letter.export")
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "reauth_required"

    rows = audit_rows(world_engine(probe_client), actor_user_id=account.user_id)
    assert len(rows) == 1
    assert rows[0]["detail"]["reason"] == "step_up_required"
    assert rows[0]["detail"]["step_up_required"] is True
    assert rows[0]["detail"]["permission"] == "letter.export"

    # After a real step-up the same request succeeds.
    step_up(probe_client, account, totp_clock)
    assert probe_client.get(f"{PROBE_PREFIX}/letter.export").status_code == 200


def test_http_letter_kind_constraint_for_the_physician(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    account = world.account("a", "physician")
    sign_in(probe_client, account, totp_clock)
    step_up(probe_client, account, totp_clock)

    refused = probe_client.get(f"{PROBE_PREFIX}/letter.generate", params={"letter_kind": "lmn"})
    assert refused.status_code == 403
    assert refused.json()["detail"]["code"] == "permission_denied"
    allowed = probe_client.get(
        f"{PROBE_PREFIX}/letter.generate", params={"letter_kind": "p2p_summary"}
    )
    assert allowed.status_code == 200


def test_unauthenticated_requests_are_refused_by_every_permission(probe_client) -> None:  # noqa: ANN001
    for permission in Permission:
        response = probe_client.get(f"{PROBE_PREFIX}/{permission.value}")
        assert response.status_code == 401, permission


def test_a_session_that_owes_a_second_factor_passes_no_permission(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    """A pending session is authenticated but not verified: it must not reach any permission.

    The physician enrols a factor in a first client; a second client then logs in with the
    password alone and holds a pending session.
    """
    account = world.account("a", "physician")
    with TestClient(probe_client.app) as first:
        sign_in(first, account, totp_clock)

    with TestClient(probe_client.app) as pending:
        login = pending.post(
            "/api/auth/login", json={"email": account.email, "password": account.password}
        )
        assert login.status_code == 200
        assert login.json()["two_factor_verified"] is False
        assert login.json()["totp_enrolled"] is True

        for permission in Permission:
            response = pending.get(f"{PROBE_PREFIX}/{permission.value}")
            assert response.status_code == 403, permission
            assert response.json()["detail"]["code"] == "second_factor_required"

        # Nothing was attributed to the pending session: it never reached a permission check.
        assert audit_rows(world_engine(probe_client), actor_user_id=account.user_id) == []


def test_a_denial_does_not_break_the_audit_chain(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    account = world.account("a", "coordinator")
    sign_in(probe_client, account, totp_clock)
    for permission in (Permission.CRITERIA_WRITE, Permission.USER_MANAGE):
        assert probe_client.get(f"{PROBE_PREFIX}/{permission.value}").status_code == 403

    checked, last_id = chain_verifies(world_engine(probe_client))
    assert checked > 0 and last_id > 0
    rows = audit_rows(world_engine(probe_client), actor_user_id=account.user_id)
    assert len(rows) == 2


def world_engine(client: TestClient):  # noqa: ANN201
    """The engine behind the app under test (the test database, not a fixture copy)."""
    from cardioauth.db import get_engine

    return get_engine()
