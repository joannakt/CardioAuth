"""Practice scoping and referenced-object authorisation (§7.3 "own practice").

The role matrix says *who may ask*; this file is about *which object* the answer may touch.
Two practices, three accounts each, real rows in the real database:

* a user of practice A cannot read or mutate an object of practice B, whether the id arrives
  in the path or the query string, and whether the role would otherwise allow the verb;
* the refusal is a **404 with the same body as an id that does not exist**, so a probe learns
  nothing about whether the id is real somewhere else;
* the refusal is audited with the reason, the permission and the object type — identifiers
  only, never a clinical value;
* a shared-library row (a global criteria set, no owning practice) is readable by everyone and
  writable by nobody.

Synthetic rows only; the case fixtures carry an empty ``patient_display``.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from cardioauth.authz.objects import audit_scope_filter
from cardioauth.authz.permissions import Scope
from cardioauth.db.models import AuditLog
from tests.authz_probe import PROBE_PREFIX
from tests.authz_support import audit_rows, chain_verifies, sign_in, step_up

pytestmark = pytest.mark.db

CASE_READ = f"{PROBE_PREFIX}/objects/case"
CASE_WRITE = f"{PROBE_PREFIX}/objects/case"
CRITERIA_READ = f"{PROBE_PREFIX}/objects/criteria_set_version"
CRITERIA_WRITE = f"{PROBE_PREFIX}/objects/criteria_set_version"
USER_READ = f"{PROBE_PREFIX}/objects/app_user"


def _sign_in(probe_client, world, practice: str, role: str, clock, *, stepped_up: bool = False):  # noqa: ANN001, ANN202
    account = world.account(practice, role)
    sign_in(probe_client, account, clock)
    if stepped_up:
        step_up(probe_client, account, clock)
    return account


# ---------------------------------------------------------------------------
# Reading another practice's case
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("role", ["coordinator", "physician", "admin"])
def test_a_user_cannot_read_another_practice_case(probe_client, world, totp_clock, role: str) -> None:  # noqa: ANN001
    account = _sign_in(probe_client, world, "a", role, totp_clock)

    own = probe_client.get(f"{CASE_READ}/{world.cases['a']}")
    assert own.status_code == 200, own.text
    assert own.json()["object_id"] == str(world.cases["a"])

    foreign = probe_client.get(f"{CASE_READ}/{world.cases['b']}")
    assert foreign.status_code == 404, foreign.text
    assert foreign.json()["detail"]["code"] == "not_found"

    rows = audit_rows(world_engine(), actor_user_id=account.user_id)
    assert len(rows) == 1, f"expected exactly one denial, got {rows}"
    assert rows[0]["object_type"] == "case"
    assert rows[0]["object_id"] == world.cases["b"]
    assert rows[0]["detail"]["reason"] == "cross_practice_denied"
    assert rows[0]["detail"]["permission"] == "case.read"
    assert rows[0]["detail"]["role"] == role


def test_a_cross_practice_refusal_is_indistinguishable_from_a_missing_object(
    probe_client, world, totp_clock
) -> None:  # noqa: ANN001
    """The whole point of 404-not-403: the response must not confirm the object exists."""
    _sign_in(probe_client, world, "a", "coordinator", totp_clock)

    foreign = probe_client.get(f"{CASE_READ}/{world.cases['b']}")
    missing = probe_client.get(f"{CASE_READ}/{uuid.uuid4()}")
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()


def test_a_missing_object_is_audited_as_not_found(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    account = _sign_in(probe_client, world, "a", "coordinator", totp_clock)
    unknown = uuid.uuid4()
    assert probe_client.get(f"{CASE_READ}/{unknown}").status_code == 404

    rows = audit_rows(world_engine(), actor_user_id=account.user_id)
    assert len(rows) == 1
    assert rows[0]["detail"]["reason"] == "object_not_found"
    assert rows[0]["object_id"] == unknown


def test_an_unparseable_object_id_is_a_404_not_a_500(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    account = _sign_in(probe_client, world, "a", "coordinator", totp_clock)
    response = probe_client.get(f"{CASE_READ}/not-a-uuid")
    assert response.status_code == 404
    rows = audit_rows(world_engine(), actor_user_id=account.user_id)
    assert len(rows) == 1
    assert rows[0]["detail"]["reason"] == "object_not_found"


# ---------------------------------------------------------------------------
# Writing another practice's case
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("role", ["coordinator", "admin"])
def test_a_user_cannot_write_another_practice_case(probe_client, world, totp_clock, role: str) -> None:  # noqa: ANN001
    account = _sign_in(probe_client, world, "a", role, totp_clock)

    assert probe_client.post(f"{CASE_WRITE}/{world.cases['a']}/write").status_code == 200

    foreign = probe_client.post(f"{CASE_WRITE}/{world.cases['b']}/write")
    assert foreign.status_code == 404
    assert foreign.json()["detail"]["code"] == "not_found"

    rows = audit_rows(world_engine(), actor_user_id=account.user_id)
    assert len(rows) == 1
    assert rows[0]["detail"]["reason"] == "cross_practice_denied"
    assert rows[0]["detail"]["permission"] == "case.write"


def test_the_physician_of_practice_b_may_read_its_own_case(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    """The denial is about the practice, not about the role: practice B's own staff work normally."""
    _sign_in(probe_client, world, "b", "physician", totp_clock)
    assert probe_client.get(f"{CASE_READ}/{world.cases['b']}").status_code == 200
    assert probe_client.get(f"{CASE_READ}/{world.cases['a']}").status_code == 404


def test_the_query_string_cannot_widen_reach(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    """An id smuggled in the query string is resolved the same way and refused the same way."""
    _sign_in(probe_client, world, "a", "coordinator", totp_clock)
    response = probe_client.get(f"{CASE_READ}/{world.cases['a']}?object_id={world.cases['b']}")
    # The path id wins; the query string is not a second address for the object.
    assert response.status_code == 200
    assert response.json()["object_id"] == str(world.cases["a"])


# ---------------------------------------------------------------------------
# Criteria versions: practice-owned and shared-library rows
# ---------------------------------------------------------------------------
def test_criteria_versions_are_practice_scoped(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    account = _sign_in(probe_client, world, "a", "coordinator", totp_clock)

    assert probe_client.get(f"{CRITERIA_READ}/{world.criteria_versions['a']}").status_code == 200
    foreign = probe_client.get(f"{CRITERIA_READ}/{world.criteria_versions['b']}")
    assert foreign.status_code == 404
    rows = audit_rows(world_engine(), actor_user_id=account.user_id)
    assert [row["detail"]["reason"] for row in rows] == ["cross_practice_denied"]


def test_a_shared_library_row_is_readable_but_never_writable(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    global_version = world.criteria_versions["global"]

    _sign_in(probe_client, world, "a", "coordinator", totp_clock)
    assert probe_client.get(f"{CRITERIA_READ}/{global_version}").status_code == 200


def test_writing_a_shared_library_row_is_refused(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    account = _sign_in(probe_client, world, "a", "admin", totp_clock, stepped_up=True)
    response = probe_client.post(f"{CRITERIA_WRITE}/{world.criteria_versions['global']}/write")
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "permission_denied"

    rows = audit_rows(world_engine(), actor_user_id=account.user_id)
    assert len(rows) == 1
    assert rows[0]["detail"]["reason"] == "shared_object_not_writable"
    assert rows[0]["object_id"] == world.criteria_versions["global"]


def test_criteria_write_needs_a_step_up_and_stays_inside_the_practice(
    probe_client, world, totp_clock
) -> None:  # noqa: ANN001
    account = _sign_in(probe_client, world, "a", "admin", totp_clock)

    refused = probe_client.post(f"{CRITERIA_WRITE}/{world.criteria_versions['a']}/write")
    assert refused.status_code == 403
    assert refused.json()["detail"]["code"] == "reauth_required"

    step_up(probe_client, account, totp_clock)
    assert probe_client.post(f"{CRITERIA_WRITE}/{world.criteria_versions['a']}/write").status_code == 200
    foreign = probe_client.post(f"{CRITERIA_WRITE}/{world.criteria_versions['b']}/write")
    assert foreign.status_code == 404

    reasons = [row["detail"]["reason"] for row in audit_rows(world_engine(), actor_user_id=account.user_id)]
    assert reasons == ["step_up_required", "cross_practice_denied"]


# ---------------------------------------------------------------------------
# User objects
# ---------------------------------------------------------------------------
def test_an_admin_cannot_read_a_user_of_another_practice(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    account = _sign_in(probe_client, world, "a", "admin", totp_clock, stepped_up=True)
    own_user = world.account("a", "coordinator").user_id
    foreign_user = world.account("b", "coordinator").user_id

    assert probe_client.get(f"{USER_READ}/{own_user}").status_code == 200
    foreign = probe_client.get(f"{USER_READ}/{foreign_user}")
    assert foreign.status_code == 404
    rows = audit_rows(world_engine(), actor_user_id=account.user_id)
    assert len(rows) == 1
    assert rows[0]["object_type"] == "app_user"
    assert rows[0]["object_id"] == foreign_user
    assert rows[0]["detail"]["reason"] == "cross_practice_denied"


def test_a_coordinator_cannot_reach_the_user_object_at_all(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    """The role gate runs before the object is loaded, so the answer is 403 for every id."""
    account = _sign_in(probe_client, world, "a", "coordinator", totp_clock)
    own_user = world.account("a", "physician").user_id
    response = probe_client.get(f"{USER_READ}/{own_user}")
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "permission_denied"
    rows = audit_rows(world_engine(), actor_user_id=account.user_id)
    assert rows[0]["detail"]["reason"] == "role_not_permitted"


# ---------------------------------------------------------------------------
# The own_actions scope (§7.3 "view audit log — physician: own actions")
# ---------------------------------------------------------------------------
def test_the_audit_scope_filter_limits_the_physician_to_their_own_rows(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    physician = _sign_in(probe_client, world, "a", "physician", totp_clock)
    coordinator = world.account("a", "coordinator")

    # One denial each, in the same practice.
    assert probe_client.get(f"{PROBE_PREFIX}/case.write").status_code == 403  # physician, denied
    probe_client.cookies.clear()
    sign_in(probe_client, coordinator, totp_clock)
    assert probe_client.get(f"{PROBE_PREFIX}/criteria.write").status_code == 403  # coordinator, denied

    engine = world_engine()
    with engine.connect() as conn:
        own = conn.execute(
            select(AuditLog.actor_user_id).where(
                audit_scope_filter(
                    scope=Scope.OWN_ACTIONS,
                    actor_user_id=physician.user_id,
                    practice_id=world.practices["a"],
                )
            )
        ).scalars().all()
        practice = conn.execute(
            select(AuditLog.actor_user_id).where(
                audit_scope_filter(
                    scope=Scope.PRACTICE,
                    actor_user_id=physician.user_id,
                    practice_id=world.practices["a"],
                )
            )
        ).scalars().all()

    assert own, "the physician's own denials should be visible to them"
    assert set(own) == {physician.user_id}
    assert {physician.user_id, coordinator.user_id} <= set(practice)


# ---------------------------------------------------------------------------
# The chain survives every refusal in this file
# ---------------------------------------------------------------------------
def test_cross_practice_denials_keep_the_chain_intact(probe_client, world, totp_clock) -> None:  # noqa: ANN001
    _sign_in(probe_client, world, "a", "coordinator", totp_clock)
    for case_id in (world.cases["b"], uuid.uuid4(), world.cases["a"]):
        probe_client.get(f"{CASE_READ}/{case_id}")
    checked, last_id = chain_verifies(world_engine())
    assert checked > 0 and last_id > 0


def world_engine():  # noqa: ANN201
    from cardioauth.db import get_engine

    return get_engine()
