"""Audit wiring for the identity core (task item 6) and the secrets that must never land in
the audit chain or in a log line.

Three properties are asserted here:

1. every authentication event of this milestone reaches the **existing** hash chain through
   ``cardioauth.audit.service.record`` (no second audit table, no direct INSERT);
2. the chain still verifies after auth activity — an auth bug that wrote an unchained row
   would fail this test;
3. no password, TOTP secret, session token, TOTP code or recovery code appears in any audit
   ``detail`` or in any log record captured while the flows run.
"""

from __future__ import annotations

import json
import logging

import pytest
from sqlalchemy import text

from cardioauth.audit.actions import AUTH_ACTIONS
from cardioauth.audit.chain import AuditChainError, canonical_payload, verify_chain
from cardioauth.settings import get_settings

from tests.test_auth_api import enrol_and_activate, fresh_totp_code, login, totp_code

pytestmark = pytest.mark.db


def audit_snapshot(engine) -> int:  # noqa: ANN001
    with engine.connect() as conn:
        return int(conn.execute(text("SELECT coalesce(max(id), 0) FROM cardioauth_audit.audit_log")).scalar_one())


def audited_since(engine, since_id: int) -> list[dict]:  # noqa: ANN001
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT id, action, outcome, detail, actor_role, object_type FROM cardioauth_audit.audit_log "
                "WHERE id > :since ORDER BY id"
            ),
            {"since": since_id},
        ).mappings()
        return [dict(row) for row in rows]


def run_every_auth_event(client, users, engine) -> tuple[dict[str, str], list[str]]:  # noqa: ANN001
    """Drive the whole milestone's surface once and return the secrets used."""
    secrets: dict[str, str] = {}
    login(client, users, "physician")  # auth.login_succeeded + pending factor
    login(client, users, "physician", password="wrong-password-value")  # auth.login_failed
    login(client, users, "coordinator", password="wrong-password-value")
    codes = enrol_and_activate(client, secrets)  # auth.totp_enrolled + recovery_codes_issued
    # Three verifications happen in this flow and each must land on a *different* time step,
    # because the ledger is keyed by step (with a frozen clock the steps are fixed):
    # activation took the current step (A), so the step-up takes A-1 and the login below takes
    # A+1 — both inside the ±1 drift window.
    client.post(
        "/api/auth/step-up",
        json={"password": users.password("physician"), "code": totp_code(secrets["secret"], offset=-1)},
    )
    client.post("/api/auth/logout")  # auth.logout

    login(client, users, "physician")
    client.post("/api/auth/2fa/verify", json={"code": "000000"})  # auth.totp_failed
    client.post(
        "/api/auth/2fa/verify", json={"code": fresh_totp_code(secrets["secret"])}
    )  # auth.totp_succeeded
    client.get("/api/auth/sessions")
    client.post("/api/auth/sessions/revoke-all", json={})  # auth.sessions_revoked_all
    client.post("/api/auth/logout")
    return secrets, codes


def test_auth_events_reach_the_existing_chain_and_it_still_verifies(client, auth_users, engine) -> None:  # noqa: ANN001
    before = audit_snapshot(engine)
    secrets, codes = run_every_auth_event(client, auth_users, engine)
    rows = audited_since(engine, before)
    actions = {row["action"] for row in rows}

    expected = {
        "auth.login_succeeded",
        "auth.login_failed",
        "auth.totp_failed",
        "auth.totp_succeeded",
        "auth.logout",
        "auth.step_up_succeeded",
        "auth.sessions_revoked_all",
        "auth.session_revoked",
        "auth.totp_enrolled",
        "auth.recovery_codes_issued",
    }
    assert expected <= actions, f"missing audit events: {sorted(expected - actions)}"
    assert actions <= AUTH_ACTIONS, f"unregistered audit actions: {sorted(actions - AUTH_ACTIONS)}"

    # Nothing was written outside the vocabulary and every row is chained.
    with engine.connect() as conn:
        checked, last_id = verify_chain(conn)
    assert checked > 0 and last_id >= before
    assert all(row["outcome"] in {"success", "denied", "error"} for row in rows)

    # The failed attempts are denials, and an account lockout is its own event.
    assert any(row["action"] == "auth.login_failed" and row["outcome"] == "denied" for row in rows)
    assert not any(secret in json.dumps(rows, default=str) for secret in (*secrets.values(), *codes))


def test_lockout_is_audited_with_stage_and_duration(client, auth_users, engine) -> None:  # noqa: ANN001
    before = audit_snapshot(engine)
    for _ in range(5):
        login(client, auth_users, "coordinator", password="wrong-password-value")
    rows = [row for row in audited_since(engine, before) if row["action"] == "auth.account_locked"]
    assert len(rows) == 1
    assert rows[0]["detail"]["lockout_stage"] == 1
    assert rows[0]["detail"]["lock_minutes"] == 15
    assert rows[0]["outcome"] == "denied"


def test_session_expiry_is_audited_once_not_per_request(client, auth_users, engine) -> None:  # noqa: ANN001
    from tests.test_auth_api import session_id_of

    before = audit_snapshot(engine)
    login(client, auth_users, "coordinator")
    session_id = session_id_of(client, auth_users, "coordinator")
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE cardioauth.user_session SET idle_expires_at = now() - interval '1 minute' "
                "WHERE id = :id"
            ),
            {"id": session_id},
        )
    for _ in range(3):
        assert client.get("/api/auth/me").status_code == 401
    rows = [row for row in audited_since(engine, before) if row["action"] == "auth.session_expired"]
    assert len(rows) == 1, "an expired session is recorded once; replaying the cookie is not an event"
    assert rows[0]["detail"]["reason"] == "expired_idle"


def test_no_secret_shaped_value_lands_in_the_audit_detail_or_in_logs(
    client, auth_users, engine, caplog
) -> None:  # noqa: ANN001
    """The screen has to accept every auth event's detail *and* no secret may appear in it."""
    settings = get_settings()
    before = audit_snapshot(engine)
    with caplog.at_level(logging.DEBUG):
        login(client, auth_users, "physician")
        first_cookie = client.cookies.get(settings.session_cookie_name)
        secrets, codes = run_every_auth_event(client, auth_users, engine)
        login(client, auth_users, "physician")
        session_cookie = client.cookies.get(settings.session_cookie_name)

    forbidden = {
        "password": auth_users.password("physician"),
        "coordinator password": auth_users.password("coordinator"),
        "totp secret": secrets["secret"],
        "session token": session_cookie or "",
        "earlier session token": first_cookie or "",
        "recovery code": codes[0],
        "recovery code (normalised)": codes[0].replace("-", ""),
    }
    assert all(value for value in forbidden.values())

    detail_blob = json.dumps([row["detail"] for row in audited_since(engine, before)], default=str)
    for label, value in forbidden.items():
        assert value not in detail_blob, f"{label} leaked into an audit detail"

    log_blob = "\n".join(f"{record.name} {record.getMessage()} {record.__dict__}" for record in caplog.records)
    for label, value in forbidden.items():
        assert value not in log_blob, f"{label} leaked into a log record"


def test_audit_screen_refuses_phi_shaped_keys_before_the_write() -> None:
    """Negative control for the screen the task relies on: it must still refuse these keys."""
    for key in ("email", "patient_name", "quote_text", "mrn", "username"):
        with pytest.raises(AuditChainError):
            canonical_payload(
                occurred_at="2026-01-01T00:00:00+00:00",
                practice_id=None,
                actor_user_id=None,
                actor_role=None,
                action="auth.login_failed",
                object_type="app_user",
                object_id=None,
                case_id=None,
                outcome="denied",
                detail={key: "TEST-ONLY value"},
                request_id=None,
                session_id=None,
            )


def test_audit_service_refuses_an_action_outside_the_vocabulary(client, auth_users, engine) -> None:  # noqa: ANN001
    """The vocabulary is closed: an inline action name is a bug, not a shortcut."""
    from sqlalchemy.orm import Session as OrmSession

    from cardioauth.audit.chain import AuditEntry
    from cardioauth.audit.service import record as audit_record

    with OrmSession(engine) as orm:
        with pytest.raises(AuditChainError):
            audit_record(
                orm,
                AuditEntry(action="auth.something_not_declared", object_type="app_user"),
            )


def test_audit_rows_cannot_be_updated_or_deleted(engine) -> None:  # noqa: ANN001
    """Append-only is a database property, not a convention — re-asserted after M1b-1."""
    with engine.connect() as conn:
        newest = int(conn.exec_driver_sql("SELECT max(id) FROM cardioauth_audit.audit_log").scalar_one())
    assert newest >= 1, "the auth flows above must have written audit rows"
    with engine.connect() as conn:
        with pytest.raises(Exception) as update_error:
            conn.exec_driver_sql(
                f"UPDATE cardioauth_audit.audit_log SET outcome = 'success' WHERE id = {newest}"
            )
    assert "audit_log_append_only" in str(update_error.value)
    with engine.connect() as conn:
        with pytest.raises(Exception) as delete_error:
            conn.exec_driver_sql(f"DELETE FROM cardioauth_audit.audit_log WHERE id = {newest}")
    assert "audit_log_append_only" in str(delete_error.value)
