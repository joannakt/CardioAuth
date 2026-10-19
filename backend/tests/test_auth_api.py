"""``/api/auth`` end-to-end against the real application and the real test database.

Every test here is a synchronous HTTP flow through FastAPI's TestClient, so it exercises the
routes, the dependencies, the SQL, the audit writes and the cookie handling together. The
negative paths are the point of this file: a security core that only passes the happy path
is not verified.

Synthetic data only: accounts are created per test and deleted afterwards; the passwords and
code values are obviously fake.
"""

from __future__ import annotations

import time
import uuid

import pyotp
import pytest
from sqlalchemy import text

from cardioauth.auth import service
from cardioauth.auth.router import router as auth_router
from cardioauth.settings import get_settings

pytestmark = pytest.mark.db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def login(client, users, role: str, password: str | None = None):  # noqa: ANN001, ANN201
    return client.post(
        "/api/auth/login",
        json={"email": users.email(role), "password": password if password is not None else users.password(role)},
    )


def totp_code(secret: str, *, offset: int = 0) -> str:
    settings = get_settings()
    step = settings.totp_period_seconds
    moment = int(time.time() // step + offset) * step
    return pyotp.TOTP(secret, digits=settings.totp_digits, interval=step).at(moment)


def fresh_totp_code(secret: str) -> str:
    """A valid code in the *next* step.

    Activation consumes the current step's code, so every later verification in a test must use
    a different step — otherwise the single-use ledger would (correctly) call it a replay.
    """
    return totp_code(secret, offset=1)


def enrol_and_activate(client, secret_holder: dict[str, str] | None = None) -> list[str]:  # noqa: ANN001
    """POST /totp/enrol then activate with a real code. Returns the recovery codes."""
    enrolment = client.post("/api/auth/totp/enrol")
    assert enrolment.status_code == 200, enrolment.text
    secret = str(enrolment.json()["otpauth"]["secret"])
    if secret_holder is not None:
        secret_holder["secret"] = secret
    activate = client.post("/api/auth/totp/activate", json={"code": totp_code(secret)})
    assert activate.status_code == 200, activate.text
    return list(activate.json()["recovery_codes"])


def session_id_of(client, users, role: str) -> uuid.UUID:  # noqa: ANN001
    listing = client.get("/api/auth/sessions")
    assert listing.status_code == 200, listing.text
    me = users.ids[role]
    assert me is not None
    return uuid.UUID(listing.json()["sessions"][0]["id"])


def physical_session_id(engine, cookie_value: str) -> uuid.UUID:  # noqa: ANN001, ANN201
    from cardioauth.security import tokens

    with engine.connect() as conn:
        return conn.execute(
            text("SELECT id FROM cardioauth.user_session WHERE token_hash = :h"),
            {"h": tokens.hash_session_token(cookie_value)},
        ).scalar_one()


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------
def test_router_is_mounted_under_api_auth() -> None:
    paths = {route.path for route in auth_router.routes}
    assert {"/api/auth/login", "/api/auth/logout", "/api/auth/sessions", "/api/auth/step-up"} <= paths


def test_coordinator_without_a_factor_can_sign_in_and_use_the_session(client, auth_users) -> None:  # noqa: ANN001
    response = login(client, auth_users, "coordinator")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "authenticated"
    assert body["totp_enrolled"] is False and body["totp_enrolment_required"] is False

    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie.replace("samesite", "SameSite")
    assert "Path=/" in cookie
    assert "Secure" not in cookie, "Secure is added by the production guard, not in the test tier"

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["status"] == "authenticated"
    assert me.json()["reauth_required"] is True, "a login is not a step-up"


def test_physician_must_enrol_a_factor_and_is_then_fully_authenticated(client, auth_users) -> None:  # noqa: ANN001
    response = login(client, auth_users, "physician")
    assert response.status_code == 200
    assert response.json()["status"] == "totp_enrolment_required"
    assert response.json()["totp_enrolment_required"] is True

    # Protected routes refuse the pending session.
    assert client.get("/api/auth/sessions").status_code == 403
    assert client.get("/api/auth/sessions").json()["detail"]["code"] == "second_factor_required"

    enrol_and_activate(client)
    assert client.get("/api/auth/sessions").status_code == 200
    assert client.get("/api/auth/me").json()["two_factor_verified"] is True


def test_login_with_enrolled_factor_requires_and_accepts_a_code(client, auth_users) -> None:  # noqa: ANN001
    secret_holder: dict[str, str] = {}
    login(client, auth_users, "physician")
    enrol_and_activate(client, secret_holder)
    client.post("/api/auth/logout")

    second = login(client, auth_users, "physician")
    assert second.json()["status"] == "totp_required"
    assert client.get("/api/auth/sessions").status_code == 403, "pending 2FA must not reach protected routes"

    verified = client.post("/api/auth/2fa/verify", json={"code": fresh_totp_code(secret_holder["secret"])})
    assert verified.status_code == 200, verified.text
    assert verified.json()["status"] == "authenticated"
    assert client.get("/api/auth/sessions").status_code == 200


def test_second_factor_verify_is_refused_when_already_complete(client, auth_users) -> None:  # noqa: ANN001
    login(client, auth_users, "coordinator")
    response = client.post("/api/auth/2fa/verify", json={"code": "123456"})
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "second_factor_not_required"


def test_second_factor_verify_is_refused_when_nothing_is_enrolled(client, auth_users) -> None:  # noqa: ANN001
    login(client, auth_users, "physician")  # pending: enrolment required
    response = client.post("/api/auth/2fa/verify", json={"code": "123456"})
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "totp_not_enrolled"


# ---------------------------------------------------------------------------
# Negative paths: password and lockout
# ---------------------------------------------------------------------------
def test_wrong_password_is_refused_and_counted(client, auth_users, engine) -> None:  # noqa: ANN001
    response = login(client, auth_users, "coordinator", password="not-the-password-at-all")
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_credentials"

    with engine.connect() as conn:
        count = conn.execute(
            text("SELECT failed_login_count FROM cardioauth.app_user WHERE id = :id"),
            {"id": auth_users.ids["coordinator"]},
        ).scalar_one()
    assert count == 1

    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT detail FROM cardioauth_audit.audit_log WHERE action = 'auth.login_failed' "
                "AND object_id = :id ORDER BY id DESC LIMIT 1"
            ),
            {"id": auth_users.ids["coordinator"]},
        ).scalar_one()
    assert row["reason"] == "bad_password"


def test_unknown_account_and_wrong_password_are_indistinguishable(client, auth_users) -> None:  # noqa: ANN001
    unknown = client.post(
        "/api/auth/login", json={"email": f"nobody-{uuid.uuid4().hex[:8]}@test-only.invalid", "password": "x" * 20}
    )
    wrong = login(client, auth_users, "coordinator", password="wrong-password-value")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["detail"]["code"] == wrong.json()["detail"]["code"] == "invalid_credentials"


def test_malformed_email_does_not_reveal_whether_an_account_exists(client) -> None:  # noqa: ANN001
    response = client.post("/api/auth/login", json={"email": "not-an-email", "password": "x" * 20})
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_credentials"


def test_lockout_after_five_failures_and_recovery_after_the_lock_expires(client, auth_users, engine) -> None:  # noqa: ANN001
    for attempt in range(1, 5):
        assert login(client, auth_users, "coordinator", password="wrong-password-value").status_code == 401, attempt

    fifth = login(client, auth_users, "coordinator", password="wrong-password-value")
    assert fifth.status_code == 423
    assert fifth.json()["detail"]["code"] == "account_locked"
    assert fifth.json()["detail"]["retry_after_minutes"] == 15
    assert "Retry-After" in fifth.headers

    # The correct password does not get in while the lock stands.
    assert login(client, auth_users, "coordinator").status_code == 423

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT locked_until, lockout_stage, failed_login_count FROM cardioauth.app_user WHERE id = :id"),
            {"id": auth_users.ids["coordinator"]},
        ).one()
    assert row.lockout_stage == 1
    assert row.failed_login_count == 0

    # Simulate the lock elapsing, then the very next success clears the counters.
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE cardioauth.app_user SET locked_until = now() - interval '1 minute' WHERE id = :id"),
            {"id": auth_users.ids["coordinator"]},
        )
    recovered = login(client, auth_users, "coordinator")
    assert recovered.status_code == 200, recovered.text

    with engine.connect() as conn:
        state = conn.execute(
            text("SELECT failed_login_count, lockout_stage, locked_until FROM cardioauth.app_user WHERE id = :id"),
            {"id": auth_users.ids["coordinator"]},
        ).one()
    assert state.failed_login_count == 0
    assert state.lockout_stage == 0
    assert state.locked_until is None


def test_second_lockout_is_twice_as_long(client, auth_users, engine) -> None:  # noqa: ANN001
    for _ in range(4):
        login(client, auth_users, "coordinator", password="wrong-password-value")
    assert login(client, auth_users, "coordinator", password="wrong-password-value").status_code == 423
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE cardioauth.app_user SET locked_until = now() - interval '1 minute' WHERE id = :id"),
            {"id": auth_users.ids["coordinator"]},
        )

    for _ in range(4):
        login(client, auth_users, "coordinator", password="wrong-password-value")
    second = login(client, auth_users, "coordinator", password="wrong-password-value")
    assert second.status_code == 423
    assert second.json()["detail"]["retry_after_minutes"] == 30

    with engine.connect() as conn:
        stage = conn.execute(
            text("SELECT lockout_stage FROM cardioauth.app_user WHERE id = :id"),
            {"id": auth_users.ids["coordinator"]},
        ).scalar_one()
    assert stage == 2


def test_inactive_account_is_refused(client, auth_users, engine) -> None:  # noqa: ANN001
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE cardioauth.app_user SET is_active = false WHERE id = :id"),
            {"id": auth_users.ids["coordinator"]},
        )
    response = login(client, auth_users, "coordinator")
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "account_inactive"


# ---------------------------------------------------------------------------
# Negative paths: second factor
# ---------------------------------------------------------------------------
def test_wrong_totp_code_is_refused(client, auth_users) -> None:  # noqa: ANN001
    secret_holder: dict[str, str] = {}
    login(client, auth_users, "physician")
    enrol_and_activate(client, secret_holder)
    client.post("/api/auth/logout")
    login(client, auth_users, "physician")

    wrong = "000000" if totp_code(secret_holder["secret"]) != "000000" else "111111"
    response = client.post("/api/auth/2fa/verify", json={"code": wrong})
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_code"
    assert client.get("/api/auth/sessions").status_code == 403, "a failed factor must not complete the session"


def test_replayed_totp_code_is_refused(client, auth_users, engine) -> None:  # noqa: ANN001
    secret_holder: dict[str, str] = {}
    login(client, auth_users, "physician")
    enrol_and_activate(client, secret_holder)
    client.post("/api/auth/logout")

    login(client, auth_users, "physician")
    code = fresh_totp_code(secret_holder["secret"])
    assert client.post("/api/auth/2fa/verify", json={"code": code}).status_code == 200

    # A fresh pending session, same code: the single-use ledger refuses it.
    client.post("/api/auth/logout")
    login(client, auth_users, "physician")
    replay = client.post("/api/auth/2fa/verify", json={"code": code})
    assert replay.status_code == 401, "a replayed code must fail"
    assert replay.json()["detail"]["code"] == "invalid_code"

    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT count(*) FROM cardioauth.totp_used_code WHERE user_id = :id"),
            {"id": auth_users.ids["physician"]},
        ).scalar_one()
    assert rows == 2, "activation and login each consumed exactly one code record"

    # The audit trail distinguishes a replay from a merely wrong code.
    with engine.connect() as conn:
        reasons = [
            row[0]
            for row in conn.execute(
                text(
                    "SELECT detail ->> 'reason' FROM cardioauth_audit.audit_log "
                    "WHERE action = 'auth.totp_failed' AND object_id = :id ORDER BY id"
                ),
                {"id": auth_users.ids["physician"]},
            )
        ]
    assert reasons == ["replayed_code"]


def test_recovery_code_is_single_use(client, auth_users) -> None:  # noqa: ANN001
    login(client, auth_users, "physician")
    codes = enrol_and_activate(client)
    assert len(codes) == 10
    client.post("/api/auth/logout")

    login(client, auth_users, "physician")
    first = client.post("/api/auth/2fa/verify", json={"code": codes[0].replace("-", " ").lower()})
    assert first.status_code == 200, first.text
    assert first.json()["recovery_codes_remaining"] == 9
    client.post("/api/auth/logout")

    login(client, auth_users, "physician")
    reuse = client.post("/api/auth/2fa/verify", json={"code": codes[0]})
    assert reuse.status_code == 401, "a recovery code must not be reusable"
    assert client.post("/api/auth/2fa/verify", json={"code": codes[1]}).status_code == 200


def test_recovery_codes_are_hashed_at_rest(client, auth_users, engine) -> None:  # noqa: ANN001
    login(client, auth_users, "physician")
    codes = enrol_and_activate(client)
    with engine.connect() as conn:
        stored = conn.execute(
            text(
                "SELECT code_hash, used_at, revoked_at FROM cardioauth.user_recovery_code WHERE user_id = :id"
            ),
            {"id": auth_users.ids["physician"]},
        ).all()
    assert len(stored) == 10
    plaintexts = {code.replace("-", "").encode() for code in codes}
    for row in stored:
        assert len(row.code_hash) == 32
        assert row.code_hash not in plaintexts, "a recovery code must never be stored in the clear"


def test_totp_secret_is_encrypted_at_rest(client, auth_users, engine) -> None:  # noqa: ANN001
    secret_holder: dict[str, str] = {}
    login(client, auth_users, "physician")
    enrol_and_activate(client, secret_holder)
    with engine.connect() as conn:
        blob = conn.execute(
            text("SELECT totp_secret_enc, totp_enrolled_at FROM cardioauth.app_user WHERE id = :id"),
            {"id": auth_users.ids["physician"]},
        ).one()
    assert secret_holder["secret"].encode() not in bytes(blob.totp_secret_enc)
    assert blob.totp_enrolled_at is not None
    from cardioauth.security import crypto

    assert crypto.decrypt_secret(bytes(blob.totp_secret_enc)) == secret_holder["secret"]


def test_enrolment_does_not_activate_until_a_code_proves_possession(client, auth_users, engine) -> None:  # noqa: ANN001
    login(client, auth_users, "physician")
    enrolment = client.post("/api/auth/totp/enrol")
    assert enrolment.status_code == 200
    secret = enrolment.json()["otpauth"]["secret"]

    with engine.connect() as conn:
        state = conn.execute(
            text("SELECT totp_secret_enc, totp_enrolled_at FROM cardioauth.app_user WHERE id = :id"),
            {"id": auth_users.ids["physician"]},
        ).one()
    assert state.totp_secret_enc is not None
    assert state.totp_enrolled_at is None, "an interrupted enrolment must not count as enrolled"
    assert client.get("/api/auth/sessions").status_code == 403

    assert client.post("/api/auth/totp/activate", json={"code": "000000"}).status_code == 401
    assert client.post("/api/auth/totp/activate", json={"code": totp_code(secret)}).status_code == 200


def test_activate_without_enrolment_is_refused(client, auth_users) -> None:  # noqa: ANN001
    login(client, auth_users, "physician")
    response = client.post("/api/auth/totp/activate", json={"code": "123456"})
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "no_enrolment_in_progress"


def test_disable_requires_a_fresh_password_and_then_removes_the_factor(client, auth_users, engine) -> None:  # noqa: ANN001
    secret_holder: dict[str, str] = {}
    login(client, auth_users, "physician")
    enrol_and_activate(client, secret_holder)

    wrong = client.post("/api/auth/totp/disable", json={"password": "not-the-password", "code": "000000"})
    assert wrong.status_code == 401
    assert wrong.json()["detail"]["code"] == "bad_password"

    without_code = client.post("/api/auth/totp/disable", json={"password": auth_users.password("physician")})
    assert without_code.status_code == 401
    assert without_code.json()["detail"]["code"] == "second_factor_required"

    ok = client.post(
        "/api/auth/totp/disable",
        json={"password": auth_users.password("physician"), "code": fresh_totp_code(secret_holder["secret"])},
    )
    assert ok.status_code == 200, ok.text
    with engine.connect() as conn:
        state = conn.execute(
            text("SELECT totp_secret_enc, totp_enrolled_at FROM cardioauth.app_user WHERE id = :id"),
            {"id": auth_users.ids["physician"]},
        ).one()
    assert state.totp_secret_enc is None and state.totp_enrolled_at is None


def test_recovery_codes_can_be_rotated_and_old_ones_stop_working(client, auth_users) -> None:  # noqa: ANN001
    secret_holder: dict[str, str] = {}
    login(client, auth_users, "coordinator")
    first_codes = enrol_and_activate(client, secret_holder)
    assert first_codes

    rotated = client.post(
        "/api/auth/totp/recovery-codes",
        json={"password": auth_users.password("coordinator"), "code": fresh_totp_code(secret_holder["secret"])},
    )
    assert rotated.status_code == 200, rotated.text
    new_codes = rotated.json()["recovery_codes"]
    assert set(new_codes).isdisjoint(first_codes)

    client.post("/api/auth/logout")
    login(client, auth_users, "coordinator")
    assert client.post("/api/auth/2fa/verify", json={"code": first_codes[0]}).status_code == 401
    assert client.post("/api/auth/2fa/verify", json={"code": new_codes[0]}).status_code == 200


# ---------------------------------------------------------------------------
# Negative paths: sessions
# ---------------------------------------------------------------------------
def test_session_token_is_not_usable_after_rotation(client, auth_users, engine) -> None:  # noqa: ANN001
    from fastapi.testclient import TestClient

    secret_holder: dict[str, str] = {}
    login(client, auth_users, "physician")
    enrol_and_activate(client, secret_holder)
    client.post("/api/auth/logout")

    login(client, auth_users, "physician")
    pending_cookie = client.cookies.get(get_settings().session_cookie_name)
    assert pending_cookie
    with TestClient(client.app) as fresh:
        fresh.cookies.set(get_settings().session_cookie_name, pending_cookie)
        assert fresh.get("/api/auth/sessions").status_code == 403, "pending session before the factor"

    assert client.post("/api/auth/2fa/verify", json={"code": fresh_totp_code(secret_holder["secret"])}).status_code == 200
    new_cookie = client.cookies.get(get_settings().session_cookie_name)
    assert new_cookie and new_cookie != pending_cookie

    with engine.connect() as conn:
        old = conn.execute(
            text("SELECT revoked_at FROM cardioauth.user_session WHERE id = :id"),
            {"id": physical_session_id(engine, pending_cookie)},
        ).scalar_one()
    assert old is not None, "the pre-rotation token must be revoked server-side"

    with TestClient(client.app) as stolen:
        stolen.cookies.set(get_settings().session_cookie_name, pending_cookie)
        assert stolen.get("/api/auth/sessions").status_code == 401


def test_logout_revokes_server_side_and_the_token_cannot_be_reused(client, auth_users, engine) -> None:  # noqa: ANN001
    from fastapi.testclient import TestClient

    login(client, auth_users, "coordinator")
    cookie = client.cookies.get(get_settings().session_cookie_name)
    assert cookie
    assert client.post("/api/auth/logout").status_code == 200

    with engine.connect() as conn:
        revoked = conn.execute(
            text("SELECT revoked_at FROM cardioauth.user_session WHERE id = :id"),
            {"id": physical_session_id(engine, cookie)},
        ).scalar_one()
    assert revoked is not None

    with TestClient(client.app) as reuse:
        reuse.cookies.set(get_settings().session_cookie_name, cookie)
        response = reuse.get("/api/auth/me")
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "revoked"


def test_idle_timeout_expires_a_session_server_side(client, auth_users, engine) -> None:  # noqa: ANN001
    login(client, auth_users, "coordinator")
    session_id = session_id_of(client, auth_users, "coordinator")
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE cardioauth.user_session SET idle_expires_at = now() - interval '1 minute', "
                "last_seen_at = now() - interval '20 minutes' WHERE id = :id"
            ),
            {"id": session_id},
        )
    response = client.get("/api/auth/sessions")
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "expired_idle"
    with engine.connect() as conn:
        assert conn.execute(
            text("SELECT revoked_at FROM cardioauth.user_session WHERE id = :id"), {"id": session_id}
        ).scalar_one() is not None


def test_absolute_timeout_expires_a_session_even_when_active(client, auth_users, engine) -> None:  # noqa: ANN001
    login(client, auth_users, "coordinator")
    session_id = session_id_of(client, auth_users, "coordinator")
    # Move the whole session nine hours into the past: the absolute deadline has passed while
    # the idle window would still be open (the database refuses the reverse ordering).
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE cardioauth.user_session SET issued_at = now() - interval '9 hours', "
                "last_seen_at = now() - interval '9 hours', "
                "idle_expires_at = now() - interval '8 hours 45 minutes', "
                "absolute_expires_at = now() - interval '1 hour' WHERE id = :id"
            ),
            {"id": session_id},
        )
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "expired_absolute"


def test_idle_timeout_slides_with_activity(client, auth_users, engine) -> None:  # noqa: ANN001
    login(client, auth_users, "coordinator")
    session_id = session_id_of(client, auth_users, "coordinator")
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE cardioauth.user_session SET idle_expires_at = now() + interval '10 seconds' WHERE id = :id"),
            {"id": session_id},
        )
    assert client.get("/api/auth/me").status_code == 200
    with engine.connect() as conn:
        remaining = conn.execute(
            text("SELECT extract(epoch FROM (idle_expires_at - now())) FROM cardioauth.user_session WHERE id = :id"),
            {"id": session_id},
        ).scalar_one()
    assert remaining > 60, "an authenticated request must slide the idle window"


def test_sessions_can_be_listed_and_revoked_one_by_one(client, auth_users) -> None:  # noqa: ANN001
    from fastapi.testclient import TestClient

    login(client, auth_users, "coordinator")
    first_cookie = client.cookies.get(get_settings().session_cookie_name)
    with TestClient(client.app) as other:
        other.post("/api/auth/login", json={"email": auth_users.email("coordinator"),
                                            "password": auth_users.password("coordinator")})
        other_cookie = other.cookies.get(get_settings().session_cookie_name)

    listing = client.get("/api/auth/sessions").json()
    assert listing["count"] == 2
    assert sum(1 for s in listing["sessions"] if s["current"]) == 1
    other_id = next(s["id"] for s in listing["sessions"] if not s["current"])
    assert listing["sessions"][0]["request_fingerprint"], "a fingerprint helps identify a session"

    assert client.post(f"/api/auth/sessions/{other_id}/revoke").status_code == 200
    assert client.get("/api/auth/sessions").json()["count"] == 1

    # The revoked session is dead, the caller's own session still works.
    with TestClient(client.app) as victim:
        victim.cookies.set(get_settings().session_cookie_name, other_cookie)
        assert victim.get("/api/auth/me").status_code == 401
    assert client.get("/api/auth/me").status_code == 200

    again = client.post(f"/api/auth/sessions/{other_id}/revoke")
    assert again.status_code == 409
    assert again.json()["detail"]["code"] == "session_already_revoked"


def test_revoking_a_foreign_or_unknown_session_is_a_404(client, auth_users) -> None:  # noqa: ANN001
    login(client, auth_users, "coordinator")
    response = client.post(f"/api/auth/sessions/{uuid.uuid4()}/revoke")
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "session_not_found"


def test_revoke_all_keeps_the_caller_by_default_and_can_include_it(client, auth_users) -> None:  # noqa: ANN001
    from fastapi.testclient import TestClient

    login(client, auth_users, "coordinator")
    with TestClient(client.app) as other:
        other.post("/api/auth/login", json={"email": auth_users.email("coordinator"),
                                            "password": auth_users.password("coordinator")})
    assert client.get("/api/auth/sessions").json()["count"] == 2

    response = client.post("/api/auth/sessions/revoke-all", json={})
    assert response.status_code == 200
    assert response.json() == {"sessions_revoked": 1, "kept_current": True}
    assert client.get("/api/auth/me").status_code == 200

    with TestClient(client.app) as other:
        other.post("/api/auth/login", json={"email": auth_users.email("coordinator"),
                                            "password": auth_users.password("coordinator")})
    everything = client.post("/api/auth/sessions/revoke-all", json={"include_current": True})
    assert everything.json()["sessions_revoked"] == 2
    assert client.get("/api/auth/me").status_code == 401


def test_unauthenticated_requests_are_401(client) -> None:  # noqa: ANN001
    for path in ("/api/auth/me", "/api/auth/sessions"):
        response = client.get(path)
        assert response.status_code == 401
        assert response.json()["detail"]["code"] == "not_authenticated"
    assert client.post("/api/auth/logout").status_code == 401
    assert client.post(f"/api/auth/sessions/{uuid.uuid4()}/revoke").status_code == 401


def test_garbage_cookie_is_401(client) -> None:  # noqa: ANN001
    client.cookies.set(get_settings().session_cookie_name, "not-a-real-session-token")
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "unknown_token"


# ---------------------------------------------------------------------------
# Step-up
# ---------------------------------------------------------------------------
def test_step_up_requires_both_factors_and_records_the_window(client, auth_users, engine) -> None:  # noqa: ANN001
    secret_holder: dict[str, str] = {}
    login(client, auth_users, "physician")
    enrol_and_activate(client, secret_holder)
    cookie_before = client.cookies.get(get_settings().session_cookie_name)

    bad = client.post("/api/auth/step-up", json={"password": "wrong-password-value"})
    assert bad.status_code == 401
    assert bad.json()["detail"]["code"] == "bad_password"

    no_code = client.post("/api/auth/step-up", json={"password": auth_users.password("physician")})
    assert no_code.status_code == 401
    assert no_code.json()["detail"]["code"] == "second_factor_required"

    ok = client.post(
        "/api/auth/step-up",
        json={"password": auth_users.password("physician"), "code": fresh_totp_code(secret_holder["secret"])},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["reauth_required"] is False

    # Step-up rotates the session: the pre-step-up token is dead.
    assert client.cookies.get(get_settings().session_cookie_name) != cookie_before
    with engine.connect() as conn:
        assert conn.execute(
            text("SELECT revoked_at FROM cardioauth.user_session WHERE id = :id"),
            {"id": physical_session_id(engine, cookie_before)},
        ).scalar_one() is not None

    me = client.get("/api/auth/me").json()
    assert me["reauth_at"] is not None


def test_recent_reauth_helper_enforces_the_window(client, auth_users, engine) -> None:  # noqa: ANN001
    """The dependency protected routes use: refuses, audits the denial, then allows."""
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from cardioauth.auth.deps import AuthContext, require_recent_reauth

    gate = FastAPI()

    @gate.get("/sensitive")
    def sensitive(auth: AuthContext = Depends(require_recent_reauth(action="letter.exported"))) -> dict[str, str]:
        return {"ok": str(auth.user_id)}

    login(client, auth_users, "coordinator")
    cookie = client.cookies.get(get_settings().session_cookie_name)

    with TestClient(gate) as guarded:
        guarded.cookies.set(get_settings().session_cookie_name, cookie)
        refused = guarded.get("/sensitive")
        assert refused.status_code == 403
        assert refused.json()["detail"]["code"] == "reauth_required"

        assert client.post(
            "/api/auth/step-up", json={"password": auth_users.password("coordinator")}
        ).status_code == 200
        guarded.cookies.set(
            get_settings().session_cookie_name, client.cookies.get(get_settings().session_cookie_name)
        )
        allowed = guarded.get("/sensitive")
        assert allowed.status_code == 200
        assert allowed.json()["ok"] == str(auth_users.ids["coordinator"])

    # The refusal is audited as a denial, with the action that was attempted.
    with engine.connect() as conn:
        detail = conn.execute(
            text(
                "SELECT detail FROM cardioauth_audit.audit_log WHERE action = 'auth.step_up_failed' "
                "AND detail ->> 'action' = 'letter.exported' ORDER BY id DESC LIMIT 1"
            )
        ).scalar_one()
    assert detail["reason"] == "reauth_required"


def test_reauth_window_can_be_tested_with_a_short_window(client, auth_users, engine) -> None:  # noqa: ANN001
    """A step-up older than the window is no longer valid (5 minutes by default)."""
    login(client, auth_users, "coordinator")
    assert client.post("/api/auth/step-up", json={"password": auth_users.password("coordinator")}).status_code == 200
    session_id = session_id_of(client, auth_users, "coordinator")
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE cardioauth.user_session SET reauth_at = now() - interval '10 minutes' WHERE id = :id"),
            {"id": session_id},
        )
    me = client.get("/api/auth/me").json()
    assert me["reauth_required"] is True


def test_is_recent_reauth_boundary(client, auth_users, engine) -> None:  # noqa: ANN001
    """The 5-minute window is a boundary, not a vibe: 4 minutes yes, 6 minutes no."""
    from datetime import timedelta

    from sqlalchemy.orm import Session as OrmSession

    from cardioauth.db.models import UserSession

    settings = get_settings()
    login(client, auth_users, "coordinator")
    session_id = session_id_of(client, auth_users, "coordinator")
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE cardioauth.user_session SET reauth_at = now() - interval '4 minutes' WHERE id = :id"),
            {"id": session_id},
        )
    with OrmSession(engine) as orm:
        obj = orm.get(UserSession, session_id)
        assert obj is not None
        assert service.is_recent_reauth(obj, settings=settings) is True
        obj.reauth_at = service.utcnow() - timedelta(minutes=6)
        assert service.is_recent_reauth(obj, settings=settings) is False
        obj.reauth_at = None
        assert service.is_recent_reauth(obj, settings=settings) is False


def test_factor_policy_helper(client, auth_users, engine) -> None:  # noqa: ANN001
    """Which sessions may reach protected routes, per role and enrolment state."""
    from sqlalchemy.orm import Session as OrmSession

    from cardioauth.db.models import AppUser, UserSession

    settings = get_settings()
    login(client, auth_users, "coordinator")
    session_id = session_id_of(client, auth_users, "coordinator")
    with OrmSession(engine) as orm:
        row = orm.get(UserSession, session_id)
        coordinator = orm.get(AppUser, auth_users.ids["coordinator"])
        physician = orm.get(AppUser, auth_users.ids["physician"])
        assert row is not None and coordinator is not None and physician is not None
        assert service.session_meets_factor_policy(row, coordinator, settings=settings) is True
        assert service.session_meets_factor_policy(row, physician, settings=settings) is False
        row.two_factor_verified_at = service.utcnow()
        assert service.session_meets_factor_policy(row, physician, settings=settings) is True


def test_production_cookie_is_secure_and_same_site_is_configurable() -> None:
    from fastapi import Response

    from cardioauth.auth.router import set_session_cookie
    from cardioauth.settings import Environment, Settings

    production = Settings(
        _env_file=None,
        cardioauth_env=Environment.production,
        app_key="production-shaped-test-key-with-32-bytes",
        session_cookie_secure=True,
    )
    response = Response()
    set_session_cookie(response, "opaque-token-value", production)
    header = response.headers["set-cookie"]
    assert "Secure" in header and "HttpOnly" in header and "SameSite=lax" in header

    strict = Settings(
        _env_file=None, cardioauth_env=Environment.test, app_key="x" * 40, session_cookie_samesite="strict"
    )
    response = Response()
    set_session_cookie(response, "opaque-token-value", strict)
    assert "SameSite=strict" in response.headers["set-cookie"]
