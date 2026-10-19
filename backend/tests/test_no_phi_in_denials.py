"""PHI-in-denial sentinel test — the test M1b-2 left unwritten (DESIGN.md §7.5).

§7.5: *"A test suite (...) drives the full pipeline over synthetic documents containing sentinel
strings (``SENTINEL-PHI-<n>``) and asserts the sentinel appears in **no** log record, no audit
``detail``, and no exception payload."* M1b-2 wired the authorisation denials into the audit
chain without it. This module is that test, aimed at the refusal paths M1b-2 added, with a
permitted request as the control:

=========================  ==========================================================
request                    expected result
=========================  ==========================================================
permitted probe            ``200`` — positive control: the sentinel really reaches the app
role denial                ``403`` ``permission_denied`` (reason ``role_not_permitted``)
undeclared route           ``403`` ``permission_not_declared``
cross-practice object      ``404`` ``not_found`` (practice A asks for practice B's case)
=========================  ==========================================================

Distinct sentinels travel in six places — a path segment, a query parameter, a JSON body field,
a caller-controlled header, the ``X-Request-ID`` header and the ``User-Agent`` header — and
every one of them must appear in no audit row and no captured log record. Why each is in the
list:

* **path segment** — a URL a caller composes can carry anything, and the route it lands on is a
  *matched* route. (This is the location the test found a real leak in: the HTTP middleware used
  to log ``request.url.path``. It now logs the matched route template — §7.5 "log only method,
  path template, status and duration".)
* **query parameter** — §7.5 requires query strings never to be logged; a search term is the
  classic PHI-in-a-URL case.
* **body field** — request bodies are never logged, and the denial ``detail`` must not copy a
  value the caller supplied.
* **caller-controlled header** — an inert header the application never reads; if this one ever
  showed up, the test would be measuring the harness rather than the application.
* **``X-Request-ID``** — the application *does* read this and puts a correlation id on every
  audit row, so the id must be the server's own, never the caller's text
  (:mod:`cardioauth.security.identifiers`). The caller still gets it back in the response.
* **``User-Agent``** — read and stored, but only as a keyed digest
  (``user_session.user_agent_hash``), never as the raw string.

Nothing here is clinical: every sentinel is an obviously fake marker string, and no request
carries any test data beyond the sentinels themselves.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from sqlalchemy import text

from tests.authz_probe import PHI_SENTINEL_HEADER
from tests.authz_support import World, chain_verifies, sign_in, step_up
from tests.logging_capture import capture_application_logs

pytestmark = pytest.mark.db

#: Distinct per location, named as §7.5 names them.
SENTINELS: dict[str, str] = {
    "path": "SENTINEL-PHI-PATH-001",
    "query": "SENTINEL-PHI-QUERY-002",
    "body": "SENTINEL-PHI-BODY-003",
    "header": "SENTINEL-PHI-HEADER-004",
    # Free text in a header whose value the application is expected to treat as an identifier,
    # exactly as a careless caller (or a browser extension) would send it.
    "request_id": "SENTINEL-PHI-REQID-005 patient Jane Q Test",
    "user_agent": "SENTINEL-PHI-UAGENT-006 (Jane Q Test, MRN 12345)",
}

CALLER_REQUEST_ID = SENTINELS["request_id"]

#: Loggers that belong to the test client's HTTP transport (httpx), not to the application.
CLIENT_TRANSPORT_LOGGERS = frozenset({"httpx", "httpcore", "urllib3"})


def _head(engine) -> int:  # noqa: ANN001
    with engine.connect() as conn:
        return int(conn.execute(text("SELECT coalesce(max(id), 0) FROM cardioauth_audit.audit_log")).scalar_one())


def _rows_since(engine, since_id: int, *, actor_user_id: Any | None = None) -> list[dict[str, Any]]:  # noqa: ANN001
    """Every column of every audit row appended since ``since_id`` (optionally by one actor).

    Broader than the §7.5 wording on purpose: ``detail`` is asserted, and so is every other
    column (``request_id``, ``object_id``, ``session_id``, ...) — a value in the wrong column
    leaks exactly as much as a value in the wrong JSON key.
    """
    sql = "SELECT * FROM cardioauth_audit.audit_log WHERE id > :since"
    params: dict[str, Any] = {"since": since_id}
    if actor_user_id is not None:
        sql += " AND actor_user_id = :actor"
        params["actor"] = actor_user_id
    with engine.connect() as conn:
        rows = conn.execute(text(sql + " ORDER BY id"), params).mappings()
        return [dict(row) for row in rows]


def _log_blob(records: list[logging.LogRecord]) -> str:
    """Everything a captured log record carries: its message, its args and every extra.

    Records from the *test client's own transport* are excluded, and only those: ``httpx`` logs
    the URL it sent, from inside this process, and no application can control its caller's
    logger. In the deployed stack the analogous line is the reverse-proxy/uvicorn access log,
    which §7.5 handles as a deployment setting (access logs omit query strings; the application
    emits its own structured line with the route template). Everything the application itself
    logs — ``cardioauth.*``, ``uvicorn.error``, anything else — is asserted on.
    """
    return "\n".join(
        f"{record.name} {record.levelname} {record.getMessage()} {record.__dict__}"
        for record in records
        if record.name.split(".")[0] not in CLIENT_TRANSPORT_LOGGERS
    )


def _app_records(records: list[logging.LogRecord]) -> list[logging.LogRecord]:
    return [record for record in records if record.name.split(".")[0] not in CLIENT_TRANSPORT_LOGGERS]


def _audit_blob(rows: list[dict[str, Any]]) -> str:
    return "\n".join(json.dumps(row, default=repr, sort_keys=True) for row in rows)


def _requests(client, world: World, *, with_request_id: bool) -> dict[str, Any]:  # noqa: ANN001
    """The four probe requests, each carrying all six sentinels in the same places."""
    headers: dict[str, str] = {
        PHI_SENTINEL_HEADER: SENTINELS["header"],
        "user-agent": SENTINELS["user_agent"],
    }
    if with_request_id:
        headers["x-request-id"] = CALLER_REQUEST_ID
    prefix = f"/api/test/authz/phi/{SENTINELS['path']}"
    params = {"note": SENTINELS["query"]}
    body = {"note": SENTINELS["body"]}
    return {
        "permitted": client.post(f"{prefix}/permitted", params=params, json=body, headers=headers),
        "role_denied": client.post(f"{prefix}/denied", params=params, json=body, headers=headers),
        "undeclared": client.post(f"{prefix}/no-policy", params=params, json=body, headers=headers),
        "cross_practice": client.post(
            f"{prefix}/objects/case/{world.cases['b']}", params=params, json=body, headers=headers
        ),
    }


@pytest.fixture
def coordinator_a(world: World, probe_client, totp_clock):  # noqa: ANN001, ANN201
    """Practice A's coordinator, signed in and stepped up.

    The interesting actor: it *holds* ``case.read`` (so the permitted probe and the
    cross-practice probe reach their real decision) and does *not* hold ``user.manage`` (so the
    role denial is about the role, not about a malformed request or a missing step-up).
    """
    account = world.account("a", "coordinator")
    sign_in(probe_client, account, totp_clock)
    step_up(probe_client, account, totp_clock)
    return account


def test_sentinels_reach_the_application_but_never_a_log_or_the_audit_chain(
    probe_client,  # noqa: ANN001
    world: World,
    engine,  # noqa: ANN001
    coordinator_a,  # noqa: ANN001
) -> None:
    """One run, four requests, six sentinel locations, zero leaks."""
    since = _head(engine)
    with capture_application_logs() as captured:
        responses = _requests(probe_client, world, with_request_id=True)
    allowed, role_denied = responses["permitted"], responses["role_denied"]
    undeclared, cross_practice = responses["undeclared"], responses["cross_practice"]

    # ------------------------------------------------------- positive controls (first)
    # Without these the negative assertions below could pass because no request was ever made,
    # or because the sentinel never travelled anywhere to be leaked.
    assert allowed.status_code == 200, allowed.text
    seen = allowed.json()
    assert seen["path_note"] == SENTINELS["path"], "the path sentinel never reached the handler"
    assert seen["query_note"] == SENTINELS["query"], "the query sentinel never reached the handler"
    assert seen["body_note"] == SENTINELS["body"], "the body sentinel never reached the handler"
    assert seen["header_note"] == SENTINELS["header"], "the header sentinel never reached the handler"
    app_records = _app_records(captured)
    assert app_records, (
        "no application log record was captured, so the assertions below would be vacuous: "
        f"captured={len(captured)} app_records={len(app_records)}"
    )
    # The application logs the *route template* for each of these requests, so the stream the
    # sentinel assertions read below really is the one a leaked path or query would appear in.
    logged_actions = {
        record.__dict__.get("action")
        for record in app_records
        if record.name == "cardioauth.api.main"
    }
    for template in (
        "POST /api/test/authz/phi/{note}/permitted",
        "POST /api/test/authz/phi/{note}/denied",
        "POST /api/test/authz/phi/{note}/no-policy",
        "POST /api/test/authz/phi/{note}/objects/case/{object_id}",
    ):
        assert template in logged_actions, f"{template} was never logged: {sorted(map(str, logged_actions))}"

    assert role_denied.status_code == 403, role_denied.text
    assert role_denied.json()["detail"]["code"] == "permission_denied"
    assert undeclared.status_code == 403, undeclared.text
    assert undeclared.json()["detail"]["code"] == "permission_not_declared"
    assert cross_practice.status_code == 404, cross_practice.text
    assert cross_practice.json()["detail"]["code"] == "not_found"

    # Each refusal was really refused by the authoriser and really audited: the reason code
    # proves the request reached the gate rather than merely failing to route.
    denials = _rows_since(engine, since, actor_user_id=coordinator_a.user_id)
    assert [row["action"] for row in denials] == ["authz.denied"] * 3, denials
    reasons = sorted(row["detail"]["reason"] for row in denials)
    assert reasons == ["cross_practice_denied", "permission_not_declared", "role_not_permitted"], reasons
    assert {row["outcome"] for row in denials} == {"denied"}
    # The permitted request wrote no authz row: only refusals are audited here (§7.3).
    assert len(denials) == 3
    assert chain_verifies(engine)[0] > 0

    # ------------------------------------------------------------------ the property
    logs = _log_blob(captured)
    audits = _audit_blob(denials)
    for where, sentinel in SENTINELS.items():
        assert sentinel not in logs, f"the {where} sentinel reached a log record (§7.5): {sentinel!r}"
        assert sentinel not in audits, f"the {where} sentinel reached an audit row (§7.5): {sentinel!r}"
        # Neither raw nor JSON-escaped nor percent-encoded: any encoding is still the value.
        assert json.dumps(sentinel)[1:-1] not in logs
        assert json.dumps(sentinel)[1:-1] not in audits
        for row in denials:
            assert sentinel not in json.dumps(row["detail"], default=repr, sort_keys=True)


def test_the_cross_practice_refusal_names_no_other_practice(
    probe_client,  # noqa: ANN001
    world: World,
    engine,  # noqa: ANN001
    coordinator_a,  # noqa: ANN001
) -> None:
    """A 404 must not leak the other practice, in the response, the log or the audit row."""
    since = _head(engine)
    with capture_application_logs() as captured:
        responses = _requests(probe_client, world, with_request_id=True)
    assert responses["cross_practice"].status_code == 404
    assert str(world.practices["b"]) not in responses["cross_practice"].text

    rows = _rows_since(engine, since, actor_user_id=coordinator_a.user_id)
    assert [row["detail"]["reason"] for row in rows] == [
        "role_not_permitted",
        "permission_not_declared",
        "cross_practice_denied",
    ]
    forbidden = {
        "the other practice": str(world.practices["b"]),
        "its case number": "AUTHZ-B-0001",
    }
    for what, value in forbidden.items():
        assert value not in _log_blob(captured), f"{what} reached a log record"
        assert value not in _audit_blob(rows), f"{what} reached an audit row"
    cross = [row for row in rows if row["detail"]["reason"] == "cross_practice_denied"]
    assert cross and cross[0]["practice_id"] == world.practices["a"], "the denial is the actor's practice"


def test_the_request_id_on_the_audit_row_is_the_servers_own(
    probe_client,  # noqa: ANN001
    world: World,
    engine,  # noqa: ANN001
    coordinator_a,  # noqa: ANN001
) -> None:
    """A caller-supplied ``X-Request-ID`` is never copied into a log line or the audit chain.

    The value the caller sent is free text — a name, an MRN — so it is discarded and replaced by
    a server-generated opaque id (``cardioauth.security.identifiers``). The caller still receives
    that id in the ``x-request-id`` response header, so correlation is not lost, and the audit
    row of the same request names the same id, so a log line and its audit row still match.
    """
    since = _head(engine)
    with capture_application_logs() as captured:
        responses = _requests(probe_client, world, with_request_id=True)

    returned = {response.headers.get("x-request-id") for response in responses.values()}
    assert None not in returned, "every response must carry the correlation id of its request"
    assert len(returned) == 4, "each request gets its own id"
    for value in returned:
        assert value is not None
        assert len(value) == 32 and value.isalnum(), value

    rows = _rows_since(engine, since, actor_user_id=coordinator_a.user_id)
    audit_ids = [row["request_id"] for row in rows]
    assert [row["action"] for row in rows] == ["authz.denied"] * 3, rows
    assert set(audit_ids) <= returned, f"audit rows must be correlatable: {audit_ids} vs {returned}"
    assert CALLER_REQUEST_ID not in _log_blob(captured)
    assert CALLER_REQUEST_ID not in _audit_blob(rows)
    assert CALLER_REQUEST_ID not in " ".join(audit_ids)
