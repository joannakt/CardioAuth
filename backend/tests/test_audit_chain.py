"""The audit hash chain: it verifies, and it fails loudly when a row is tampered with."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text

from cardioauth.audit.chain import (
    AuditEntry,
    AuditChainError,
    append_entry,
    canonical_payload,
    compute_entry_hash,
    verify_chain,
)
from tests.conftest import insert_fact, insert_span, seed as seed_fixture  # noqa: F401

pytestmark = pytest.mark.db


def _entries(seed) -> list[AuditEntry]:  # noqa: ANN001
    return [
        AuditEntry(
            action="case.created", object_type="case", object_id=seed.case_id, case_id=seed.case_id,
            actor_user_id=seed.coordinator_id, actor_role="coordinator", practice_id=seed.practice_id,
            detail={"procedure_code": "tte_test_only"},
        ),
        AuditEntry(
            action="document.uploaded", object_type="document", object_id=seed.document_id, case_id=seed.case_id,
            actor_user_id=seed.coordinator_id, actor_role="coordinator", detail={"page_count": 1},
        ),
        AuditEntry(
            action="letter.exported", object_type="letter_version", outcome="denied",
            actor_user_id=seed.coordinator_id, actor_role="coordinator",
            detail={"reason_code": "export_blocked"},
        ),
    ]


def test_chain_verifies_and_is_deterministic(conn, seed) -> None:
    hashes = [append_entry(conn, entry) for entry in _entries(seed)]
    assert len(set(hashes)) == 3
    checked, last_id = verify_chain(conn)
    assert checked == 3
    assert last_id > 0

    payload = canonical_payload(
        occurred_at="2026-02-01T12:00:00.000000+00:00",
        practice_id=None, actor_user_id=None, actor_role=None, action="a", object_type="b",
        object_id=None, case_id=None, outcome="success", detail={"z": 1, "a": "x"},
        request_id=None, session_id=None,
    )
    assert payload == canonical_payload(
        occurred_at="2026-02-01T12:00:00+00:00",
        practice_id=None, actor_user_id=None, actor_role=None, action="a", object_type="b",
        object_id=None, case_id=None, outcome="success", detail={"a": "x", "z": 1},
        request_id=None, session_id=None,
    )
    assert compute_entry_hash(payload, b"\x00" * 32) == compute_entry_hash(payload, bytes(32))


def test_phi_shaped_detail_is_refused_before_it_reaches_the_table(conn, seed) -> None:
    with pytest.raises(AuditChainError):
        append_entry(
            conn,
            AuditEntry(action="case.viewed", object_type="case", detail={"patient_name": "J. Doe"}),
        )


def test_tampering_with_a_row_makes_verification_fail(conn, seed) -> None:
    """Requires disabling the append-only trigger, i.e. the same thing an attacker with
    database access would do — and the chain detects it anyway (§2.9, M1 acceptance 4)."""
    for entry in _entries(seed):
        append_entry(conn, entry)
    assert verify_chain(conn)[0] == 3

    conn.exec_driver_sql("ALTER TABLE cardioauth_audit.audit_log DISABLE TRIGGER trg_audit_log_append_only")
    conn.exec_driver_sql(
        "UPDATE cardioauth_audit.audit_log SET action = %s WHERE id = (SELECT min(id) FROM cardioauth_audit.audit_log)",
        ("case.deleted",),
    )
    with pytest.raises(AuditChainError) as excinfo:
        verify_chain(conn)
    assert "entry_hash does not match" in str(excinfo.value)


def test_deleting_a_row_makes_verification_fail(conn, seed) -> None:
    for entry in _entries(seed):
        append_entry(conn, entry)
    conn.exec_driver_sql("ALTER TABLE cardioauth_audit.audit_log DISABLE TRIGGER trg_audit_log_append_only")
    conn.exec_driver_sql(
        "DELETE FROM cardioauth_audit.audit_log WHERE id = (SELECT min(id) FROM cardioauth_audit.audit_log)"
    )
    with pytest.raises(AuditChainError) as excinfo:
        verify_chain(conn)
    assert "prev_hash does not match" in str(excinfo.value)


def test_verify_cli_exit_code(test_database_url: str) -> None:
    """`scripts/audit_chain_verify.py` reports a valid chain with exit code 0."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "scripts/audit_chain_verify.py", "--database-url", test_database_url],
        capture_output=True, text=True, cwd="/".join(__file__.split("/")[:-2] + [".."]) or ".",
        check=False,
    )
    if result.returncode == 2:  # script not found from this cwd: try the explicit path
        result = subprocess.run(
            [sys.executable, "../scripts/audit_chain_verify.py", "--database-url", test_database_url],
            capture_output=True, text=True, cwd=str(__import__("pathlib").Path(__file__).resolve().parents[1]),
            check=False,
        )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "audit chain OK" in result.stdout


def test_span_integrity_sweep_script_is_runnable(test_database_url: str) -> None:
    """scripts/check_span_integrity.py re-validates every stored span (§2.5.5)."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "scripts/check_span_integrity.py", "--database-url", test_database_url],
        capture_output=True, text=True, check=False,
        cwd=str(__import__("pathlib").Path(__file__).resolve().parents[1]),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "span integrity OK" in result.stdout
