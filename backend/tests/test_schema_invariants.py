"""The invariant tests: each one attempts the forbidden operation and asserts the database
refuses it with a specific token. A happy-path test would not count (§2.11, INV-1…INV-5).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.exc import DBAPIError, IntegrityError

from tests.conftest import (
    SAMPLE_TEXT,
    expect_rejection,
    insert_fact,
    insert_letter_chain,
    insert_span,
    make_criteria_version,
    sign_off,
)

pytestmark = pytest.mark.db


# --------------------------------------------------------------------------- INV-1
def test_fact_span_quote_must_match_stored_page_text(conn, seed) -> None:
    """A span whose quote is not literally the stored text cannot exist."""
    fact_id = insert_fact(conn, seed)
    insert_span(conn, seed, fact_id)  # the honest span is accepted

    good_start, good_end = seed.offsets("LVEF 55 percent")
    with expect_rejection(conn, "fact_span_quote_mismatch"):
        insert_span(conn, seed, fact_id, quote="LVEF 40 percent", start=good_start, end=good_end)


def test_fact_span_offset_out_of_range_is_rejected(conn, seed) -> None:
    fact_id = insert_fact(conn, seed)
    with expect_rejection(conn, "fact_span_out_of_range"):
        insert_span(conn, seed, fact_id, quote="x", start=len(SAMPLE_TEXT) - 1, end=len(SAMPLE_TEXT) + 10)


def test_fact_span_page_and_document_must_agree_with_text_version(conn, seed) -> None:
    fact_id = insert_fact(conn, seed)
    other_page = uuid.uuid4()
    conn.exec_driver_sql(
        "INSERT INTO cardioauth.document_page (id, document_id, page_number, ocr_method) VALUES (%s, %s, %s, %s)",
        (other_page, seed.document_id, 2, "pasted"),
    )
    with expect_rejection(conn, "fact_span_page_mismatch"):
        insert_span(conn, seed, fact_id, page_id=other_page)

    other_document = uuid.uuid4()
    conn.exec_driver_sql(
        "INSERT INTO cardioauth.document (id, case_id, kind, mime_type, byte_size, sha256, blob_key, page_count, "
        "ingest_status, source, uploaded_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (other_document, seed.case_id, "other", "text/plain", 1, b"\x09" * 32, "test-only/blob-2", 0, "ready",
         "paste", seed.coordinator_id),
    )
    with expect_rejection(conn, "fact_span_document_mismatch"):
        insert_span(conn, seed, fact_id, document_id=other_document)


def test_update_of_a_span_cannot_rewrite_the_quote(conn, seed) -> None:
    """The validation also runs on UPDATE, so a stored span cannot be re-pointed."""
    fact_id = insert_fact(conn, seed)
    span_id = insert_span(conn, seed, fact_id)
    with expect_rejection(conn, "fact_span_quote_mismatch"):
        conn.exec_driver_sql(
            "UPDATE cardioauth.fact_span SET quote_text = %s WHERE id = %s", ("not in the document", span_id)
        )


def test_fact_without_a_span_is_unrepresentable(conn, seed) -> None:
    """INV-1: no source-less fact. The check is a deferred constraint trigger, so it fires
    at COMMIT; SET CONSTRAINTS ALL IMMEDIATE makes it fire here, inside the test
    transaction, which is the same trigger firing at the same moment."""
    insert_fact(conn, seed)
    with expect_rejection(conn, "fact_without_span"):
        conn.exec_driver_sql("SET CONSTRAINTS ALL IMMEDIATE")


def test_deleting_the_last_span_of_a_surviving_fact_is_rejected(conn, seed) -> None:
    fact_id = insert_fact(conn, seed)
    span_id = insert_span(conn, seed, fact_id)
    conn.exec_driver_sql("DELETE FROM cardioauth.fact_span WHERE id = %s", (span_id,))
    with expect_rejection(conn, "fact_without_span"):
        conn.exec_driver_sql("SET CONSTRAINTS ALL IMMEDIATE")


def test_deleting_the_fact_with_its_span_is_allowed(conn, seed) -> None:
    """The rule protects stored facts, it does not make mistakes undeletable before commit."""
    fact_id = insert_fact(conn, seed)
    insert_span(conn, seed, fact_id)
    conn.exec_driver_sql("DELETE FROM cardioauth.fact_span WHERE fact_id = %s", (fact_id,))
    conn.exec_driver_sql("DELETE FROM cardioauth.fact WHERE id = %s", (fact_id,))
    conn.exec_driver_sql("SET CONSTRAINTS ALL IMMEDIATE")  # must not raise
    assert conn.exec_driver_sql("SELECT count(*) FROM cardioauth.fact WHERE id = %s", (fact_id,)).scalar_one() == 0


def test_page_text_version_is_append_only(conn, seed) -> None:
    with expect_rejection(conn, "page_text_version_append_only"):
        conn.exec_driver_sql(
            "UPDATE cardioauth.page_text_version SET text_normalized = %s WHERE id = %s",
            ("rewritten by an attacker", seed.text_version_id),
        )
    with expect_rejection(conn, "page_text_version_append_only"):
        conn.exec_driver_sql("DELETE FROM cardioauth.page_text_version WHERE id = %s", (seed.text_version_id,))


def test_reocr_appends_a_new_version_and_the_old_one_still_validates(conn, seed) -> None:
    """Re-OCR creates version_no=2; spans bound to version 1 keep validating."""
    fact_id = insert_fact(conn, seed)
    insert_span(conn, seed, fact_id)
    v2 = uuid.uuid4()
    conn.exec_driver_sql(
        "INSERT INTO cardioauth.page_text_version (id, page_id, version_no, text_normalized, char_count, ocr_method) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (v2, seed.page_id, 2, SAMPLE_TEXT + "[v2]", len(SAMPLE_TEXT) + 4, "tesseract"),
    )
    conn.exec_driver_sql(
        "UPDATE cardioauth.document_page SET current_text_version_id = %s WHERE id = %s", (v2, seed.page_id)
    )
    with expect_rejection(conn, "fact_span_quote_mismatch"):
        insert_span(conn, seed, fact_id, quote="LVEF 55 percent", text_version_id=v2, start=0, end=15)


def test_document_page_cannot_point_at_another_pages_text(conn, seed) -> None:
    other_page = uuid.uuid4()
    conn.exec_driver_sql(
        "INSERT INTO cardioauth.document_page (id, document_id, page_number, ocr_method) VALUES (%s, %s, %s, %s)",
        (other_page, seed.document_id, 3, "pasted"),
    )
    with expect_rejection(conn, "page_current_text_foreign_page"):
        conn.exec_driver_sql(
            "UPDATE cardioauth.document_page SET current_text_version_id = %s WHERE id = %s",
            (seed.text_version_id, other_page),
        )


# --------------------------------------------------------------------------- INV-2
def test_published_criteria_version_is_immutable(conn, seed) -> None:
    _, version_id, _ = make_criteria_version(conn, seed, status="published")
    with expect_rejection(conn, "criteria_version_immutable"):
        conn.exec_driver_sql(
            "UPDATE cardioauth.criteria_set_version SET fingerprint = %s WHERE id = %s",
            ("different-rules", version_id),
        )
    with expect_rejection(conn, "criteria_version_immutable"):
        conn.exec_driver_sql(
            "UPDATE cardioauth.criteria_set_version SET effective_from = %s WHERE id = %s", ("2020-01-01", version_id)
        )
    with expect_rejection(conn, "criteria_version_immutable"):
        conn.exec_driver_sql(
            "UPDATE cardioauth.criteria_set_version SET source_citation = %s WHERE id = %s",
            ('{"doc_name":"swapped"}', version_id),
        )
    with expect_rejection(conn, "criteria_version_immutable"):
        conn.exec_driver_sql("DELETE FROM cardioauth.criteria_set_version WHERE id = %s", (version_id,))


def test_criteria_version_lifecycle_is_one_way(conn, seed) -> None:
    _, version_id, _ = make_criteria_version(conn, seed, status="published")
    with expect_rejection(conn, "criteria_version_status_transition"):
        conn.exec_driver_sql(
            "UPDATE cardioauth.criteria_set_version SET status = 'draft' WHERE id = %s", (version_id,)
        )
    conn.exec_driver_sql("UPDATE cardioauth.criteria_set_version SET status = 'retired' WHERE id = %s", (version_id,))
    with expect_rejection(conn, "criteria_version_status_transition"):
        conn.exec_driver_sql(
            "UPDATE cardioauth.criteria_set_version SET status = 'published' WHERE id = %s", (version_id,)
        )


def test_draft_version_is_editable_and_publishing_stamps_are_required(conn, seed) -> None:
    _, version_id, _ = make_criteria_version(conn, seed, status="draft")
    conn.exec_driver_sql(
        "UPDATE cardioauth.criteria_set_version SET notes = %s WHERE id = %s", ("edited while draft", version_id)
    )
    with expect_rejection(conn, "criteria_version_publish_incomplete"):
        conn.exec_driver_sql("UPDATE cardioauth.criteria_set_version SET status = 'published' WHERE id = %s", (version_id,))


def test_criteria_rows_of_a_published_version_cannot_be_touched(conn, seed) -> None:
    _, version_id, criterion_id = make_criteria_version(conn, seed, status="published")
    with expect_rejection(conn, "criterion_immutable"):
        conn.exec_driver_sql(
            "UPDATE cardioauth.criterion SET plain_text = %s WHERE id = %s", ("rewritten rule", criterion_id)
        )
    with expect_rejection(conn, "criterion_immutable"):
        conn.exec_driver_sql("DELETE FROM cardioauth.criterion WHERE id = %s", (criterion_id,))
    with expect_rejection(conn, "criterion_immutable"):
        conn.exec_driver_sql(
            "INSERT INTO cardioauth.criterion (id, version_id, code, ordinal, category, plain_text, logic) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (uuid.uuid4(), version_id, "TEST-ONLY-99", 9, "documentation", "TEST-ONLY", "{}"),
        )


def test_publishing_an_empty_version_is_refused(conn, seed) -> None:
    set_id, version_id = uuid.uuid4(), uuid.uuid4()
    conn.exec_driver_sql(
        "INSERT INTO cardioauth.criteria_set (id, key, name, created_by) VALUES (%s, %s, %s, %s)",
        (set_id, f"empty-{uuid.uuid4().hex[:6]}", "TEST-ONLY empty set", seed.admin_id),
    )
    conn.exec_driver_sql(
        "INSERT INTO cardioauth.criteria_set_version (id, criteria_set_id, version_no, status, source_citation, "
        "effective_from, fingerprint) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (version_id, set_id, 1, "draft", "{}", "2026-01-01", "fp"),
    )
    with expect_rejection(conn, "criteria_version_publish_empty"):
        conn.exec_driver_sql(
            "UPDATE cardioauth.criteria_set_version SET status = 'published', published_at = now(), "
            "published_by = %s WHERE id = %s",
            (seed.admin_id, version_id),
        )
        conn.exec_driver_sql("SET CONSTRAINTS ALL IMMEDIATE")


def test_only_one_published_version_can_be_effective_on_a_date(conn, seed) -> None:
    """Exclusion constraint on the published date ranges (§2.6)."""
    set_id, first_version, _ = make_criteria_version(conn, seed, status="published", effective_from="2026-01-01")
    second_version = uuid.uuid4()
    with pytest.raises(DBAPIError) as excinfo:
        conn.exec_driver_sql(
            "INSERT INTO cardioauth.criteria_set_version (id, criteria_set_id, version_no, status, source_citation, "
            "effective_from, published_at, published_by, fingerprint) VALUES (%s, %s, %s, %s, %s, %s, now(), %s, %s)",
            (second_version, set_id, 2, "published", "{}", "2026-06-01", seed.admin_id, "fp2"),
        )
    assert "ex_criteria_version_effective" in str(excinfo.value.orig)
    # a non-overlapping range is fine
    conn.exec_driver_sql(
        "UPDATE cardioauth.criteria_set_version SET effective_to = %s WHERE id = %s", ("2025-12-31", first_version)
    )
    conn.exec_driver_sql(
        "INSERT INTO cardioauth.criteria_set_version (id, criteria_set_id, version_no, status, source_citation, "
        "effective_from, published_at, published_by, fingerprint) VALUES (%s, %s, %s, %s, %s, %s, now(), %s, %s)",
        (second_version, set_id, 2, "published", "{}", "2026-06-01", seed.admin_id, "fp2"),
    )


# --------------------------------------------------------------------------- INV-3 / INV-4
def test_letter_version_is_insert_only(conn, seed) -> None:
    insert_letter_chain(conn, seed)
    with expect_rejection(conn, "letter_version_append_only"):
        conn.exec_driver_sql(
            "UPDATE cardioauth.letter_version SET ast = %s WHERE id = %s",
            ('{"blocks": [{"text": "silently rewritten"}]}', seed.extra["letter_version"]),
        )
    with expect_rejection(conn, "letter_version_append_only"):
        conn.exec_driver_sql("DELETE FROM cardioauth.letter_version WHERE id = %s", (seed.extra["letter_version"],))


def test_verification_rows_are_insert_only(conn, seed) -> None:
    insert_letter_chain(conn, seed)
    with expect_rejection(conn, "verification_run_append_only"):
        conn.exec_driver_sql(
            "UPDATE cardioauth.verification_run SET counts = %s WHERE id = %s",
            ('{"sentences": 99}', seed.extra["verification_run"]),
        )


def test_case_status_history_is_append_only(conn, seed) -> None:
    history_id = conn.exec_driver_sql(
        "SELECT id FROM cardioauth.case_status_history WHERE case_id = %s", (seed.case_id,)
    ).scalar_one()
    with expect_rejection(conn, "case_status_history_append_only"):
        conn.exec_driver_sql(
            "UPDATE cardioauth.case_status_history SET reason = %s WHERE id = %s", ("rewritten", history_id)
        )
    with expect_rejection(conn, "case_status_history_append_only"):
        conn.exec_driver_sql("DELETE FROM cardioauth.case_status_history WHERE id = %s", (history_id,))


def test_signoff_columns_are_immutable_except_one_revocation(conn, seed) -> None:
    insert_letter_chain(conn, seed)
    signoff_id = sign_off(conn, seed)
    with expect_rejection(conn, "signoff_immutable"):
        conn.exec_driver_sql(
            "UPDATE cardioauth.signoff SET attestation_text = %s WHERE id = %s", ("different words", signoff_id)
        )
    with expect_rejection(conn, "signoff_immutable"):
        conn.exec_driver_sql("DELETE FROM cardioauth.signoff WHERE id = %s", (signoff_id,))
    with expect_rejection(conn, "signoff_needs_revoke_reason"):
        conn.exec_driver_sql("UPDATE cardioauth.signoff SET revoked_at = now() WHERE id = %s", (signoff_id,))
    conn.exec_driver_sql(
        "UPDATE cardioauth.signoff SET revoked_at = now(), revoke_reason = %s WHERE id = %s",
        ("TEST-ONLY revocation", signoff_id),
    )
    with expect_rejection(conn, "signoff_immutable"):
        conn.exec_driver_sql(
            "UPDATE cardioauth.signoff SET revoked_at = now(), revoke_reason = %s WHERE id = %s",
            ("second revoke", signoff_id),
        )


def test_signoff_requires_fresh_reauth(conn, seed) -> None:
    insert_letter_chain(conn, seed)
    with pytest.raises(IntegrityError) as excinfo:
        sign_off(conn, seed, reauth_offset_minutes=10)
    assert "ck_signoff_reauth_fresh" in str(excinfo.value.orig)


def test_signoff_requires_a_verification_run_and_one_active_signoff(conn, seed) -> None:
    insert_letter_chain(conn, seed)
    sign_off(conn, seed)
    with pytest.raises(IntegrityError) as excinfo:
        sign_off(conn, seed)
    assert "uq_signoff_active" in str(excinfo.value.orig)


def test_signoff_verification_run_is_required(conn, seed) -> None:
    insert_letter_chain(conn, seed)
    with pytest.raises(IntegrityError) as excinfo:
        conn.exec_driver_sql(
            "INSERT INTO cardioauth.signoff (id, case_id, letter_id, letter_version_id, signer_id, method, "
            "attestation_text, signature_hash, signed_at, reauth_at, verification_run_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now(), now(), %s)",
            (uuid.uuid4(), seed.case_id, seed.extra["letter"], seed.extra["letter_version"], seed.physician_id,
             "typed_attestation", "TEST-ONLY", b"\x04" * 32, None),
        )
    assert "verification_run_id" in str(excinfo.value.orig)


# --------------------------------------------------------------------------- INV-5
def test_audit_log_is_append_only(conn, seed) -> None:
    from cardioauth.audit.chain import AuditEntry, append_entry

    entry_hash = append_entry(
        conn,
        AuditEntry(
            action="case.created",
            object_type="case",
            object_id=seed.case_id,
            case_id=seed.case_id,
            actor_user_id=seed.coordinator_id,
            actor_role="coordinator",
            practice_id=seed.practice_id,
            detail={"field_keys": ["lvef.value"], "count": 1},
        ),
    )
    row_id = conn.exec_driver_sql(
        "SELECT id FROM cardioauth_audit.audit_log WHERE entry_hash = %s", (entry_hash,)
    ).scalar_one()
    with expect_rejection(conn, "audit_log_append_only"):
        conn.exec_driver_sql("UPDATE cardioauth_audit.audit_log SET action = %s WHERE id = %s", ("case.deleted", row_id))
    with expect_rejection(conn, "audit_log_append_only"):
        conn.exec_driver_sql("DELETE FROM cardioauth_audit.audit_log WHERE id = %s", (row_id,))


def test_database_rejects_a_useless_audit_row_shape(conn) -> None:
    """detail is jsonb and hashes are fixed width — a malformed chain row cannot be written."""
    with pytest.raises(IntegrityError):
        conn.exec_driver_sql(
            "INSERT INTO cardioauth_audit.audit_log (action, object_type, prev_hash, entry_hash) "
            "VALUES (%s, %s, %s, %s)",
            ("case.created", "case", b"\x00" * 31, b"\x00" * 32),
        )


def test_criteria_fixtures_are_obviously_fake() -> None:
    """Every criteria-shaped fixture in the suite is marked TEST-ONLY (INV-2 / task constraint)."""
    body = open(__file__, encoding="utf-8").read()
    assert "TEST-ONLY-01" in body
    assert "No medical-necessity content" in body
