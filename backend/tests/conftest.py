"""Shared test fixtures.

Database-backed tests are marked ``@pytest.mark.db``. They are skipped (loudly) when no
PostgreSQL is reachable, so the unit tests still run on a machine without a database;
CI and ``docker compose run api pytest`` always have one.

Synthetic data only: every value below is obviously fake and never clinical truth.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, make_url
from sqlalchemy.exc import DBAPIError

BACKEND_ROOT = Path(__file__).resolve().parents[1]

ADMIN_URL = os.environ.get(
    "CARDIOAUTH_TEST_ADMIN_URL", "postgresql+psycopg://cardioauth:cardioauth@localhost:5432/postgres"
)
TEST_DB_NAME = os.environ.get("CARDIOAUTH_TEST_DB_NAME", "cardioauth_test")
ROUNDTRIP_DB_NAME = f"{TEST_DB_NAME}_roundtrip"

# Obviously synthetic page text. NOT clinical guidance; a placeholder for offset tests.
SAMPLE_TEXT = (
    "TEST-ONLY synthetic clinic note.\n"
    "Patient reports exertional chest discomfort. LVEF 55 percent on 2026-01-05.\n"
    "Prior stress ECG performed 2025-12-01. No contraindication documented.\n"
)


def url_for(database: str) -> str:
    return str(make_url(ADMIN_URL).set(database=database))


def _drop_and_create(database: str) -> None:
    admin = create_engine(ADMIN_URL, isolation_level="AUTOCOMMIT", poolclass=None)
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
        conn.execute(text(f'CREATE DATABASE "{database}"'))
    admin.dispose()


def _alembic_config() -> Config:
    cfg = Config(str(BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_ROOT / "migrations"))
    return cfg


def _database_available() -> bool:
    from sqlalchemy.exc import SQLAlchemyError

    try:
        engine = create_engine(ADMIN_URL, connect_args={"connect_timeout": 3})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except (SQLAlchemyError, OSError):
        return False


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if _database_available():
        return
    skip = pytest.mark.skip(
        reason=(
            f"no PostgreSQL reachable at {make_url(ADMIN_URL).render_as_string(hide_password=True)}; "
            "start the Compose db service or set CARDIOAUTH_TEST_ADMIN_URL"
        )
    )
    for item in items:
        if "db" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def test_database_url() -> Iterator[str]:
    """A migrated, empty database for the whole session."""
    _drop_and_create(TEST_DB_NAME)
    url = url_for(TEST_DB_NAME)
    os.environ["CARDIOAUTH_ENV"] = "test"
    os.environ["CARDIOAUTH_PHI_LOGGING"] = "off"
    os.environ["DATABASE_URL"] = url
    os.environ["CARDIOAUTH_MIGRATION_DATABASE_URL"] = url

    from cardioauth.db import reset_engine
    from cardioauth.settings import get_settings

    get_settings.cache_clear()
    reset_engine()
    command.upgrade(_alembic_config(), "head")
    yield url
    reset_engine()


@pytest.fixture
def engine(test_database_url: str):  # noqa: ANN201
    eng = create_engine(test_database_url, poolclass=None)
    yield eng
    eng.dispose()


@pytest.fixture
def conn(engine) -> Iterator[Connection]:  # noqa: ANN001
    """One transaction per test, always rolled back: tests cannot leak rows into each other."""
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            yield connection
        finally:
            transaction.rollback()


@contextmanager
def expect_rejection(conn: Connection, token: str) -> Iterator[None]:
    """Assert the database refuses an operation, with the exact invariant token."""
    savepoint = conn.begin_nested()
    try:
        with pytest.raises(DBAPIError) as excinfo:
            yield
        savepoint.rollback()
    except Exception:
        savepoint.rollback()
        raise
    message = str(getattr(excinfo.value, "orig", excinfo.value))
    assert token in message, f"expected rejection token {token!r}, got: {message}"
    assert "cardioauth:" in message


@dataclass
class Seed:
    """Foreign-key scaffolding for the invariant tests (all values synthetic)."""

    practice_id: uuid.UUID
    coordinator_id: uuid.UUID
    physician_id: uuid.UUID
    admin_id: uuid.UUID
    procedure_id: uuid.UUID
    payer_id: uuid.UUID
    case_id: uuid.UUID
    document_id: uuid.UUID
    page_id: uuid.UUID
    text_version_id: uuid.UUID
    text_version_2_id: uuid.UUID | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def offsets(self, needle: str, *, text_version_id: uuid.UUID | None = None) -> tuple[int, int]:
        """Offsets of ``needle`` inside the stored page text (the tests use this to build
        valid spans, and to build deliberately wrong ones)."""
        text_version_id = text_version_id or self.text_version_id
        body = SAMPLE_TEXT if text_version_id == self.text_version_id else f"{SAMPLE_TEXT}[v2]"
        start = body.index(needle)
        return start, start + len(needle)


def _exec(conn: Connection, sql: str, params: tuple[Any, ...] = ()) -> None:
    conn.exec_driver_sql(sql, params)


@pytest.fixture
def seed(conn: Connection) -> Seed:
    ids = {name: uuid.uuid4() for name in
           ("practice", "coordinator", "physician", "admin", "procedure", "payer", "case", "document", "page", "text")}
    _exec(conn, "INSERT INTO cardioauth.practice (id, name) VALUES (%s, %s)", (ids["practice"], "TEST-ONLY Practice"))
    for role, key in (("coordinator", "coordinator"), ("physician", "physician"), ("admin", "admin")):
        _exec(
            conn,
            "INSERT INTO cardioauth.app_user (id, practice_id, email, password_hash, full_name, role) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (ids[key], ids["practice"], f"{key}@test-only.invalid", "argon2-placeholder", f"TEST-ONLY {role}", role),
        )
    _exec(
        conn,
        "INSERT INTO cardioauth.procedure (id, code, display_name, cpt_codes, modality, fact_fields) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (ids["procedure"], "tte_test_only", "TEST-ONLY Procedure", ["0000T"], "echo", "{}"),
    )
    _exec(
        conn,
        "INSERT INTO cardioauth.payer (id, name, payer_type) VALUES (%s, %s, %s)",
        (ids["payer"], "TEST-ONLY-PAYER", "commercial"),
    )
    _exec(
        conn,
        "INSERT INTO cardioauth.case_record (id, practice_id, case_number, patient_ref, patient_display, "
        "procedure_code_id, payer_id, cpt_code, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            ids["case"], ids["practice"], "CAR-2026-0001", "SYNTH-0001", '{"initials":"J.D.","dob_year":1958}',
            ids["procedure"], ids["payer"], "0000T", ids["coordinator"],
        ),
    )
    _exec(
        conn,
        "INSERT INTO cardioauth.document (id, case_id, kind, mime_type, byte_size, sha256, blob_key, page_count, "
        "ingest_status, source, uploaded_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            ids["document"], ids["case"], "clinic_note", "text/plain", 1234, b"\x01" * 32,
            "test-only/blob-1", 1, "ready", "paste", ids["coordinator"],
        ),
    )
    _exec(
        conn,
        "INSERT INTO cardioauth.document_page (id, document_id, page_number, ocr_method) VALUES (%s, %s, %s, %s)",
        (ids["page"], ids["document"], 1, "pasted"),
    )
    _exec(
        conn,
        "INSERT INTO cardioauth.page_text_version (id, page_id, version_no, text_normalized, char_count, ocr_method) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (ids["text"], ids["page"], 1, SAMPLE_TEXT, len(SAMPLE_TEXT), "pasted"),
    )
    _exec(
        conn,
        "UPDATE cardioauth.document_page SET current_text_version_id = %s WHERE id = %s",
        (ids["text"], ids["page"]),
    )
    _exec(
        conn,
        "INSERT INTO cardioauth.case_status_history (id, case_id, from_status, to_status, changed_by) "
        "VALUES (%s, %s, %s, %s, %s)",
        (uuid.uuid4(), ids["case"], None, "draft", ids["coordinator"]),
    )
    return Seed(
        practice_id=ids["practice"],
        coordinator_id=ids["coordinator"],
        physician_id=ids["physician"],
        admin_id=ids["admin"],
        procedure_id=ids["procedure"],
        payer_id=ids["payer"],
        case_id=ids["case"],
        document_id=ids["document"],
        page_id=ids["page"],
        text_version_id=ids["text"],
        extra={k: v for k, v in ids.items()},
    )


def insert_extraction_run(conn: Connection, seed: Seed) -> uuid.UUID:
    run_id = uuid.uuid4()
    _exec(
        conn,
        "INSERT INTO cardioauth.extraction_run (id, case_id, procedure_code_id, status, llm_provider, llm_model, "
        "prompt_version) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (run_id, seed.case_id, seed.procedure_id, "succeeded", "mock", "mock-extract-v1", "extract-v1"),
    )
    return run_id


def insert_fact(
    conn: Connection,
    seed: Seed,
    *,
    field_key: str = "lvef.value",
    value_text: str = "55",
    run_id: uuid.UUID | None = None,
) -> uuid.UUID:
    fact_id = uuid.uuid4()
    run_id = run_id or insert_extraction_run(conn, seed)
    _exec(
        conn,
        "INSERT INTO cardioauth.fact (id, case_id, extraction_run_id, field_key, value_text, confidence) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (fact_id, seed.case_id, run_id, field_key, value_text, "0.900"),
    )
    return fact_id


def insert_span(
    conn: Connection,
    seed: Seed,
    fact_id: uuid.UUID,
    *,
    quote: str | None = None,
    start: int | None = None,
    end: int | None = None,
    text_version_id: uuid.UUID | None = None,
    page_id: uuid.UUID | None = None,
    document_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Insert a fact_span. Defaults produce a *valid* span; pass quote/start/end to break it."""
    text_version_id = text_version_id or seed.text_version_id
    page_id = page_id or seed.page_id
    document_id = document_id or seed.document_id
    if quote is None:
        quote = "LVEF 55 percent"
    if start is None:
        start, end = seed.offsets(quote, text_version_id=text_version_id)
    span_id = uuid.uuid4()
    _exec(
        conn,
        "INSERT INTO cardioauth.fact_span (id, fact_id, page_text_version_id, page_id, document_id, "
        "start_offset, end_offset, quote_text) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (span_id, fact_id, text_version_id, page_id, document_id, start, end, quote),
    )
    return span_id


def make_criteria_version(conn: Connection, seed: Seed, *, status: str = "draft", effective_from: str = "2026-01-01"):  # noqa: ANN201
    """A criteria set + version + one criterion. TEST-ONLY: no real medical necessity text."""
    set_id, version_id, criterion_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    key = f"test-only-{uuid.uuid4().hex[:8]}"
    _exec(
        conn,
        "INSERT INTO cardioauth.criteria_set (id, key, name, procedure_code_id, payer_id, created_by) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (set_id, key, "TEST-ONLY criteria set", seed.procedure_id, seed.payer_id, seed.admin_id),
    )
    _exec(
        conn,
        "INSERT INTO cardioauth.criteria_set_version (id, criteria_set_id, version_no, status, source_citation, "
        "effective_from, published_at, published_by, fingerprint) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            version_id, set_id, 1, status, '{"doc_name":"TEST-ONLY"}', effective_from,
            datetime.now(timezone.utc) if status != "draft" else None,
            seed.admin_id if status != "draft" else None,
            "test-only-fingerprint",
        ),
    )
    _exec(
        conn,
        "INSERT INTO cardioauth.criterion (id, version_id, code, ordinal, category, plain_text, logic, required_fields) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (
            criterion_id, version_id, "TEST-ONLY-01", 1, "documentation",
            "TEST-ONLY placeholder criterion. No medical-necessity content.",
            '{"op": "exists", "field": "lvef.value"}', ["lvef.value"],
        ),
    )
    return set_id, version_id, criterion_id


def sign_off(conn: Connection, seed: Seed, *, reauth_offset_minutes: int = 1) -> uuid.UUID:  # real sign-off fixture (used by M1b tests)
    now = datetime.now(timezone.utc)
    signoff_id = uuid.uuid4()
    _exec(
        conn,
        "INSERT INTO cardioauth.signoff (id, case_id, letter_id, letter_version_id, signer_id, method, "
        "attestation_text, signature_hash, signed_at, reauth_at, verification_run_id) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            signoff_id, seed.case_id, seed.extra["letter"], seed.extra["letter_version"], seed.physician_id,
            "typed_attestation", "TEST-ONLY attestation", b"\x02" * 32, now,
            now - timedelta(minutes=reauth_offset_minutes), seed.extra["verification_run"],
        ),
    )
    return signoff_id


def insert_letter_chain(conn: Connection, seed: Seed) -> None:
    """letter → letter_version → verification_run, enough to exercise the sign-off rules."""
    letter_id, version_id, run_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    _exec(
        conn,
        "INSERT INTO cardioauth.letter (id, case_id, kind, current_version_no, created_by) VALUES (%s, %s, %s, %s, %s)",
        (letter_id, seed.case_id, "lmn", 1, seed.coordinator_id),
    )
    _exec(
        conn,
        "INSERT INTO cardioauth.letter_version (id, letter_id, version_no, source, ast, ast_sha256, created_by) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (version_id, letter_id, 1, "generated", '{"blocks": []}', b"\x03" * 32, seed.coordinator_id),
    )
    _exec(
        conn,
        "INSERT INTO cardioauth.verification_run (id, letter_version_id, status, verifier_provider, verifier_model, "
        "method_version, counts) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (run_id, version_id, "succeeded", "mock", "mock-verify-v1", "verify-v1", '{"sentences": 0}'),
    )
    seed.extra.update(letter=letter_id, letter_version=version_id, verification_run=run_id)
