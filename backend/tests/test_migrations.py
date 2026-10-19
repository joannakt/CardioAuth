"""Migrations apply to an empty database, round-trip, and cannot drift from the ORM."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import create_engine, text

from tests.conftest import ROUNDTRIP_DB_NAME, _alembic_config, _drop_and_create, url_for

BACKEND_ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.db

DDL_TABLES = {
    "practice", "app_user", "user_session", "user_invitation", "procedure", "payer", "case_record",
    "case_status_history", "case_party", "document", "document_page", "page_text_version", "extraction_run",
    "fact", "fact_span", "criteria_set", "criteria_set_version", "criterion", "criteria_set_version_selection",
    "criteria_evaluation", "criterion_verdict", "criterion_verdict_fact", "gap_item", "letter", "letter_version",
    "verification_run", "claim_verdict", "claim_verdict_fact", "signoff",
}


def test_migration_applies_to_an_empty_database_and_downgrade_round_trips(monkeypatch) -> None:  # noqa: ANN001
    _drop_and_create(ROUNDTRIP_DB_NAME)
    url = url_for(ROUNDTRIP_DB_NAME)
    # migrations/env.py resolves the URL from -x db_url, then this override, then Settings.
    # Without the override the round-trip migrates the default (application) database.
    monkeypatch.setenv("CARDIOAUTH_MIGRATION_DATABASE_URL", url)
    cfg = _alembic_config()
    engine = create_engine(url)

    command.upgrade(cfg, "head")
    with engine.connect() as conn:
        revision = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        tables = {
            row[0]
            for row in conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'cardioauth'")
            )
        }
    assert revision == "0001"
    assert tables == DDL_TABLES, f"schema drift: {DDL_TABLES ^ tables}"

    command.downgrade(cfg, "base")
    with engine.connect() as conn:
        remaining = conn.execute(
            text("SELECT count(*) FROM pg_tables WHERE schemaname IN ('cardioauth','cardioauth_audit')")
        ).scalar_one()
    assert remaining == 0

    command.upgrade(cfg, "head")
    with engine.connect() as conn:
        assert conn.execute(
            text("SELECT count(*) FROM pg_tables WHERE schemaname = 'cardioauth'")
        ).scalar_one() == len(DDL_TABLES)

    engine.dispose()
    _drop_and_create(ROUNDTRIP_DB_NAME)  # leave it empty for the next run


def test_ddl_declares_every_invariant_trigger(conn) -> None:
    """The mechanisms are what matter: assert they exist in the migrated database."""
    triggers = {
        row[0]
        for row in conn.exec_driver_sql(
            "SELECT tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE NOT t.tgisinternal AND n.nspname IN ('cardioauth','cardioauth_audit')"
        )
    }
    assert {
        "trg_fact_span_validate",
        "trg_fact_requires_span",
        "trg_fact_span_delete_guard",
        "trg_page_text_version_append_only",
        "trg_letter_version_append_only",
        "trg_case_status_history_append_only",
        "trg_verification_run_append_only",
        "trg_claim_verdict_append_only",
        "trg_claim_verdict_fact_append_only",
        "trg_audit_log_append_only",
        "trg_signoff_guard",
        "trg_criteria_set_version_guard",
        "trg_criterion_guard",
        "trg_require_published_criteria",
        "trg_page_current_text_version",
    } <= triggers


def test_orm_matches_the_migrated_database(conn) -> None:
    """No silent drift between cardioauth/db/models.py and the DDL."""
    from cardioauth.db import Base
    import cardioauth.db.models  # noqa: F401 - registers the mappings

    db_columns = {}
    for row in conn.exec_driver_sql(
        "SELECT table_schema || '.' || table_name AS t, column_name FROM information_schema.columns "
        "WHERE table_schema IN ('cardioauth','cardioauth_audit')"
    ):
        db_columns.setdefault(row[0], set()).add(row[1])

    for table in Base.metadata.sorted_tables:
        key = f"{table.schema}.{table.name}"
        assert key in db_columns, f"ORM declares {key}, the database does not have it"
        missing = {c.name for c in table.columns} - db_columns[key]
        assert not missing, f"ORM columns missing from {key}: {sorted(missing)}"


def test_expected_head_matches_the_only_revision(conn) -> None:
    from cardioauth.api.health import expected_head_revision

    assert expected_head_revision() == "0001"
