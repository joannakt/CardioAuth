"""baseline schema (§2 of DESIGN.md)

Applies the authoritative DDL in ``cardioauth/db/sql/001_schema.sql`` — the whole data
model plus every database-enforced invariant (fact_span validation, span-required
facts, append-only page text, immutable published criteria, insert-only letters,
revocable-once sign-offs, hash-chained audit log).

Revision ID: 0001
Revises:
"""

from __future__ import annotations

from pathlib import Path

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

SQL_FILE = Path(__file__).resolve().parents[2] / "cardioauth" / "db" / "sql" / "001_schema.sql"


def upgrade() -> None:
    op.execute(SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    # The baseline owns both schemas entirely, so dropping them is exact.
    op.execute("DROP SCHEMA IF EXISTS cardioauth CASCADE")
    op.execute("DROP SCHEMA IF EXISTS cardioauth_audit CASCADE")
    op.execute("DROP EXTENSION IF EXISTS btree_gist")
    op.execute("DROP EXTENSION IF EXISTS citext")
