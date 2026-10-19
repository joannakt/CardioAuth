"""authorisation support for the §7.3 RBAC matrix: denial-review index, "a denial must say
why" constraint, case soft-redaction columns, practice/role user index (DESIGN.md §7.3).

The matrix itself lives in code (``cardioauth/authz/permissions.py``) so that it is reviewed
against §7.3 and cannot be widened by a database write. This revision adds only the storage
the matrix's decisions need.

Additive only: revisions 0001 and 0002 are never amended.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

from pathlib import Path

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

SQL_FILE = Path(__file__).resolve().parents[2] / "cardioauth" / "db" / "sql" / "003_authz.sql"


def upgrade() -> None:
    op.execute(SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    op.execute(
        """
        DROP INDEX IF EXISTS cardioauth.ix_app_user_practice_role;
        DROP INDEX IF EXISTS cardioauth.ix_case_redacted;
        ALTER TABLE cardioauth.case_record DROP CONSTRAINT IF EXISTS ck_case_redaction_complete;
        ALTER TABLE cardioauth.case_record
            DROP COLUMN IF EXISTS redaction_reason,
            DROP COLUMN IF EXISTS redacted_by,
            DROP COLUMN IF EXISTS redacted_at;
        DROP INDEX IF EXISTS cardioauth_audit.ix_audit_outcome_actor;
        ALTER TABLE cardioauth_audit.audit_log
            DROP CONSTRAINT IF EXISTS ck_audit_denied_has_detail;
        """
    )
