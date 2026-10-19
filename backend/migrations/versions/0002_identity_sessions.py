"""identity and session core: lockout escalation, pending-2FA sessions, TOTP replay ledger,
single-use recovery codes (DESIGN.md §2.1, §7.1, §7.2).

Additive only: revision 0001 (``cardioauth/db/sql/001_schema.sql``) is never amended.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

from pathlib import Path

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

SQL_FILE = Path(__file__).resolve().parents[2] / "cardioauth" / "db" / "sql" / "002_identity_sessions.sql"


def upgrade() -> None:
    op.execute(SQL_FILE.read_text(encoding="utf-8"))


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS cardioauth.user_recovery_code;
        DROP TABLE IF EXISTS cardioauth.totp_used_code;
        ALTER TABLE cardioauth.user_session DROP CONSTRAINT IF EXISTS ck_session_totp_after_issue;
        ALTER TABLE cardioauth.user_session DROP COLUMN IF EXISTS two_factor_verified_at;
        ALTER TABLE cardioauth.app_user DROP CONSTRAINT IF EXISTS ck_app_user_lockout_stage_non_negative;
        ALTER TABLE cardioauth.app_user DROP COLUMN IF EXISTS lockout_stage;
        """
    )
