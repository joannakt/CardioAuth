"""ORM declarations for the tables the application touches in M1/M2.

Why only some tables: the DDL in ``db/sql/001_schema.sql`` is the authoritative, complete
data model (§2) and it is what the migrated database contains. Mapping a table in the ORM
adds nothing until a service uses it, so each milestone adds the mappings it needs and
``tests/test_schema_sync.py`` proves the ORM matches the migrated database (and that the
DDL's table list is complete).
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    ARRAY,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import CITEXT, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from cardioauth.db import Base


def _uuid_col(**kwargs: object) -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, **kwargs)


class Practice(Base):
    __tablename__ = "practice"

    id: Mapped[uuid.UUID] = _uuid_col()
    name: Mapped[str] = mapped_column(Text, nullable=False)
    npi: Mapped[str | None] = mapped_column(String(10))
    timezone: Mapped[str] = mapped_column(Text, nullable=False, server_default="America/New_York")
    settings: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AppUser(Base):
    __tablename__ = "app_user"
    __table_args__ = (UniqueConstraint("practice_id", "email", name="uq_app_user_practice_email"),)

    id: Mapped[uuid.UUID] = _uuid_col()
    practice_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("cardioauth.practice.id"))
    email: Mapped[str] = mapped_column(CITEXT, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    full_name: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    npi: Mapped[str | None] = mapped_column(String(10))
    totp_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    totp_enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class UserSession(Base):
    __tablename__ = "user_session"

    id: Mapped[uuid.UUID] = _uuid_col()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cardioauth.app_user.id"), nullable=False)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ip_hash: Mapped[bytes | None] = mapped_column(LargeBinary)
    user_agent_hash: Mapped[bytes | None] = mapped_column(LargeBinary)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reauth_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class UserInvitation(Base):
    __tablename__ = "user_invitation"

    id: Mapped[uuid.UUID] = _uuid_col()
    practice_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cardioauth.practice.id"), nullable=False)
    email: Mapped[str] = mapped_column(CITEXT, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)
    invited_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("cardioauth.app_user.id"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Procedure(Base):
    __tablename__ = "procedure"

    id: Mapped[uuid.UUID] = _uuid_col()
    code: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    cpt_codes: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, server_default="{}")
    modality: Mapped[str] = mapped_column(Text, nullable=False)
    default_criterion_categories: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, server_default="{}")
    fact_fields: Mapped[dict] = mapped_column(JSONB, nullable=False)
    booster_letter_kind: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    display_order: Mapped[int] = mapped_column(Integer, nullable=False, server_default="100")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Payer(Base):
    __tablename__ = "payer"
    __table_args__ = (UniqueConstraint("name", "state", "plan_hint", name="uq_payer_identity"),)

    id: Mapped[uuid.UUID] = _uuid_col()
    name: Mapped[str] = mapped_column(Text, nullable=False)
    payer_type: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str | None] = mapped_column(String(2))
    plan_hint: Mapped[str | None] = mapped_column(Text)
    turnaround_days: Mapped[int] = mapped_column(Integer, nullable=False, server_default="14")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CaseRecord(Base):
    __tablename__ = "case_record"
    __table_args__ = (UniqueConstraint("practice_id", "case_number", name="uq_case_number"),)

    id: Mapped[uuid.UUID] = _uuid_col()
    practice_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cardioauth.practice.id"), nullable=False)
    case_number: Mapped[str] = mapped_column(Text, nullable=False)
    patient_ref: Mapped[str] = mapped_column(Text, nullable=False)
    patient_display: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    procedure_code_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cardioauth.procedure.id"), nullable=False)
    payer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cardioauth.payer.id"), nullable=False)
    cpt_code: Mapped[str] = mapped_column(Text, nullable=False)
    date_of_service: Mapped[date | None] = mapped_column(Date)
    ordering_provider: Mapped[str | None] = mapped_column(Text)
    urgency: Mapped[str] = mapped_column(Text, nullable=False, server_default="routine")
    criteria_set_version_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("cardioauth.criteria_set_version.id"))
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="draft")
    priority_rank: Mapped[int] = mapped_column(Integer, nullable=False, server_default="100")
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    submission_ref: Mapped[dict | None] = mapped_column(JSONB)
    due_date: Mapped[date | None] = mapped_column(Date)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    close_reason: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("cardioauth.app_user.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuditLog(Base):
    """Read-side mapping of ``cardioauth_audit.audit_log``. The application only inserts
    through :mod:`cardioauth.audit.chain`, and the database refuses UPDATE/DELETE."""

    __tablename__ = "audit_log"
    __table_args__ = {"schema": "cardioauth_audit"}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    practice_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    actor_role: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    object_type: Mapped[str] = mapped_column(Text, nullable=False)
    object_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    outcome: Mapped[str] = mapped_column(Text, nullable=False, server_default="success")
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    request_id: Mapped[str | None] = mapped_column(Text)
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    prev_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    entry_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)


__all__ = [
    "AppUser",
    "AuditLog",
    "Base",
    "CaseRecord",
    "Payer",
    "Practice",
    "Procedure",
    "UserInvitation",
    "UserSession",
]
