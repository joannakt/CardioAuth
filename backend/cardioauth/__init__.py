"""CardioAuth backend package.

Milestone M1a ships: settings + production guards, structured logging with the PHI
filter, the complete schema (``db/sql/001_schema.sql``) with its database-enforced
invariants, the Alembic baseline, the audit hash-chain primitives, and ``/api/health``.

Not implemented yet (each raises ``NotImplementedError`` rather than silently doing
nothing): authentication/RBAC/sessions/audit *service* (M1b), BlobStore backends and
ingest/OCR (M2), extraction/criteria/letter/verification services and LLM/OCR providers
(M3–M6).
"""

__version__ = "0.1.0"
