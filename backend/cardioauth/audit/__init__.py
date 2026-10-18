"""Audit module. The chain primitives are real and tested in M1a; the *service* that
writes application events (with a request-scoped actor, session and request id) is M1b."""

from cardioauth.audit.chain import (
    GENESIS_PREV_HASH,
    AuditEntry,
    append_entry,
    canonical_payload,
    compute_entry_hash,
    verify_chain,
)

__all__ = [
    "GENESIS_PREV_HASH",
    "AuditEntry",
    "append_entry",
    "canonical_payload",
    "compute_entry_hash",
    "verify_chain",
]
