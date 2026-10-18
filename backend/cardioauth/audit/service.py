"""Audit service — M1b.

Boundary is fixed here so the rest of the codebase can already import it:
``record(session, entry)`` appends a chained audit row for an application event and is
the only supported way to write to ``cardioauth_audit.audit_log``.
"""

from __future__ import annotations

from typing import Any

from cardioauth.audit.chain import AuditEntry

_NOT_IMPLEMENTED = (
    "cardioauth.audit.service.record() is implemented in M1b (audit service with request "
    "context: actor, session, request id). The hash-chain primitives it will use are in "
    "cardioauth.audit.chain and are already tested."
)


def record(session: Any, entry: AuditEntry) -> bytes:  # pragma: no cover - M1b
    raise NotImplementedError(_NOT_IMPLEMENTED)


def record_denied(session: Any, *, action: str, object_type: str, **kwargs: Any) -> bytes:  # pragma: no cover - M1b
    raise NotImplementedError(_NOT_IMPLEMENTED)
