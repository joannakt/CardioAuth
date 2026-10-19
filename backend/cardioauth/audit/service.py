"""Audit service — the only supported way to write ``cardioauth_audit.audit_log``.

``record(session, entry)`` appends a chained row inside the caller's transaction: the audit
row commits if and only if the action it describes commits, so the log cannot claim
something that was rolled back, and a failed write cannot lose the record of an attempt.
Callers that must log a failure *and* keep the transaction alive (a rejected login, say)
call ``record`` and then commit or roll back deliberately.

Two screens run before the row is written:

* the action must be in the closed vocabulary (:mod:`cardioauth.audit.actions`), and
* the PHI-key screen in :mod:`cardioauth.audit.chain` rejects a ``detail`` key that names a
  PHI field. That screen also rejects the keys this milestone might be tempted to use —
  ``email`` and anything containing ``name`` — which is exactly why the auth events carry
  ``user_id`` and reason codes instead of the address that was typed in.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

from cardioauth.audit.actions import ALL_ACTIONS, AUTH_ACTIONS
from cardioauth.audit.chain import AuditChainError, AuditEntry, append_entry


def _connection(session: Any) -> Connection:
    """Accept a Session (normal case) or an already-open Connection (scripts, fixtures)."""
    if isinstance(session, Connection):
        return session
    if isinstance(session, Session):
        return session.connection()
    connection = getattr(session, "connection", None)
    if callable(connection):  # a Session-like object from a test double
        return connection()
    raise TypeError("audit.record() needs a SQLAlchemy Session or Connection")


def record(session: Any, entry: AuditEntry) -> bytes:
    """Append one audit entry to the hash chain. Returns the entry hash."""
    if entry.action not in ALL_ACTIONS:
        raise AuditChainError(
            f"audit action {entry.action!r} is not in the closed vocabulary "
            "(cardioauth.audit.actions); add it there deliberately, never inline"
        )
    return append_entry(_connection(session), entry)


def record_auth(session: Any, entry: AuditEntry) -> bytes:
    """``record`` for the authentication events, with the vocabulary enforced."""
    if entry.action not in AUTH_ACTIONS:
        raise AuditChainError(f"{entry.action!r} is not an auth action (cardioauth.audit.actions)")
    return record(session, entry)


def record_denied(session: Any, *, action: str, object_type: str, **kwargs: Any) -> bytes:
    """A refused action (RBAC denial, failed step-up). Always ``outcome='denied'`` (§7.3)."""
    return record(session, AuditEntry(action=action, object_type=object_type, outcome="denied", **kwargs))


__all__ = ["record", "record_auth", "record_denied"]
