"""The audit hash chain (§2.9, §7.5).

Design rule  **entry_hash = sha256(canonical_json(row without entry_hash) || prev_hash)**,
with ``prev_hash`` = the previous row's ``entry_hash`` (32 zero bytes for the first row).

The canonical form is defined here, once, and used by both the writer (M1b's
``audit_service``, and :func:`append_entry` below) and the verifier
(``scripts/audit_chain_verify.py``), so the chain cannot disagree with itself.

Constraints on ``detail`` (documented, enforced by :func:`canonical_payload`): only
strings, integers, booleans, ``None``, and lists/dicts of those. Never PHI values —
ids, counts, field names and codes only (INV-5).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

GENESIS_PREV_HASH = b"\x00" * 32
HASH_LEN = 32

ALLOWED_DETAIL_TYPES = (str, int, bool, type(None))


class AuditChainError(RuntimeError):
    """The audit chain is broken (tampering, deletion or a writer bug)."""


@dataclass(frozen=True)
class AuditEntry:
    action: str
    object_type: str
    outcome: str = "success"
    practice_id: uuid.UUID | None = None
    actor_user_id: uuid.UUID | None = None
    actor_role: str | None = None
    object_id: uuid.UUID | None = None
    case_id: uuid.UUID | None = None
    request_id: str | None = None
    session_id: uuid.UUID | None = None
    occurred_at: datetime | None = None
    detail: dict[str, Any] = field(default_factory=dict)


def _validate_detail(value: Any, path: str = "detail") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AuditChainError(f"{path}: audit detail keys must be strings")
            _validate_detail(item, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_detail(item, f"{path}[{index}]")
        return
    if isinstance(value, tuple(ALLOWED_DETAIL_TYPES)) and not isinstance(value, float):
        return
    raise AuditChainError(
        f"{path}: audit detail may only contain str/int/bool/None (got {type(value).__name__}); "
        "never PHI values (INV-5)"
    )


def _ts(value: datetime | None) -> str:
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _uid(value: uuid.UUID | str | None) -> str | None:
    return None if value is None else str(value)


def canonical_payload(
    *,
    occurred_at: datetime | str,
    practice_id: uuid.UUID | str | None,
    actor_user_id: uuid.UUID | str | None,
    actor_role: str | None,
    action: str,
    object_type: str,
    object_id: uuid.UUID | str | None,
    case_id: uuid.UUID | str | None,
    outcome: str,
    detail: dict[str, Any],
    request_id: str | None,
    session_id: uuid.UUID | str | None,
) -> bytes:
    """Deterministic bytes for one audit row (excludes id and entry_hash)."""
    if isinstance(occurred_at, str):
        occurred_at = datetime.fromisoformat(occurred_at)
    _validate_detail(detail)
    body = {
        "action": action,
        "actor_role": actor_role,
        "actor_user_id": _uid(actor_user_id),
        "case_id": _uid(case_id),
        "detail": detail,
        "object_id": _uid(object_id),
        "object_type": object_type,
        "occurred_at": _ts(occurred_at),
        "outcome": outcome,
        "practice_id": _uid(practice_id),
        "request_id": request_id,
        "session_id": _uid(session_id),
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_entry_hash(payload: bytes, prev_hash: bytes) -> bytes:
    return hashlib.sha256(payload + prev_hash).digest()


def row_payload_from_db(row: dict[str, Any]) -> bytes:
    return canonical_payload(
        occurred_at=row["occurred_at"],
        practice_id=row["practice_id"],
        actor_user_id=row["actor_user_id"],
        actor_role=row["actor_role"],
        action=row["action"],
        object_type=row["object_type"],
        object_id=row["object_id"],
        case_id=row["case_id"],
        outcome=row["outcome"],
        detail=row["detail"] or {},
        request_id=row["request_id"],
        session_id=row["session_id"],
    )


_AUDIT_COLUMNS = (
    "occurred_at, practice_id, actor_user_id, actor_role, action, object_type, "
    "object_id, case_id, outcome, detail, request_id, session_id, prev_hash, entry_hash"
)


def append_entry(conn: Any, entry: AuditEntry) -> bytes:
    """Append one chained row inside the caller's transaction and return its hash.

    Serialises on the last row (``SELECT ... ORDER BY id DESC LIMIT 1 FOR SHARE``) so two
    concurrent writers cannot fork the chain.
    """
    occurred_at = entry.occurred_at or datetime.now(timezone.utc)
    last = conn.exec_driver_sql(
        "SELECT entry_hash FROM cardioauth_audit.audit_log ORDER BY id DESC LIMIT 1 FOR SHARE"
    ).fetchone()
    prev_hash = bytes(last[0]) if last else GENESIS_PREV_HASH
    payload = canonical_payload(
        occurred_at=occurred_at,
        practice_id=entry.practice_id,
        actor_user_id=entry.actor_user_id,
        actor_role=entry.actor_role,
        action=entry.action,
        object_type=entry.object_type,
        object_id=entry.object_id,
        case_id=entry.case_id,
        outcome=entry.outcome,
        detail=entry.detail,
        request_id=entry.request_id,
        session_id=entry.session_id,
    )
    entry_hash = compute_entry_hash(payload, prev_hash)
    conn.exec_driver_sql(
        f"INSERT INTO cardioauth_audit.audit_log ({_AUDIT_COLUMNS}) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            occurred_at,
            entry.practice_id,
            entry.actor_user_id,
            entry.actor_role,
            entry.action,
            entry.object_type,
            entry.object_id,
            entry.case_id,
            entry.outcome,
            json.dumps(entry.detail, sort_keys=True, ensure_ascii=False),
            entry.request_id,
            entry.session_id,
            prev_hash,
            entry_hash,
        ),
    )
    return entry_hash


def verify_chain(conn: Any, *, limit: int | None = None) -> tuple[int, int]:
    """Walk the chain. Returns ``(rows_checked, last_id)`` or raises :class:`AuditChainError`."""
    sql = f"SELECT id, {_AUDIT_COLUMNS} FROM cardioauth_audit.audit_log ORDER BY id ASC"
    if limit:
        sql += f" LIMIT {int(limit)}"
    prev_hash = GENESIS_PREV_HASH
    rows_checked = 0
    last_id = 0
    for row in conn.exec_driver_sql(sql).mappings():
        payload = row_payload_from_db(dict(row))
        expected = compute_entry_hash(payload, prev_hash)
        if bytes(row["prev_hash"]) != prev_hash:
            raise AuditChainError(
                f"audit row id={row['id']}: prev_hash does not match the previous entry_hash "
                "(a row was deleted, inserted out of order or rewritten)"
            )
        if bytes(row["entry_hash"]) != expected:
            raise AuditChainError(
                f"audit row id={row['id']}: entry_hash does not match its contents "
                "(the row was modified after it was written)"
            )
        prev_hash = bytes(row["entry_hash"])
        rows_checked += 1
        last_id = row["id"]
    return rows_checked, last_id


def _iter_rows(rows: Iterable[dict[str, Any]]) -> Sequence[dict[str, Any]]:
    return list(rows)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI: verify the audit chain; non-zero exit when it is broken (§2.9, M1 acceptance 4)."""
    parser = argparse.ArgumentParser(description="Verify the CardioAuth audit hash chain.")
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL"), help="SQLAlchemy URL")
    parser.add_argument("--limit", type=int, default=None, help="verify only the first N rows")
    args = parser.parse_args(argv)

    from sqlalchemy import create_engine  # local import keeps the module import-light

    from cardioauth.settings import get_settings

    url = args.database_url or get_settings().database_url
    engine = create_engine(url)
    with engine.connect() as conn:
        try:
            checked, last_id = verify_chain(conn, limit=args.limit)
        except AuditChainError as exc:
            print(f"AUDIT CHAIN INVALID: {exc}", file=sys.stderr)
            return 1
    print(f"audit chain OK: {checked} row(s) verified, last id={last_id}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
