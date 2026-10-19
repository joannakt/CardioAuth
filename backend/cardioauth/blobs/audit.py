"""Audited BlobStore wrapper: every create, read, export and delete reaches the hash chain.

§7.4 lists what an audit entry records and INV-5 forbids PHI in it. Storage events are recorded
**at the store boundary**, not only at the API boundary, because that is where the bytes
actually move: an OCR worker that reads a document, a cleanup job that deletes one and an
export that hands a PDF to a coordinator all touch the store, and a compliance reviewer needs
one place that shows all three.

Two rules this wrapper enforces rather than documents
-----------------------------------------------------
* **No object exists without an audit row.** If the ``blob.created`` write fails, the object is
  deleted again and the error is raised. An unaudited document is worse than a failed upload.
* **No read is served without an audit row.** If the audit write fails the read fails, because
  a read a practice cannot later account for is a disclosure it cannot account for.

The ``detail`` payload is :func:`cardioauth.blobs.base.describe_metadata` — backend, encryption
mode, namespace kind, blob id, content type, sizes and digests. Never a filename, never a byte
of the object, never a patient identifier: the key is PHI-free by construction, and the detail
is built from the key and from counts.
"""

from __future__ import annotations

import logging
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, BinaryIO, Callable, Iterator

from cardioauth.audit.chain import AuditEntry
from cardioauth.audit.service import record as audit_record
from cardioauth.blobs.base import BlobMetadata, BlobStore, coerce_key, describe_metadata
from cardioauth.blobs.errors import BlobIntegrityError
from cardioauth.blobs.keys import BlobKey

logger = logging.getLogger(__name__)

#: What a session factory has to look like: ``sessionmaker(bind=engine)`` and anything with the
#: same shape. Kept as a Protocol-free callable so this module does not import SQLAlchemy.
SessionFactory = Callable[[], Any]


@dataclass(frozen=True)
class BlobAuditContext:
    """Who is doing this, for the audit columns. Ids and a role name only — never a name."""

    practice_id: uuid.UUID | None = None
    actor_user_id: uuid.UUID | None = None
    actor_role: str | None = None
    request_id: str | None = None
    case_id: uuid.UUID | None = None


class AuditedBlobStore:
    """Wraps a store and appends one audit entry per storage event."""

    def __init__(
        self,
        inner: BlobStore,
        *,
        session_factory: SessionFactory,
        context: BlobAuditContext | None = None,
    ) -> None:
        self._inner = inner
        self._session_factory = session_factory
        self._context = context or BlobAuditContext()
        self.name = inner.name

    # --- audit plumbing ---------------------------------------------------
    def _detail(self, key: BlobKey, metadata: BlobMetadata | None) -> dict[str, Any]:
        if metadata is None:
            return {"backend": self.name, "kind": key.kind, "blob_id": str(key.blob_id)}
        return dict(describe_metadata(metadata))

    def _record(
        self,
        action: str,
        *,
        key: BlobKey,
        metadata: BlobMetadata | None = None,
        outcome: str = "success",
        reason: str | None = None,
    ) -> None:
        detail = self._detail(key, metadata)
        if reason is not None:
            detail["reason"] = reason
        entry = AuditEntry(
            action=action,
            object_type="blob",
            outcome=outcome,
            practice_id=self._context.practice_id or key.practice_id,
            actor_user_id=self._context.actor_user_id,
            actor_role=self._context.actor_role,
            object_id=key.blob_id,
            case_id=self._context.case_id,
            request_id=self._context.request_id,
            detail=detail,
        )
        with self._session_factory() as session:
            audit_record(session, entry)
            session.commit()

    # --- interface --------------------------------------------------------
    def put(self, key: BlobKey | str, source: BinaryIO, *, content_type: str) -> BlobMetadata:
        metadata = self._inner.put(key, source, content_type=content_type)
        try:
            self._record("blob.created", key=metadata.key, metadata=metadata)
        except Exception:
            # Fail closed: an object that cannot be accounted for must not stay in the store.
            try:
                self._inner.delete(metadata.key)
            except Exception:  # pragma: no cover - a delete failure after a failed audit
                logger.error(
                    "blob.audit_rollback_failed",
                    extra={"blob_id": str(metadata.key.blob_id), "kind": metadata.key.kind},
                )
            raise
        return metadata

    @contextmanager
    def open(self, key: BlobKey | str) -> Iterator[BinaryIO]:
        key = coerce_key(key)
        metadata = self._inner.head(key)
        self._record("blob.read", key=key, metadata=metadata)
        try:
            with self._inner.open(key) as stream:
                yield stream
        except BlobIntegrityError as exc:
            # Corruption under a citation is a compliance event, not a 500: record it, then
            # let the caller refuse to use the bytes as evidence (§2.4).
            self._record(
                "blob.integrity_failed",
                key=key,
                metadata=metadata,
                outcome="failure",
                reason=type(exc).__name__,
            )
            raise

    def get(self, key: BlobKey | str) -> bytes:
        key = coerce_key(key)
        metadata = self._inner.head(key)
        self._record("blob.read", key=key, metadata=metadata)
        try:
            return self._inner.get(key)
        except BlobIntegrityError as exc:
            self._record(
                "blob.integrity_failed",
                key=key,
                metadata=metadata,
                outcome="failure",
                reason=type(exc).__name__,
            )
            raise

    def export(self, key: BlobKey | str) -> bytes:
        """Read for delivery to a human (a download or an exported letter). Its own action,
        because "the bytes left the system" is the event a disclosure log is about."""
        key = coerce_key(key)
        metadata = self._inner.head(key)
        payload = self._inner.get(key)
        self._record("blob.exported", key=key, metadata=metadata)
        return payload

    def head(self, key: BlobKey | str) -> BlobMetadata:
        # Metadata-only lookups are not disclosures and are not recorded; recording them would
        # bury the events that matter (§7.4 rationale for not logging allowed requests).
        return self._inner.head(coerce_key(key))

    def exists(self, key: BlobKey | str) -> bool:
        return self._inner.exists(coerce_key(key))

    def delete(self, key: BlobKey | str) -> None:
        key = coerce_key(key)
        # Capture what is about to be destroyed *before* destroying it: a deletion entry that
        # cannot say what was deleted is not much of an audit record.
        metadata = self._safe_head(key)
        self._inner.delete(key)
        self._record("blob.deleted", key=key, metadata=metadata)

    def _safe_head(self, key: BlobKey) -> BlobMetadata | None:
        try:
            return self._inner.head(key)
        except Exception:
            return None

    @property
    def inner(self) -> BlobStore:
        return self._inner


__all__ = ["AuditedBlobStore", "BlobAuditContext", "SessionFactory"]
