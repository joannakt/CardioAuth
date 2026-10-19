"""The BlobStore boundary (§1.3): one interface, two real backends, three wrappers.

What a caller uses::

    store = get_blob_store(practice_id=case.practice_id, session_factory=SessionLocal,
                           audit=BlobAuditContext(actor_user_id=user.id, actor_role=role))
    metadata = store.put(key, upload_stream, content_type="application/pdf")
    with store.open(key) as stream:   # decrypted, integrity-checked
        ...
    store.export(key)                 # the "bytes left the system" event
    store.delete(key)

What a caller never sees: a filesystem path, a bucket key, a boto3 client, an encryption key,
or a way to build one from anything a user typed. Moving to HIPAA-eligible storage is
``BLOB_BACKEND=s3`` plus ``S3_*`` — a configuration change, not a code change.

Composition order (bottom to top)::

    LocalBlobStore | S3BlobStore | MemoryBlobStore     provider
      -> EncryptedBlobStore                            application-level envelope encryption
      -> AuditedBlobStore                              create/read/export/delete -> hash chain
      -> PracticeScopedBlobStore                       practice isolation, checked first

The scope wrapper is outermost so a cross-practice key is refused before anything is read,
audited or decrypted. The production guards run in the factory as well as at startup
(:meth:`cardioauth.settings.Settings.assert_storage_safe`), so a worker or a script cannot
build a backend the process should never have been allowed to select.
"""

from __future__ import annotations

import uuid
from typing import Any

from cardioauth.blobs.audit import AuditedBlobStore, BlobAuditContext
from cardioauth.blobs.base import (
    ALLOWED_CONTENT_TYPES,
    BlobMetadata,
    BlobStore,
    describe_metadata,
    validate_content_type,
)
from cardioauth.blobs.encrypted import EncryptedBlobStore
from cardioauth.blobs.envelope import ENCRYPTION_LABEL
from cardioauth.blobs.errors import (
    BlobAccessDenied,
    BlobBackendUnavailable,
    BlobIntegrityError,
    BlobNotFound,
    BlobStoreError,
    BlobTooLarge,
    InvalidBlobKey,
    InvalidContentType,
)
from cardioauth.blobs.keys import BLOB_KINDS, BlobKey
from cardioauth.blobs.local import LocalBlobStore
from cardioauth.blobs.memory import MemoryBlobStore
from cardioauth.blobs.scoped import PracticeScopedBlobStore
from cardioauth.settings import Settings, get_settings

__all__ = [
    "ALLOWED_CONTENT_TYPES",
    "BLOB_KINDS",
    "ENCRYPTION_LABEL",
    "AuditedBlobStore",
    "BlobAccessDenied",
    "BlobAuditContext",
    "BlobBackendUnavailable",
    "BlobIntegrityError",
    "BlobKey",
    "BlobMetadata",
    "BlobNotFound",
    "BlobStore",
    "BlobStoreError",
    "BlobTooLarge",
    "EncryptedBlobStore",
    "InvalidBlobKey",
    "InvalidContentType",
    "LocalBlobStore",
    "MemoryBlobStore",
    "PracticeScopedBlobStore",
    "describe_metadata",
    "get_blob_store",
    "validate_content_type",
]


def build_backend(settings: Settings, *, client: Any | None = None) -> BlobStore:
    """Build the configured provider, with no wrappers. Guards run first."""
    settings.assert_storage_safe()
    if settings.blob_backend == "local":
        return LocalBlobStore(settings.blob_local_root, max_bytes=settings.document_max_bytes)
    if settings.blob_backend == "memory":
        return MemoryBlobStore(max_bytes=settings.document_max_bytes)
    if settings.blob_backend == "s3":
        from cardioauth.blobs.s3 import S3BlobStore  # local import: boto3 only when needed

        return S3BlobStore(settings, client=client)
    # A Literal in Settings makes this unreachable without editing the type, which is the point.
    raise BlobBackendUnavailable(f"unknown BLOB_BACKEND {settings.blob_backend!r}")


def get_blob_store(
    settings: Settings | None = None,
    *,
    practice_id: uuid.UUID | None = None,
    session_factory: Any | None = None,
    audit: BlobAuditContext | None = None,
    client: Any | None = None,
) -> BlobStore:
    """The composed store.

    ``practice_id`` gives a request-scoped store that cannot address another practice's objects.
    ``session_factory`` turns on audit; without it the store is unaudited, which is only
    appropriate for tooling and tests — the application always passes one.
    """
    settings = settings or get_settings()
    store: BlobStore = build_backend(settings, client=client)
    if settings.blob_app_encryption:
        store = EncryptedBlobStore(
            store,
            settings=settings,
            max_bytes=settings.document_max_bytes,
            chunk_size=settings.blob_chunk_size_bytes,
        )
    if session_factory is not None:
        store = AuditedBlobStore(store, session_factory=session_factory, context=audit)
    if practice_id is not None:
        store = PracticeScopedBlobStore(store, practice_id=practice_id)
    return store
