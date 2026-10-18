"""BlobStore boundary (§1.3). Implementations arrive in M2 (local + S3).

The seam exists now so that document storage can move to HIPAA-eligible infrastructure
without touching any service: swap ``BLOB_BACKEND`` and provide the ``S3_*`` variables.
"""

from __future__ import annotations

from typing import BinaryIO, Protocol, runtime_checkable

from cardioauth.settings import Settings, get_settings


@runtime_checkable
class BlobStore(Protocol):
    """Opaque, content-addressed object storage. Keys are opaque strings; nothing in the
    application may construct a filesystem path from user input."""

    def put(self, key: str, data: BinaryIO, *, content_type: str) -> str: ...

    def get(self, key: str) -> bytes: ...

    def delete(self, key: str) -> None: ...

    def exists(self, key: str) -> bool: ...


def get_blob_store(settings: Settings | None = None) -> BlobStore:  # pragma: no cover - M2
    settings = settings or get_settings()
    raise NotImplementedError(
        f"BlobStore backend '{settings.blob_backend}' is implemented in M2 "
        "(LocalBlobStore for dev, S3BlobStore for HIPAA-eligible production storage). "
        "No implementation is wired yet, by design: nothing may silently succeed here."
    )
