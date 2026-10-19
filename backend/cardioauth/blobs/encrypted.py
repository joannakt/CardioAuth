"""Envelope-encryption wrapper: seals every object before the backend ever sees it.

A transparent :class:`~cardioauth.blobs.base.BlobStore`: same methods, same errors, same
metadata — plus ciphertext at rest. Composition is the point; the backends know nothing about
encryption and the services know nothing about either.

What the caller sees
--------------------
``put`` returns metadata whose ``plaintext_byte_size`` and ``plaintext_sha256`` are the bytes
the caller wrote (what ``document.byte_size`` / ``document.sha256`` record, §2.4), while
``stored_byte_size`` / ``stored_sha256`` describe the ciphertext. ``head`` cannot know the
plaintext digest without reading the object — it is inside the authenticated trailer — so it
reports ``None`` for those two fields and says so in the docstring. ``get`` and ``open`` verify
the plaintext length and digest against that trailer as they stream.

The size limit is enforced on the plaintext *before* the backend is called, so an oversized
upload never reaches the provider and never leaves a partial object behind (§5.4).
"""

from __future__ import annotations

import tempfile
from contextlib import contextmanager
from dataclasses import replace
from typing import Any, BinaryIO, Iterator

from cardioauth.blobs.base import BlobMetadata, BlobStore, coerce_key
from cardioauth.blobs.envelope import (
    ENCRYPTION_LABEL,
    blob_kek,
    encrypt_stream,
    open_envelope,
)
from cardioauth.blobs.keys import BlobKey
from cardioauth.settings import Settings

#: Spool threshold. Under 8 MiB the sealed object stays in memory; above it, in a temp file
#: that is removed when the block exits. Either way the caller's stream is consumed once.
SPOOL_MAX_MEMORY_BYTES = 8 * 1024 * 1024


class EncryptedBlobStore:
    """Wraps any BlobStore, adding application-level envelope encryption (§1.3)."""

    def __init__(
        self,
        inner: BlobStore,
        *,
        settings: Settings | None = None,
        kek: bytes | None = None,
        max_bytes: int | None = None,
        chunk_size: int | None = None,
    ) -> None:
        self._inner = inner
        self._kek = kek if kek is not None else blob_kek(settings)
        self._max_bytes = max_bytes
        self._chunk_size = chunk_size or (settings.blob_chunk_size_bytes if settings else 64 * 1024)
        self.name = inner.name
        self.encryption = ENCRYPTION_LABEL

    def put(self, key: BlobKey | str, source: BinaryIO, *, content_type: str) -> BlobMetadata:
        key = coerce_key(key)
        with tempfile.SpooledTemporaryFile(max_size=SPOOL_MAX_MEMORY_BYTES) as spool:
            info = encrypt_stream(
                source,
                spool,
                kek=self._kek,
                chunk_size=self._chunk_size,
                max_bytes=self._max_bytes,
            )
            spool.seek(0)
            stored = self._inner.put(key, spool, content_type=content_type)
        return replace(
            stored,
            encryption=ENCRYPTION_LABEL,
            plaintext_byte_size=info.plaintext_byte_size,
            plaintext_sha256=info.plaintext_sha256,
        )

    @contextmanager
    def open(self, key: BlobKey | str) -> Iterator[BinaryIO]:
        """Decrypting stream. Truncation, reordering, splicing and a wrong ``APP_KEY`` all
        raise :class:`~cardioauth.blobs.errors.BlobIntegrityError`."""
        with self._inner.open(coerce_key(key)) as raw:
            stream = open_envelope(raw, kek=self._kek)
            try:
                yield stream
            finally:
                stream.close()

    def get(self, key: BlobKey | str) -> bytes:
        with self.open(key) as stream:
            return stream.read()

    def head(self, key: BlobKey | str) -> BlobMetadata:
        """Metadata without reading the object.

        ``plaintext_byte_size`` / ``plaintext_sha256`` are ``None`` here: they live in the
        object's authenticated trailer, and reporting a value this method did not verify would
        be a lie the caller could rely on. Read the object (``get``/``open``) to verify them.
        """
        return replace(self._inner.head(coerce_key(key)), encryption=ENCRYPTION_LABEL)

    def exists(self, key: BlobKey | str) -> bool:
        return self._inner.exists(coerce_key(key))

    def delete(self, key: BlobKey | str) -> None:
        self._inner.delete(coerce_key(key))

    # --- extras that make the wrapper usable in tests and tooling ----------
    @property
    def inner(self) -> BlobStore:
        return self._inner

    def __getattr__(self, item: Any) -> Any:  # pragma: no cover - narrow delegation
        # Only reached for attributes this wrapper does not define (e.g. a backend's
        # ensure_bucket in an admin script). Never used on the request path.
        return getattr(self._inner, item)


__all__ = ["EncryptedBlobStore", "SPOOL_MAX_MEMORY_BYTES"]
