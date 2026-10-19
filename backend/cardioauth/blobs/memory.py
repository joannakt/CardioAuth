"""In-process BlobStore: the dev/mock backend the production guard exists to refuse.

It exists for one honest reason: CI and unit tests that need *a* store without touching a
filesystem, and a local demo that should not leave files behind. It is the backend the
production guard is aimed at, and ``tests/test_blob_production_guards.py`` asserts both halves
of that sentence — production refuses it, dev accepts it — so the guard is proven to be a guard
rather than a blanket refusal.

It behaves like the real backends: same limits, same integrity checks, same metadata, same
idempotent delete. That is deliberate — a mock that behaves differently is a mock that lets a
bug through.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
from typing import BinaryIO, Iterator

from cardioauth.blobs.base import (
    STREAM_CHUNK_BYTES,
    BlobMetadata,
    coerce_key,
    drain,
    validate_content_type,
    verifying_stream,
)
from cardioauth.blobs.errors import BlobIntegrityError, BlobNotFound, BlobTooLarge
from cardioauth.blobs.keys import BlobKey


class MemoryBlobStore:
    """Objects in a dict. Lost on restart, which is exactly why production refuses it."""

    name = "memory"

    def __init__(
        self,
        *,
        max_bytes: int,
        chunk_size: int = STREAM_CHUNK_BYTES,
        encryption_label: str = "none",
    ) -> None:
        self._max_bytes = max_bytes
        self._chunk_size = chunk_size
        self._encryption = encryption_label
        self._objects: dict[str, tuple[bytes, BlobMetadata]] = {}

    def put(self, key: BlobKey | str, source: BinaryIO, *, content_type: str) -> BlobMetadata:
        key = coerce_key(key)
        content_type = validate_content_type(content_type)
        buffer = bytearray()
        hasher = sha256()
        for chunk in drain(source, chunk_size=self._chunk_size):
            if len(buffer) + len(chunk) > self._max_bytes:
                raise BlobTooLarge(
                    f"object exceeds the {self._max_bytes}-byte per-document limit (§5.4)"
                )
            buffer.extend(chunk)
            hasher.update(chunk)
        payload = bytes(buffer)
        metadata = BlobMetadata(
            key=key,
            content_type=content_type,
            stored_byte_size=len(payload),
            stored_sha256=hasher.hexdigest(),
            created_at=datetime.now(timezone.utc),
            encryption=self._encryption,
            backend=self.name,
        )
        self._objects[key.namespace] = (payload, metadata)
        return metadata

    @contextmanager
    def open(self, key: BlobKey | str) -> Iterator[BinaryIO]:
        key = coerce_key(key)
        try:
            payload, metadata = self._objects[key.namespace]
        except KeyError as exc:
            raise BlobNotFound(f"no object at {key.namespace}") from exc
        stream = BytesIO(payload)
        try:
            yield verifying_stream(
                stream,
                expected_sha256=metadata.stored_sha256,
                expected_size=metadata.stored_byte_size,
                what=f"object {key.namespace}",
            )
        finally:
            stream.close()

    def get(self, key: BlobKey | str) -> bytes:
        with self.open(key) as stream:
            return stream.read()

    def head(self, key: BlobKey | str) -> BlobMetadata:
        key = coerce_key(key)
        try:
            return self._objects[key.namespace][1]
        except KeyError as exc:
            raise BlobNotFound(f"no object at {key.namespace}") from exc

    def exists(self, key: BlobKey | str) -> bool:
        return coerce_key(key).namespace in self._objects

    def delete(self, key: BlobKey | str) -> None:
        self._objects.pop(coerce_key(key).namespace, None)

    # --- test support (never used by the application) ---------------------
    def corrupt(self, key: BlobKey | str, *, mutate: str = "flip") -> None:
        """Damage the stored bytes without touching the metadata, to prove reads verify.

        A test helper, named as one. It lives here rather than in the test file so the
        contract suite can express "tampered object" for every backend in the same way.
        """
        key = coerce_key(key)
        payload, metadata = self._objects[key.namespace]
        if not payload:
            raise BlobIntegrityError("cannot corrupt an empty object")
        damaged = bytes([payload[0] ^ 0xFF]) + payload[1:]
        self._objects[key.namespace] = (damaged, metadata)


__all__ = ["MemoryBlobStore"]
