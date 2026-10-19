"""Local-filesystem BlobStore: the dev/test backend (§1.3).

It is a real backend, not a stand-in: real files, real fsync, real integrity checks — which is
what makes the shared contract suite meaningful when it runs against it. It is refused under
``CARDIOAUTH_ENV=production`` (:meth:`cardioauth.settings.Settings.storage_problems`) because a
container's local volume is not a managed, encrypted, backed-up, BAA-covered place to keep PHI.

Layout under ``BLOB_LOCAL_ROOT``::

    p/<practice hex>/<kind>/<blob hex>              the object bytes
    p/<practice hex>/<kind>/<blob hex>.meta.json    its metadata sidecar
    .tmp/<uuid>.part                                an in-flight upload

The key components are 32-character lower-case hex strings and a namespace name from a closed
set, so a path segment cannot be anything else (:mod:`cardioauth.blobs.keys`). The containment
check in :meth:`LocalBlobStore._path` is belt-and-braces on top of that construction, not the
thing that makes it safe.
"""

from __future__ import annotations

import json
import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import BinaryIO, Iterator

from cardioauth.blobs.base import (
    STREAM_CHUNK_BYTES,
    BlobMetadata,
    coerce_key,
    drain,
    validate_content_type,
    verifying_stream,
)
from cardioauth.blobs.errors import (
    BlobIntegrityError,
    BlobNotFound,
    BlobStoreError,
    BlobTooLarge,
    InvalidBlobKey,
)
from cardioauth.blobs.keys import BlobKey

_META_SUFFIX = ".meta.json"
_TMP_DIR = ".tmp"


class LocalBlobStore:
    """Objects on a filesystem, addressed only by :class:`BlobKey`."""

    name = "local"

    def __init__(
        self,
        root: str | Path,
        *,
        max_bytes: int,
        chunk_size: int = STREAM_CHUNK_BYTES,
        encryption_label: str = "none",
    ) -> None:
        self._root = Path(root).expanduser().resolve()
        self._max_bytes = max_bytes
        self._chunk_size = chunk_size
        self._encryption = encryption_label
        self._root.mkdir(parents=True, exist_ok=True)
        (self._root / _TMP_DIR).mkdir(parents=True, exist_ok=True)

    # --- paths ------------------------------------------------------------
    @property
    def root(self) -> Path:
        """The storage root. Exposed for backup tooling and tests; services never see it."""
        return self._root

    def _path(self, key: BlobKey) -> Path:
        path = self._root / "p" / key.practice_id.hex / key.kind / key.blob_id.hex
        # Belt and braces: the components are already hex/allowlisted, so this can only fire if
        # somebody changed the layout above or a symlink was planted inside the root.
        resolved = path.resolve()
        if resolved != self._root and self._root not in resolved.parents:
            raise InvalidBlobKey("resolved object path escapes the storage root")
        return path

    def _meta_path(self, path: Path) -> Path:
        return path.with_name(path.name + _META_SUFFIX)

    # --- interface --------------------------------------------------------
    def put(self, key: BlobKey | str, source: BinaryIO, *, content_type: str) -> BlobMetadata:
        key = coerce_key(key)
        content_type = validate_content_type(content_type)
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._root / _TMP_DIR / f"{uuid.uuid4().hex}.part"
        hasher = sha256()
        size = 0
        try:
            with open(tmp, "wb") as handle:
                for chunk in drain(source, chunk_size=self._chunk_size):
                    size += len(chunk)
                    if size > self._max_bytes:
                        raise BlobTooLarge(
                            f"object exceeds the {self._max_bytes}-byte per-document limit (§5.4)"
                        )
                    hasher.update(chunk)
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
            metadata = BlobMetadata(
                key=key,
                content_type=content_type,
                stored_byte_size=size,
                stored_sha256=hasher.hexdigest(),
                created_at=datetime.now(timezone.utc),
                encryption=self._encryption,
                backend=self.name,
            )
            # Atomic: a reader never sees a half-written object under its real key.
            os.replace(tmp, path)
            self._write_meta(path, metadata)
        finally:
            tmp.unlink(missing_ok=True)
        return metadata

    @contextmanager
    def open(self, key: BlobKey | str) -> Iterator[BinaryIO]:
        """Streaming read. The digest recorded at write time is verified at EOF."""
        key = coerce_key(key)
        path = self._path(key)
        if not path.is_file():
            raise BlobNotFound(f"no object at {key.namespace}")
        metadata = self._read_meta(path)
        handle = open(path, "rb")
        try:
            yield verifying_stream(
                handle,
                expected_sha256=metadata.stored_sha256,
                expected_size=metadata.stored_byte_size,
                what=f"object {key.namespace}",
            )
        finally:
            handle.close()

    def get(self, key: BlobKey | str) -> bytes:
        with self.open(key) as stream:
            return stream.read()

    def head(self, key: BlobKey | str) -> BlobMetadata:
        path = self._path(coerce_key(key))
        if not path.is_file():
            raise BlobNotFound(f"no object at {coerce_key(key).namespace}")
        return self._read_meta(path)

    def exists(self, key: BlobKey | str) -> bool:
        return self._path(coerce_key(key)).is_file()

    def delete(self, key: BlobKey | str) -> None:
        path = self._path(coerce_key(key))
        # Idempotent, like S3's DeleteObject: a retried cleanup must not fail on its second run.
        path.unlink(missing_ok=True)
        self._meta_path(path).unlink(missing_ok=True)

    # --- metadata sidecar -------------------------------------------------
    def _write_meta(self, path: Path, metadata: BlobMetadata) -> None:
        payload = json.dumps(metadata.to_json(), sort_keys=True).encode("utf-8")
        tmp = path.with_name(f"{path.name}{_META_SUFFIX}.{uuid.uuid4().hex}.tmp")
        try:
            with open(tmp, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._meta_path(path))
        finally:
            tmp.unlink(missing_ok=True)

    def _read_meta(self, path: Path) -> BlobMetadata:
        meta_path = self._meta_path(path)
        try:
            payload = json.loads(meta_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise BlobIntegrityError(
                "object exists without its metadata sidecar: the bytes cannot be verified, so "
                "they are not usable as clinical evidence"
            ) from exc
        except (OSError, ValueError) as exc:
            raise BlobStoreError(f"object metadata is unreadable: {type(exc).__name__}") from exc
        try:
            return BlobMetadata.from_json(payload)
        except (KeyError, TypeError, ValueError) as exc:
            raise BlobIntegrityError("object metadata is malformed") from exc


__all__ = ["LocalBlobStore"]
