"""The BlobStore boundary (§1.3): one interface, no caller ever touching a path or a bucket key.

Design rules encoded here
-------------------------
* **Opaque keys.** Every method takes a :class:`cardioauth.blobs.keys.BlobKey`, never a path,
  a bucket key, a filename or a URL. Moving to HIPAA-eligible storage is therefore a
  configuration change (``BLOB_BACKEND=s3`` + ``S3_*``), not a code change.
* **Streaming both ways.** ``put`` consumes a binary stream and ``open`` yields one, so a 50 MB
  scan is never held in memory as one ``bytes`` object. ``get`` exists for the small-object
  cases (a page image, an exported letter) and is defined in terms of ``open``.
* **Integrity is checked, not assumed.** The sha256 and size recorded at write time are
  verified on read; a mismatch raises :class:`BlobIntegrityError` rather than handing corrupted
  bytes to extraction (§2.4 — a citation points at specific pixels forever).
* **Limits are enforced mid-stream** and leave nothing behind (§5.4).

What the interface deliberately does *not* expose: a filesystem path, a bucket name, a
pre-signed URL, a boto3 client, or a way to enumerate a namespace. Those are provider details;
a caller that needs one of them is a caller that has stopped being provider-agnostic.
"""

from __future__ import annotations

import hashlib
import io
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, BinaryIO, Protocol, runtime_checkable

from cardioauth.blobs.errors import BlobIntegrityError, InvalidContentType
from cardioauth.blobs.keys import BlobKey, coerce_key

#: Content types the store will accept. It is written into object metadata and into the audit
#: ``detail``, and later drives the OCR backend's choice, so it is an allowlist rather than a
#: free-text field (§5.1). A type not here is a bug in the caller, not a policy decision to
#: make at runtime.
ALLOWED_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "application/pdf",
        "image/png",
        "image/jpeg",
        "image/tiff",
        "image/webp",
        "image/heic",
        "text/plain",
    }
)

#: Streaming read/write chunk. 64 KiB: one AES-GCM record per chunk for the envelope layer,
#: and small enough that a slow client cannot pin a large buffer.
STREAM_CHUNK_BYTES = 64 * 1024


def validate_content_type(value: str) -> str:
    """Return the content type, or refuse it. Canonical form only (no parameters, no case
    variants), so what is stored is what was checked."""
    if not isinstance(value, str):
        raise InvalidContentType(f"content_type must be a str, not {type(value).__name__}")
    if value not in ALLOWED_CONTENT_TYPES:
        # The value is echoed here on purpose: a content type is not PHI and a caller needs to
        # see the typo. It is length-bounded so a caller cannot smuggle a payload into a log.
        raise InvalidContentType(
            f"content_type {value[:80]!r} is not an allowed type; allowed: "
            + ", ".join(sorted(ALLOWED_CONTENT_TYPES))
        )
    return value


@dataclass(frozen=True)
class BlobMetadata:
    """What the store knows about one object.

    Two sizes and two digests, because an encrypted store has two different truths and
    conflating them would make an integrity check meaningless:

    * ``stored_byte_size`` / ``stored_sha256`` — the bytes actually at rest (ciphertext when
      application-level envelope encryption is on);
    * ``plaintext_byte_size`` / ``plaintext_sha256`` — the bytes the caller wrote and reads
      back. These are what ``document.byte_size`` and ``document.sha256`` record (§2.4) and
      what the caller's own dedupe check uses.

    ``plaintext_*`` is ``None`` when the store cannot know it without reading the object — an
    encrypted object keeps its plaintext length and digest inside the authenticated trailer,
    so :meth:`BlobStore.head` reports ``None`` there and :meth:`BlobStore.get` /
    :meth:`BlobStore.open` verify them. The :attr:`byte_size` and :attr:`sha256` properties
    fall back to the stored values so a caller that only wants "how big is this thing" is not
    forced to care.
    """

    key: BlobKey
    content_type: str
    stored_byte_size: int
    stored_sha256: str
    created_at: datetime
    encryption: str
    backend: str
    plaintext_byte_size: int | None = None
    plaintext_sha256: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def byte_size(self) -> int:
        return self.plaintext_byte_size if self.plaintext_byte_size is not None else self.stored_byte_size

    @property
    def sha256(self) -> str:
        return self.plaintext_sha256 or self.stored_sha256

    def with_plaintext(self, *, byte_size: int, sha256: str) -> BlobMetadata:
        return replace(self, plaintext_byte_size=byte_size, plaintext_sha256=sha256)

    def to_json(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["key"] = self.key.namespace
        payload["created_at"] = self.created_at.astimezone(timezone.utc).isoformat()
        return payload

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> BlobMetadata:
        data = dict(payload)
        data["key"] = BlobKey.parse(data["key"])
        created = data["created_at"]
        data["created_at"] = created if isinstance(created, datetime) else datetime.fromisoformat(created)
        if data["created_at"].tzinfo is None:  # never store a naive timestamp
            data["created_at"] = data["created_at"].replace(tzinfo=timezone.utc)
        return cls(**data)


@runtime_checkable
class BlobStore(Protocol):
    """Opaque object storage. Two implementations (local filesystem, S3-compatible) and any
    number of transparent wrappers (envelope encryption, practice scope, audit) implement it."""

    #: Short provider name for logs and audit detail: ``local``, ``s3``, ``memory``.
    name: str

    def put(self, key: BlobKey | str, source: BinaryIO, *, content_type: str) -> BlobMetadata:
        """Stream ``source`` into the object at ``key`` and return its metadata.

        Consumes the stream to EOF. Raises :class:`BlobTooLarge` mid-stream if the object
        exceeds the configured limit, in which case nothing is stored.
        """

    def open(self, key: BlobKey | str) -> AbstractContextManager[BinaryIO]:
        """Open a streaming reader. The bytes are integrity-checked as they are read; a
        truncated or tampered object raises :class:`BlobIntegrityError` at EOF."""

    def get(self, key: BlobKey | str) -> bytes:
        """Read the whole object (small objects only). Integrity-checked."""

    def head(self, key: BlobKey | str) -> BlobMetadata:
        """Metadata without reading the object. Raises :class:`BlobNotFound`."""

    def exists(self, key: BlobKey | str) -> bool: ...

    def delete(self, key: BlobKey | str) -> None:
        """Delete the object. Idempotent: deleting a key that is not there is not an error, so
        a retried cleanup job cannot fail on its second run."""


class ChecksumVerifyingReader(io.RawIOBase):
    """A binary reader that verifies size and sha256 as it streams.

    Used by every backend, so "the bytes I got back are the bytes that were written" is a
    property of the interface rather than of one provider. Verification happens at EOF: a
    caller that stops reading early has not verified anything, which is why ``get`` reads to
    EOF and ``open`` documents that the check lands on the last read.
    """

    def __init__(
        self,
        source: BinaryIO,
        *,
        expected_sha256: str,
        expected_size: int | None = None,
        what: str = "object",
    ) -> None:
        super().__init__()
        self._source = source
        self._expected_sha256 = expected_sha256.lower()
        self._expected_size = expected_size
        self._hasher = hashlib.sha256()
        self._size = 0
        self._verified = False
        self._what = what

    def readable(self) -> bool:  # pragma: no cover - trivial
        return True

    def readinto(self, buffer: Any) -> int:
        data = self._source.read(len(buffer))
        if not data:
            self._verify()
            return 0
        self._hasher.update(data)
        self._size += len(data)
        buffer[: len(data)] = data
        return len(data)

    def _verify(self) -> None:
        if self._verified:
            return
        self._verified = True
        if self._expected_size is not None and self._size != self._expected_size:
            raise BlobIntegrityError(
                f"{self._what} is {self._size} bytes but {self._expected_size} were written: "
                "the object is truncated or was replaced"
            )
        actual = self._hasher.hexdigest()
        if actual != self._expected_sha256:
            raise BlobIntegrityError(
                f"{self._what} failed its integrity check (sha256 {actual[:12]}… != "
                f"{self._expected_sha256[:12]}…): the stored bytes are not the bytes that were "
                "written"
            )

    def close(self) -> None:
        try:
            self._source.close()
        finally:
            super().close()


def verifying_stream(
    source: BinaryIO,
    *,
    expected_sha256: str,
    expected_size: int | None = None,
    what: str = "object",
) -> BinaryIO:
    """Wrap ``source`` in the verifying reader plus a buffer, so callers get ordinary
    ``read(n)`` / ``readline()`` semantics over a stream whose digest is checked at EOF."""
    return io.BufferedReader(
        ChecksumVerifyingReader(
            source,
            expected_sha256=expected_sha256,
            expected_size=expected_size,
            what=what,
        ),
        buffer_size=STREAM_CHUNK_BYTES,
    )


@contextmanager
def read_all(store: BlobStore, key: BlobKey | str) -> Iterator[bytes]:
    """``get`` in terms of ``open``, so there is exactly one read path to keep correct."""
    with store.open(key) as stream:
        yield stream.read()


@contextmanager
def read_all(store: BlobStore, key: BlobKey | str) -> Iterator[bytes]:
    """``get`` in terms of ``open``, so there is exactly one read path to keep correct."""
    with store.open(key) as stream:
        yield stream.read()


def drain(source: BinaryIO, *, chunk_size: int = STREAM_CHUNK_BYTES) -> Iterator[bytes]:
    """Yield a stream in chunks until EOF. The one loop every ``put`` is built on."""
    while True:
        chunk = source.read(chunk_size)
        if not chunk:
            return
        yield chunk


def describe_metadata(metadata: BlobMetadata) -> dict[str, str | int]:
    """The PHI-free projection of metadata used for audit ``detail`` and structured logs.

    Ids, sizes, digests and codes only — never a filename, never a byte of the object (INV-5).
    """
    return {
        "backend": metadata.backend,
        "encryption": metadata.encryption,
        "kind": metadata.key.kind,
        "blob_id": str(metadata.key.blob_id),
        "content_type": metadata.content_type,
        "byte_size": metadata.byte_size,
        "stored_byte_size": metadata.stored_byte_size,
        "sha256": metadata.sha256,
    }


__all__ = [
    "ALLOWED_CONTENT_TYPES",
    "STREAM_CHUNK_BYTES",
    "BlobMetadata",
    "BlobStore",
    "ChecksumVerifyingReader",
    "coerce_key",
    "describe_metadata",
    "drain",
    "read_all",
    "validate_content_type",
    "verifying_stream",
]
