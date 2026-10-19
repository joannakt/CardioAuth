"""Envelope encryption for objects at rest (§1.3 "encryption at rest", INV-5).

Why application-level encryption on top of the provider's
---------------------------------------------------------
The design's production storage is S3 with server-side encryption (SSE-KMS) and a BAA. That
protects the *volume* — but only for as long as the provider's configuration stays right, and
not at all for the dev filesystem, a misconfigured bucket, a restored backup, or an operator
who can read the bucket. So this layer is **additional, not a replacement**:

* the production guard still requires server-side encryption
  (:meth:`cardioauth.settings.Settings.storage_problems`), and
* every object is *also* sealed with a key derived from ``APP_KEY`` before it reaches the
  backend, so a bucket listing, a stray copy of the data volume, or a provider-side mistake
  yields ciphertext rather than cardiology reports.

Envelope, not a single key
--------------------------
A fresh 256-bit data-encryption key (DEK) is generated per object and sealed with a
key-encryption key (KEK) derived from ``APP_KEY`` through HKDF with its own ``info`` string,
so the blob KEK is a different key from the TOTP-secret key or any keyed-digest key in
:mod:`cardioauth.security.crypto` (key separation, one KDF). The sealed DEK lives in the
object header; rotating ``APP_KEY`` therefore invalidates every object's KEK — a documented
consequence (``docs/STORAGE.md``), and the reason this is not the only copy of the data path.

The wire format (v1)
--------------------
::

    MAGIC  b"CAENV1\\x00"                      7 bytes
    u16    header length
    header JSON  {"v":1,"alg":"AES-256-GCM","chunk":N,"dek":b64(wrap_nonce||wrapped_dek)}
    record*      [u8 type][u32 ciphertext_len][12-byte nonce][ciphertext+tag]
                 type 0x01 = data chunk, type 0x02 = trailer (last record, always present)

Each record is AES-256-GCM with a random 96-bit nonce (safe here: a fresh DEK per object and
at most a few thousand records per object) and additional authenticated data binding the
*header bytes*, the record type and the record index. That binding is what stops splicing:
a chunk cannot be moved to another object, reordered within an object, or re-labelled as the
trailer without the tag failing. The trailer carries the plaintext length and sha256, so
truncation at a record boundary is detected even though each surviving record still
authenticates. A stream that ends before the trailer is an error, not a short read.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
from dataclasses import dataclass
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cardioauth.blobs.base import STREAM_CHUNK_BYTES, drain
from cardioauth.blobs.errors import BlobIntegrityError, BlobTooLarge
from cardioauth.security.crypto import derived_key_for

#: The one purpose string for this layer. Adding a new encrypted store means a new ``info``
#: string, never a reuse of this one.
KEK_PURPOSE = b"blob-envelope-kek/v1"
_DEK_AAD = b"cardioauth/blob-dek/v1"

MAGIC = b"CAENV1\x00"
HEADER_LEN_BYTES = 2
RECORD_TYPE_DATA = 0x01
RECORD_TYPE_TRAILER = 0x02
NONCE_BYTES = 12
TAG_BYTES = 16
MIN_CHUNK_BYTES = 1024
MAX_CHUNK_BYTES = 8 * 1024 * 1024
MAX_HEADER_BYTES = 4096
ENCRYPTION_LABEL = "app-envelope-aes-256-gcm-v1"


@dataclass(frozen=True)
class EnvelopeInfo:
    """What the writer learned about the plaintext it just sealed."""

    plaintext_byte_size: int
    plaintext_sha256: str
    chunk_count: int
    stored_byte_size: int


def blob_kek(settings: Any = None) -> bytes:
    """The KEK for this deployment, derived from ``APP_KEY`` (never from configuration)."""
    return derived_key_for(KEK_PURPOSE, settings=settings)


def _aad(header: bytes, record_type: int, index: int) -> bytes:
    return header + b"|" + bytes((record_type,)) + b"|" + str(index).encode("ascii")


def _write_record(dest: BinaryIO, aead: AESGCM, header: bytes, record_type: int, index: int, plaintext: bytes) -> None:
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = aead.encrypt(nonce, plaintext, _aad(header, record_type, index))
    dest.write(bytes((record_type,)))
    dest.write(len(ciphertext).to_bytes(4, "big"))
    dest.write(nonce)
    dest.write(ciphertext)


def encrypt_stream(
    source: BinaryIO,
    dest: BinaryIO,
    *,
    kek: bytes,
    chunk_size: int = STREAM_CHUNK_BYTES,
    max_bytes: int | None = None,
) -> EnvelopeInfo:
    """Seal ``source`` into ``dest`` in bounded memory. Returns the plaintext size and digest.

    The DEK is generated here, per object, and never leaves the process unsealed. The size
    limit is enforced on the **plaintext**, because that is the number the design's limit
    refers to (§5.4) and it is what the caller believes it is uploading.
    """
    if not MIN_CHUNK_BYTES <= chunk_size <= MAX_CHUNK_BYTES:
        raise ValueError(f"chunk_size must be between {MIN_CHUNK_BYTES} and {MAX_CHUNK_BYTES} bytes")
    dek = AESGCM.generate_key(bit_length=256)
    wrap_nonce = os.urandom(NONCE_BYTES)
    wrapped_dek = AESGCM(kek).encrypt(wrap_nonce, dek, _DEK_AAD)
    header = json.dumps(
        {
            "v": 1,
            "alg": "AES-256-GCM",
            "chunk": chunk_size,
            "dek": base64.b64encode(wrap_nonce + wrapped_dek).decode("ascii"),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(header) > MAX_HEADER_BYTES:  # pragma: no cover - only if a parameter gets silly
        raise ValueError("envelope header too large")
    dest.write(MAGIC)
    dest.write(len(header).to_bytes(HEADER_LEN_BYTES, "big"))
    dest.write(header)

    aead = AESGCM(dek)
    hasher = hashlib.sha256()
    total = 0
    index = 0
    stored = len(MAGIC) + HEADER_LEN_BYTES + len(header)
    for chunk in drain(source, chunk_size=chunk_size):
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            raise BlobTooLarge(
                f"object exceeds the {max_bytes}-byte per-document limit (§5.4); nothing was stored"
            )
        hasher.update(chunk)
        _write_record(dest, aead, header, RECORD_TYPE_DATA, index, chunk)
        stored += 1 + 4 + NONCE_BYTES + len(chunk) + TAG_BYTES
        index += 1
    trailer = json.dumps(
        {"size": total, "sha256": hasher.hexdigest()}, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    _write_record(dest, aead, header, RECORD_TYPE_TRAILER, index, trailer)
    stored += 1 + 4 + NONCE_BYTES + len(trailer) + TAG_BYTES
    return EnvelopeInfo(
        plaintext_byte_size=total,
        plaintext_sha256=hasher.hexdigest(),
        chunk_count=index,
        stored_byte_size=stored,
    )


def _read_exact(source: BinaryIO, count: int, *, what: str) -> bytes:
    data = source.read(count)
    if data is None or len(data) != count:
        raise BlobIntegrityError(
            f"encrypted object ended inside {what} ({len(data or b'')} of {count} bytes): "
            "the object is truncated"
        )
    return data


def read_header(source: BinaryIO, *, kek: bytes) -> tuple[bytes, AESGCM, int]:
    """Parse and unseal the header. Returns ``(header_bytes, aead, chunk_size)``.

    ``header_bytes`` is returned because it is the AAD every record is bound to; a tampered
    header cannot be used to decrypt anything.
    """
    magic = _read_exact(source, len(MAGIC), what="the header")
    if magic != MAGIC:
        raise BlobIntegrityError(
            "not an encrypted cardioauth object (bad magic): the object was written without "
            "envelope encryption or was replaced"
        )
    raw_len = _read_exact(source, HEADER_LEN_BYTES, what="the header")
    header_len = int.from_bytes(raw_len, "big")
    if not 0 < header_len <= MAX_HEADER_BYTES:
        raise BlobIntegrityError(f"implausible envelope header length {header_len}")
    header = _read_exact(source, header_len, what="the header")
    try:
        parsed = json.loads(header)
        if parsed.get("v") != 1 or parsed.get("alg") != "AES-256-GCM":
            raise BlobIntegrityError("unsupported envelope version or algorithm")
        chunk_size = int(parsed["chunk"])
        wrapped = base64.b64decode(parsed["dek"], validate=True)
    except (ValueError, KeyError, TypeError) as exc:
        raise BlobIntegrityError("the envelope header is malformed") from exc
    if not MIN_CHUNK_BYTES <= chunk_size <= MAX_CHUNK_BYTES:
        raise BlobIntegrityError("the envelope header declares an implausible chunk size")
    if len(wrapped) <= NONCE_BYTES:
        raise BlobIntegrityError("the sealed data key is truncated")
    try:
        dek = AESGCM(kek).decrypt(wrapped[:NONCE_BYTES], wrapped[NONCE_BYTES:], _DEK_AAD)
    except InvalidTag as exc:
        raise BlobIntegrityError(
            "the object's data key could not be unsealed: APP_KEY is not the key this object "
            "was written with, or the header was tampered with"
        ) from exc
    return header, AESGCM(dek), chunk_size


class EnvelopeReader(io.RawIOBase):
    """Streaming decryptor with authenticated truncation and integrity detection."""

    def __init__(self, source: BinaryIO, *, kek: bytes) -> None:
        super().__init__()
        self._source = source
        self._header, self._aead, self._chunk_size = read_header(source, kek=kek)
        self._hasher = hashlib.sha256()
        self._size = 0
        self._index = 0
        self._buffer = b""
        self._finished = False
        #: Set when the authenticated trailer has been read and verified.
        self.plaintext_byte_size: int | None = None
        self.plaintext_sha256: str | None = None

    @property
    def record_count(self) -> int:
        """Records consumed so far (data records plus the trailer)."""
        return self._index

    def readable(self) -> bool:  # pragma: no cover - trivial
        return True

    def readinto(self, buffer: Any) -> int:
        while not self._buffer:
            if self._finished:
                return 0
            self._buffer = self._next_record()
        count = min(len(buffer), len(self._buffer))
        buffer[:count] = self._buffer[:count]
        self._buffer = self._buffer[count:]
        return count

    def _next_record(self) -> bytes:
        head = _read_exact(self._source, 5, what="a record header")
        record_type = head[0]
        length = int.from_bytes(head[1:], "big")
        if length <= TAG_BYTES or length > self._chunk_size + TAG_BYTES + MAX_HEADER_BYTES:
            raise BlobIntegrityError(f"implausible encrypted record length {length}")
        nonce = _read_exact(self._source, NONCE_BYTES, what="a record nonce")
        body = _read_exact(self._source, length, what="a record body")
        try:
            plaintext = self._aead.decrypt(
                nonce,
                body,
                _aad(self._header, record_type, self._index),
            )
        except InvalidTag as exc:
            raise BlobIntegrityError(
                "an encrypted record failed authentication: the object was modified, or a "
                "record was moved or reordered"
            ) from exc
        self._index += 1
        if record_type == RECORD_TYPE_DATA:
            self._hasher.update(plaintext)
            self._size += len(plaintext)
            return plaintext
        if record_type == RECORD_TYPE_TRAILER:
            self._finish(plaintext)
            self._finished = True
            return b""
        raise BlobIntegrityError(f"unknown encrypted record type {record_type}")

    def _finish(self, trailer: bytes) -> None:
        try:
            parsed = json.loads(trailer)
            expected_size = int(parsed["size"])
            expected_sha = str(parsed["sha256"])
        except (ValueError, KeyError, TypeError) as exc:
            raise BlobIntegrityError("the encrypted trailer is malformed") from exc
        trailing = self._source.read(1)
        if trailing:
            raise BlobIntegrityError("bytes follow the encrypted trailer: the object was extended")
        if self._size != expected_size:
            raise BlobIntegrityError(
                f"decrypted {self._size} bytes but the trailer records {expected_size}: the "
                "object is truncated"
            )
        if self._hasher.hexdigest() != expected_sha:
            raise BlobIntegrityError("the decrypted object does not match its recorded sha256")
        self.plaintext_byte_size = expected_size
        self.plaintext_sha256 = expected_sha

    def close(self) -> None:
        try:
            self._source.close()
        finally:
            super().close()


def open_envelope(source: BinaryIO, *, kek: bytes) -> io.BufferedReader:
    """A buffered, ordinary ``read(n)`` stream over an encrypted object."""
    return io.BufferedReader(EnvelopeReader(source, kek=kek), buffer_size=STREAM_CHUNK_BYTES)


def decrypt_stream(source: BinaryIO, dest: BinaryIO, *, kek: bytes) -> EnvelopeInfo:
    """Decrypt ``source`` into ``dest``, verifying size and digest. Returns the plaintext info."""
    reader = EnvelopeReader(source, kek=kek)
    while True:
        chunk = reader.read(STREAM_CHUNK_BYTES)
        if not chunk:
            break
        dest.write(chunk)
    if reader.plaintext_byte_size is None:  # pragma: no cover - the loop above runs to EOF
        raise BlobIntegrityError("the encrypted object produced no trailer")
    return EnvelopeInfo(
        plaintext_byte_size=reader.plaintext_byte_size,
        plaintext_sha256=reader.plaintext_sha256 or "",
        chunk_count=reader.record_count - 1,
        stored_byte_size=0,
    )


__all__ = [
    "ENCRYPTION_LABEL",
    "KEK_PURPOSE",
    "MAGIC",
    "EnvelopeInfo",
    "EnvelopeReader",
    "blob_kek",
    "decrypt_stream",
    "encrypt_stream",
    "open_envelope",
    "read_header",
]
