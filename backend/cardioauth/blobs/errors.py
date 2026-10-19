"""Storage failures, in one place so callers never catch a provider's exception type.

Nothing in this module may carry PHI in its message: a blob key is PHI-free *by construction*
(:mod:`cardioauth.blobs.keys`), and the one function that describes a rejected key prints a
category, never the value, so a coordinator who pastes a filename with a patient name into a
key field cannot get that name into an error string that reaches a log line (INV-5).
"""

from __future__ import annotations

from typing import Any


class BlobStoreError(RuntimeError):
    """Base class for every storage failure. Callers catch this, never a boto3 error."""


class BlobNotFound(BlobStoreError):
    """The object does not exist (or was deleted)."""


class BlobTooLarge(BlobStoreError):
    """The object exceeded the configured per-document limit (§5.4).

    Raised *during* the upload, before anything is left behind: the caller sees one error and
    the store is unchanged (no partial object, no orphaned temp file).
    """


class BlobIntegrityError(BlobStoreError):
    """Stored bytes do not match the digest recorded when they were written.

    This is corruption or tampering, not a missing object: the caller must not treat the
    bytes as clinical evidence (§2.4, §5.2 — a citation points at specific pixels forever).
    """


class BlobAccessDenied(BlobStoreError):
    """A key belongs to another practice. One practice's objects are not addressable from
    another's, even with a valid key (task item 3)."""


class BlobBackendUnavailable(BlobStoreError):
    """The configured backend cannot be built: unknown name, or refused by the guards."""


class InvalidBlobKey(BlobStoreError, ValueError):
    """A key is not in the one canonical form. Raised before any I/O happens."""


class InvalidContentType(BlobStoreError, ValueError):
    """A content type outside the allowlist. It is stored as object metadata and audited, so
    an arbitrary caller-supplied string is not accepted."""


#: Reasons a candidate key is refused, as categories. Deliberately never echoes the value:
#: the value came from somewhere a human typed, and error strings reach logs (INV-5).
def describe_rejected_key(value: Any) -> str:
    if not isinstance(value, str):
        return f"type {type(value).__name__} is not str"
    if not value:
        return "empty string"
    reasons: list[str] = []
    if "\x00" in value:
        reasons.append("contains a NUL byte")
    if ".." in value:
        reasons.append("contains '..'")
    if value.startswith(("/", "\\")) or (len(value) > 1 and value[1] == ":"):
        reasons.append("looks like an absolute path")
    if any(ord(char) > 126 or ord(char) < 32 for char in value):
        reasons.append("contains a non-printable or non-ASCII character")
    if "\\" in value:
        reasons.append("contains a backslash")
    if value != value.lower():
        reasons.append("contains upper-case characters")
    if not reasons:
        reasons.append("does not match the canonical 'p/<32 hex>/<kind>/<32 hex>' form")
    return f"length {len(value)}; " + "; ".join(reasons)


__all__ = [
    "BlobAccessDenied",
    "BlobBackendUnavailable",
    "BlobIntegrityError",
    "BlobNotFound",
    "BlobStoreError",
    "BlobTooLarge",
    "InvalidBlobKey",
    "InvalidContentType",
    "describe_rejected_key",
]
