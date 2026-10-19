"""Blob keys: built only from typed UUIDs, parsed only in one canonical form.

This is task item 3, and the whole point is *by construction* rather than by sanitising.

* A key is **not a string a caller assembles**. It is ``BlobKey(practice_id, kind, blob_id)``
  where the first and third fields must be :class:`uuid.UUID` instances and the second must be
  a member of :data:`BLOB_KINDS`. ``BlobKey(practice_id="../../etc/passwd", ...)`` raises
  :class:`InvalidBlobKey` because a ``str`` is not a UUID — there is no code path in which a
  caller-supplied string becomes a path segment.
* The **textual** form has exactly one shape — ``p/<32 hex>/<kind>/<32 hex>`` — and
  :meth:`BlobKey.parse` accepts nothing else: the pattern is a full match, so ``..``,
  ``/`` (beyond the three fixed separators), ``\\``, ``%2e``, a NUL byte, a leading ``/``, an
  absolute Windows path, non-ASCII look-alikes and upper-case hex all fail before any I/O.
  The parse then re-serialises and compares, so a key can only round-trip if it is canonical.
* A key is **PHI-free**: two UUIDs and a namespace name. No patient name, MRN, date of birth,
  filename or free text ever enters it, so the key is safe to audit, log as an identifier and
  show in a bucket listing (INV-5).
* The practice UUID is the first segment, so an object's namespace is a practice's own. The
  :class:`cardioauth.blobs.scoped.PracticeScopedBlobStore` refuses a key whose practice is not
  the caller's, which is what makes one practice's objects unaddressable from another's.

Object bytes are immutable: a key is created once, written once, deleted once. A new version of
a document gets a new key (the design's content-addressing rule, §0.1 "Documents addressed by
content hash, never rewritten").
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from cardioauth.blobs.errors import InvalidBlobKey, describe_rejected_key

#: The namespaces an object may live in. A closed set, because the namespace is part of the
#: key and therefore part of every audit detail and every stored path.
BLOB_KINDS: frozenset[str] = frozenset(
    {
        "document",  # the uploaded file itself (§2.4 ``document.blob_key``)
        "page-image",  # the normalised page image a citation highlights (§2.4 image_blob_key)
        "export",  # a rendered PDF/DOCX of a letter version (§8.6)
        "template",  # practice letterhead assets (§8.6)
    }
)

#: 32 lower-case hex characters: ``uuid.UUID.hex``. Not the dashed form, and not upper-case.
_HEX32 = r"[0-9a-f]{32}"
_NAMESPACE_RE = re.compile(rf"p/({_HEX32})/([a-z][a-z0-9-]{{0,31}})/({_HEX32})")
_SEPARATOR = "/"


@dataclass(frozen=True, order=True)
class BlobKey:
    """One immutable object, in one practice's namespace, in one kind of namespace."""

    practice_id: uuid.UUID
    kind: str
    blob_id: uuid.UUID

    def __post_init__(self) -> None:
        # Every check here is a type/allowlist check, never a string sanitisation. That is the
        # difference between "rejected by construction" and "rejected by string-replace": there
        # is no string to sanitise, because the caller cannot supply one.
        if not isinstance(self.practice_id, uuid.UUID):
            raise InvalidBlobKey(
                f"practice_id must be a uuid.UUID, not {type(self.practice_id).__name__}"
            )
        if not isinstance(self.blob_id, uuid.UUID):
            raise InvalidBlobKey(f"blob_id must be a uuid.UUID, not {type(self.blob_id).__name__}")
        if not isinstance(self.kind, str) or self.kind not in BLOB_KINDS:
            raise InvalidBlobKey(
                f"kind must be one of {sorted(BLOB_KINDS)}, not {type(self.kind).__name__}"
            )

    @property
    def namespace(self) -> str:
        """The canonical text form: ``p/<practice hex>/<kind>/<blob hex>``."""
        return _SEPARATOR.join(
            ("p", self.practice_id.hex, self.kind, self.blob_id.hex)
        )

    def __str__(self) -> str:
        return self.namespace

    @classmethod
    def generate(
        cls,
        *,
        practice_id: uuid.UUID,
        kind: str,
        blob_id: uuid.UUID | None = None,
    ) -> BlobKey:
        """A fresh key. The server generates the object id; nothing derives it from content or
        from anything a user typed."""
        return cls(practice_id=practice_id, kind=kind, blob_id=blob_id or uuid.uuid4())

    @classmethod
    def parse(cls, value: str) -> BlobKey:
        """The only way text becomes a key. Strict full match + canonical round-trip."""
        if not isinstance(value, str):
            raise InvalidBlobKey(f"a blob key must be a str, not {type(value).__name__}")
        match = _NAMESPACE_RE.fullmatch(value)
        if match is None:
            raise InvalidBlobKey(
                "not a canonical blob key (expected 'p/<32 hex>/<kind>/<32 hex>'): "
                + describe_rejected_key(value)
            )
        practice_hex, kind, blob_hex = match.groups()
        if kind not in BLOB_KINDS:
            raise InvalidBlobKey(f"unknown namespace {kind!r}; expected one of {sorted(BLOB_KINDS)}")
        key = cls(
            practice_id=uuid.UUID(practice_hex),
            kind=kind,
            blob_id=uuid.UUID(blob_hex),
        )
        if key.namespace != value:  # canonical round-trip: no normalising parser to fool
            raise InvalidBlobKey("key is not in canonical form: " + describe_rejected_key(value))
        return key


def coerce_key(value: BlobKey | str) -> BlobKey:
    """Accept a key object, or text that must parse as one. Never anything else."""
    if isinstance(value, BlobKey):
        return value
    return BlobKey.parse(value)


__all__ = ["BLOB_KINDS", "BlobKey", "coerce_key"]
