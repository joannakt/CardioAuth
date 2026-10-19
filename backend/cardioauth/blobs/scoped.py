"""Practice scoping: one practice's objects are not addressable from another's.

A key already names a practice, so the *namespace* is separate. This wrapper enforces it: a
store handed to a request for practice A refuses a key that belongs to practice B with
:class:`~cardioauth.blobs.errors.BlobAccessDenied`, before any I/O happens and before anything
is audited.

Why a wrapper and not a rule in each backend: the check must be impossible to forget. Services
never build a backend directly — :func:`cardioauth.blobs.get_blob_store` composes the backend,
the encryption layer and this scope, and a request-scoped store is always built with a
practice. The check therefore sits at exactly one seam, above every backend and every wrapper,
and a new backend inherits it for free.

Scope is *not* authorisation: it says "this key is not in your practice", not "your role may
read documents". Role checks live in :mod:`cardioauth.authz` (§7.3) and are enforced per
endpoint; this is the storage-side floor under them, so a bug in a router cannot turn into a
cross-practice read.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from typing import BinaryIO, Iterator

from cardioauth.blobs.base import BlobMetadata, BlobStore, coerce_key
from cardioauth.blobs.errors import BlobAccessDenied
from cardioauth.blobs.keys import BlobKey


class PracticeScopedBlobStore:
    """A view of a store restricted to one practice."""

    def __init__(self, inner: BlobStore, *, practice_id: uuid.UUID) -> None:
        if not isinstance(practice_id, uuid.UUID):
            raise ValueError(f"practice_id must be a uuid.UUID, not {type(practice_id).__name__}")
        self._inner = inner
        self._practice_id = practice_id
        self.name = inner.name

    @property
    def practice_id(self) -> uuid.UUID:
        return self._practice_id

    @property
    def inner(self) -> BlobStore:
        return self._inner

    def _check(self, key: BlobKey | str) -> BlobKey:
        key = coerce_key(key)
        if key.practice_id != self._practice_id:
            # The message names the namespace kind and the ids' practice, never the object's
            # contents: a denial must not become a channel for another practice's data.
            raise BlobAccessDenied(
                "blob key belongs to a different practice; this store is scoped to "
                f"practice {self._practice_id} and the key names practice {key.practice_id}"
            )
        return key

    def put(self, key: BlobKey | str, source: BinaryIO, *, content_type: str) -> BlobMetadata:
        return self._inner.put(self._check(key), source, content_type=content_type)

    @contextmanager
    def open(self, key: BlobKey | str) -> Iterator[BinaryIO]:
        with self._inner.open(self._check(key)) as stream:
            yield stream

    def get(self, key: BlobKey | str) -> bytes:
        return self._inner.get(self._check(key))

    def head(self, key: BlobKey | str) -> BlobMetadata:
        return self._inner.head(self._check(key))

    def exists(self, key: BlobKey | str) -> bool:
        return self._inner.exists(self._check(key))

    def delete(self, key: BlobKey | str) -> None:
        self._inner.delete(self._check(key))

    def export(self, key: BlobKey | str) -> bytes:
        """Read for delivery to a human (download/export). Only defined on wrappers that can
        audit it; the scoped wrapper forwards when the inner store supports it."""
        export = getattr(self._inner, "export", None)
        if export is None:  # pragma: no cover - an unaudited store in a test
            return self.get(key)
        return export(self._check(key))


__all__ = ["PracticeScopedBlobStore"]
