"""S3-compatible BlobStore: MinIO in compose, real S3 in production (§1.3).

One code path for both. ``S3_ENDPOINT_URL`` empty means AWS S3; set, it means MinIO (or any
S3-compatible store), which is what makes the production storage path exercised locally instead
of being a code path that only exists in production (§12 addition 4).

Choices that matter, and why
----------------------------
* **Spool, then upload.** The object is streamed from the caller into a
  :class:`tempfile.SpooledTemporaryFile` while its size and digest are computed, and only then
  handed to ``upload_fileobj``. Two consequences, both deliberate: the per-document limit is
  enforced *before* any network write (so an oversized upload never leaves a partial object or
  an orphaned multipart upload behind), and the digest stored in object metadata is the digest
  of exactly the bytes that were sent.
* **Server-side encryption is sent on every write**, from configuration, never defaulted: the
  production guard refuses to start without it (:meth:`Settings.storage_problems`).
* **Metadata round-trips through ``x-amz-meta-*``**, so :meth:`head` can report content type,
  size, digest, creation time and the encryption mode without reading the object. A read
  verifies the digest it finds there, so an object replaced out of band is detected.
* **No bucket creation in production.** ``S3_CREATE_BUCKET_IF_MISSING`` is a dev convenience and
  is refused under ``CARDIOAUTH_ENV=production``, where creating a bucket implicitly would hide
  a typo in ``S3_BUCKET``.
* **Path-style addressing is available** because MinIO does not do virtual-host style on
  ``localhost``; ``S3_ADDRESSING_STYLE=path`` is what the compose stack uses.
"""

from __future__ import annotations

import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, BinaryIO, Iterator

from cardioauth.blobs.base import (
    STREAM_CHUNK_BYTES,
    BlobMetadata,
    coerce_key,
    drain,
    validate_content_type,
    verifying_stream,
)
from cardioauth.blobs.errors import (
    BlobBackendUnavailable,
    BlobIntegrityError,
    BlobNotFound,
    BlobStoreError,
    BlobTooLarge,
)
from cardioauth.blobs.keys import BlobKey
from cardioauth.settings import Settings

SPOOL_MAX_MEMORY_BYTES = 8 * 1024 * 1024

_META_SHA256 = "cardioauth-sha256"
_META_SIZE = "cardioauth-byte-size"
_META_CREATED = "cardioauth-created-at"
_META_ENCRYPTION = "cardioauth-encryption"
_META_CONTENT_TYPE = "cardioauth-content-type"


def _import_boto3() -> Any:
    try:
        import boto3  # noqa: PLC0415 - imported lazily so the local backend needs no boto3
    except ImportError as exc:  # pragma: no cover - only on an install without the extra
        raise BlobBackendUnavailable(
            "BLOB_BACKEND=s3 needs the 'boto3' package; install requirements.lock"
        ) from exc
    return boto3


class S3BlobStore:
    """Objects in an S3-compatible bucket, addressed only by :class:`BlobKey`."""

    name = "s3"

    def __init__(
        self,
        settings: Settings,
        *,
        client: Any | None = None,
        max_bytes: int | None = None,
        chunk_size: int = STREAM_CHUNK_BYTES,
        encryption_label: str = "none",
    ) -> None:
        if not settings.s3_bucket:
            raise BlobBackendUnavailable("BLOB_BACKEND=s3 requires S3_BUCKET")
        self._settings = settings
        self._bucket = settings.s3_bucket
        self._client = client if client is not None else self._build_client(settings)
        self._max_bytes = settings.document_max_bytes if max_bytes is None else max_bytes
        self._chunk_size = chunk_size
        self._encryption = encryption_label
        if settings.s3_create_bucket_if_missing:
            self.ensure_bucket()

    # --- client -----------------------------------------------------------
    @staticmethod
    def _build_client(settings: Settings) -> Any:
        boto3 = _import_boto3()
        from botocore.config import Config  # noqa: PLC0415

        kwargs: dict[str, Any] = {
            "region_name": settings.s3_region,
            "use_ssl": settings.s3_use_ssl,
            "config": Config(
                signature_version="s3v4",
                s3={"addressing_style": settings.s3_addressing_style},
                retries={"max_attempts": 3, "mode": "standard"},
            ),
        }
        if settings.s3_endpoint_url:
            kwargs["endpoint_url"] = settings.s3_endpoint_url
        if settings.s3_access_key_id:
            kwargs["aws_access_key_id"] = settings.s3_access_key_id
            kwargs["aws_secret_access_key"] = (
                settings.s3_secret_access_key.get_secret_value() if settings.s3_secret_access_key else None
            )
        return boto3.client("s3", **kwargs)

    def ensure_bucket(self) -> None:
        """Create the bucket if it is missing. Dev convenience; refused in production."""
        try:
            self._client.head_bucket(Bucket=self._bucket)
            return
        except Exception as exc:  # noqa: BLE001 - any head failure means "try to create"
            if not self._is_missing(exc):
                raise BlobStoreError(f"bucket is not reachable: {type(exc).__name__}") from exc
        try:
            self._client.create_bucket(
                Bucket=self._bucket,
                **(
                    {"CreateBucketConfiguration": {"LocationConstraint": self._settings.s3_region}}
                    if self._settings.s3_region and self._settings.s3_region != "us-east-1"
                    else {}
                ),
            )
        except Exception as exc:  # noqa: BLE001
            raise BlobStoreError(f"bucket could not be created: {type(exc).__name__}") from exc

    # --- helpers ----------------------------------------------------------
    @staticmethod
    def _is_missing(exc: BaseException) -> bool:
        response = getattr(exc, "response", None) or {}
        code = str(response.get("Error", {}).get("Code", ""))
        status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return code in {"404", "NoSuchKey", "NoSuchBucket", "NotFound"} or status == 404

    def _extra_args(self, content_type: str, *, sha256_hex: str, size: int, created_at: datetime) -> dict[str, Any]:
        extra: dict[str, Any] = {
            "ContentType": content_type,
            "Metadata": {
                _META_SHA256: sha256_hex,
                _META_SIZE: str(size),
                _META_CREATED: created_at.astimezone(timezone.utc).isoformat(),
                _META_ENCRYPTION: self._encryption,
                _META_CONTENT_TYPE: content_type,
            },
        }
        if self._settings.s3_server_side_encryption:
            extra["ServerSideEncryption"] = self._settings.s3_server_side_encryption
            if self._settings.s3_kms_key_id:
                extra["SSEKMSKeyId"] = self._settings.s3_kms_key_id
        return extra

    def _metadata_from_head(self, key: BlobKey, head: dict[str, Any]) -> BlobMetadata:
        meta = {str(k).lower(): str(v) for k, v in (head.get("Metadata") or {}).items()}
        created_raw = meta.get(_META_CREATED)
        try:
            created = datetime.fromisoformat(created_raw) if created_raw else head["LastModified"]
        except (KeyError, ValueError):
            created = datetime.now(timezone.utc)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        size = int(head.get("ContentLength", 0))
        return BlobMetadata(
            key=key,
            content_type=meta.get(_META_CONTENT_TYPE) or head.get("ContentType") or "application/octet-stream",
            stored_byte_size=size,
            stored_sha256=meta.get(_META_SHA256, ""),
            created_at=created,
            encryption=meta.get(_META_ENCRYPTION, self._encryption),
            backend=self.name,
            extra={"sse": str(head.get("ServerSideEncryption", ""))} if head.get("ServerSideEncryption") else {},
        )

    def _head_object(self, key: BlobKey) -> dict[str, Any]:
        try:
            return self._client.head_object(Bucket=self._bucket, Key=key.namespace)
        except Exception as exc:  # noqa: BLE001
            if self._is_missing(exc):
                raise BlobNotFound(f"no object at {key.namespace}") from exc
            raise BlobStoreError(f"object metadata is unavailable: {type(exc).__name__}") from exc

    # --- interface --------------------------------------------------------
    def put(self, key: BlobKey | str, source: BinaryIO, *, content_type: str) -> BlobMetadata:
        key = coerce_key(key)
        content_type = validate_content_type(content_type)
        created_at = datetime.now(timezone.utc)
        with tempfile.SpooledTemporaryFile(max_size=SPOOL_MAX_MEMORY_BYTES) as spool:
            hasher = sha256()
            size = 0
            for chunk in drain(source, chunk_size=self._chunk_size):
                size += len(chunk)
                if size > self._max_bytes:
                    raise BlobTooLarge(
                        f"object exceeds the {self._max_bytes}-byte per-document limit (§5.4); "
                        "nothing was uploaded"
                    )
                hasher.update(chunk)
                spool.write(chunk)
            digest = hasher.hexdigest()
            spool.seek(0)
            try:
                self._client.upload_fileobj(
                    spool,
                    self._bucket,
                    key.namespace,
                    ExtraArgs=self._extra_args(
                        content_type, sha256_hex=digest, size=size, created_at=created_at
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                raise BlobStoreError(f"upload failed: {type(exc).__name__}") from exc
        return BlobMetadata(
            key=key,
            content_type=content_type,
            stored_byte_size=size,
            stored_sha256=digest,
            created_at=created_at,
            encryption=self._encryption,
            backend=self.name,
        )

    @contextmanager
    def open(self, key: BlobKey | str) -> Iterator[BinaryIO]:
        key = coerce_key(key)
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key.namespace)
        except Exception as exc:  # noqa: BLE001
            if self._is_missing(exc):
                raise BlobNotFound(f"no object at {key.namespace}") from exc
            raise BlobStoreError(f"download failed: {type(exc).__name__}") from exc
        body = response["Body"]
        metadata = self._metadata_from_head(key, response)
        if not metadata.stored_sha256:
            body.close()
            raise BlobIntegrityError(
                "object has no recorded digest, so the bytes cannot be verified and must not be "
                "used as clinical evidence"
            )
        try:
            yield verifying_stream(
                body,
                expected_sha256=metadata.stored_sha256,
                expected_size=metadata.stored_byte_size,
                what=f"object {key.namespace}",
            )
        finally:
            body.close()

    def get(self, key: BlobKey | str) -> bytes:
        with self.open(key) as stream:
            return stream.read()

    def head(self, key: BlobKey | str) -> BlobMetadata:
        key = coerce_key(key)
        return self._metadata_from_head(key, self._head_object(key))

    def exists(self, key: BlobKey | str) -> bool:
        try:
            self._head_object(coerce_key(key))
            return True
        except BlobNotFound:
            return False

    def delete(self, key: BlobKey | str) -> None:
        try:
            self._client.delete_object(Bucket=self._bucket, Key=coerce_key(key).namespace)
        except Exception as exc:  # noqa: BLE001
            raise BlobStoreError(f"delete failed: {type(exc).__name__}") from exc


__all__ = ["S3BlobStore"]
