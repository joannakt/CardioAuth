"""The BlobStore contract: one suite, every backend (M1b-3).

The point of parametrising is honesty. Local filesystem, in-process memory and S3-compatible
storage are held to the same behaviour, so "it works on my machine with local files" cannot be
mistaken for "it works". **What was actually exercised:**

* ``local`` — a real filesystem, real files, real fsync. Live.
* ``memory`` — a real implementation of the same contract, in a dict. Live, but not durable.
* ``s3`` — ``moto``, an in-process S3 emulator: real botocore request construction, real
  signature/header serialisation, an emulated server. **Not** a real MinIO or AWS endpoint;
  this path is UNVERIFIED against a real server (there is no Docker daemon on this machine to
  start MinIO). ``tests/test_blob_s3_specifics.py`` is where that distinction is recorded.

Every test here runs twice: once against the raw backend and once with the envelope-encryption
wrapper on top, because a wrapper that changes behaviour is a wrapper that breaks a caller.
"""

from __future__ import annotations

import io
import uuid

import pytest

from cardioauth.blobs import (
    BlobIntegrityError,
    BlobKey,
    BlobNotFound,
    BlobTooLarge,
    EncryptedBlobStore,
    InvalidBlobKey,
    InvalidContentType,
    LocalBlobStore,
    MemoryBlobStore,
    PracticeScopedBlobStore,
    BlobAccessDenied,
)
from cardioauth.settings import Settings

PRACTICE = uuid.UUID("11111111-1111-4111-8111-111111111111")
OTHER_PRACTICE = uuid.UUID("22222222-2222-4222-8222-222222222222")
KEY = BlobKey.generate(practice_id=PRACTICE, kind="document")
PAYLOAD = b"%PDF-1.7 TEST-ONLY synthetic cardiology document\n" * 200


# --------------------------------------------------------------------------- fixtures
@pytest.fixture(params=["local", "memory", "s3"])
def backend(request, tmp_path, monkeypatch):  # noqa: ANN001
    """A raw (unencrypted, unscoped) store for each provider."""
    if request.param == "local":
        yield LocalBlobStore(tmp_path / "blobs", max_bytes=64 * 1024)
        return
    if request.param == "memory":
        yield MemoryBlobStore(max_bytes=64 * 1024)
        return
    moto = pytest.importorskip("moto")
    import boto3

    with moto.mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="cardioauth-test")
        settings = Settings(
            _env_file=None,
            blob_backend="s3",
            s3_bucket="cardioauth-test",
            s3_region="us-east-1",
            s3_server_side_encryption="aws:kms",
            s3_use_ssl=False,
        )
        from cardioauth.blobs.s3 import S3BlobStore

        yield S3BlobStore(settings, client=client, max_bytes=64 * 1024)


@pytest.fixture(params=["plain", "encrypted"])
def store(request, backend):  # noqa: ANN001
    """The backend as a caller sees it: with and without application-level encryption."""
    if request.param == "plain":
        return backend
    return EncryptedBlobStore(backend, kek=b"k" * 32, max_bytes=64 * 1024, chunk_size=1024)


# --------------------------------------------------------------------------- contract
def test_put_get_roundtrip_and_metadata(store) -> None:  # noqa: ANN001
    metadata = store.put(KEY, io.BytesIO(PAYLOAD), content_type="application/pdf")
    assert metadata.key == KEY
    assert metadata.content_type == "application/pdf"
    assert metadata.byte_size == len(PAYLOAD)
    assert len(metadata.sha256) == 64
    assert metadata.created_at.tzinfo is not None
    assert store.get(KEY) == PAYLOAD
    assert store.exists(KEY) is True


def test_streaming_read_in_chunks(store) -> None:  # noqa: ANN001
    store.put(KEY, io.BytesIO(PAYLOAD), content_type="application/pdf")
    chunks = []
    with store.open(KEY) as stream:
        while chunk := stream.read(4096):
            chunks.append(chunk)
    assert b"".join(chunks) == PAYLOAD
    assert len(chunks) > 1, "the read really was streamed, not returned in one piece"


def test_empty_object_round_trips(store) -> None:  # noqa: ANN001
    metadata = store.put(KEY, io.BytesIO(b""), content_type="text/plain")
    assert metadata.byte_size == 0
    assert store.get(KEY) == b""
    head = store.head(KEY)
    assert head.key == KEY
    # An encrypted store cannot report the plaintext length from metadata alone (it lives in
    # the authenticated trailer), so it reports None rather than a value it did not verify.
    if head.plaintext_byte_size is not None:
        assert head.plaintext_byte_size == 0


def test_missing_object_is_blob_not_found(store) -> None:  # noqa: ANN001
    with pytest.raises(BlobNotFound):
        store.get(KEY)
    with pytest.raises(BlobNotFound):
        store.head(KEY)
    with pytest.raises(BlobNotFound):
        with store.open(KEY):
            pass
    assert store.exists(KEY) is False


def test_delete_is_idempotent(store) -> None:  # noqa: ANN001
    store.put(KEY, io.BytesIO(PAYLOAD), content_type="application/pdf")
    store.delete(KEY)
    assert store.exists(KEY) is False
    store.delete(KEY)  # a retried cleanup must not raise


def test_oversized_object_is_refused_and_leaves_nothing_behind(store) -> None:  # noqa: ANN001
    oversized = b"x" * (70 * 1024)
    with pytest.raises(BlobTooLarge):
        store.put(KEY, io.BytesIO(oversized), content_type="application/pdf")
    assert store.exists(KEY) is False, "a rejected upload must not leave a partial object"


def test_content_type_must_be_allowlisted(store) -> None:  # noqa: ANN001
    with pytest.raises(InvalidContentType):
        store.put(KEY, io.BytesIO(b"x"), content_type="application/x-evil")
    assert store.exists(KEY) is False


def test_tampered_bytes_are_detected_on_read(store, backend) -> None:  # noqa: ANN001
    store.put(KEY, io.BytesIO(PAYLOAD), content_type="application/pdf")
    # Damage the stored bytes without touching the recorded metadata.
    if isinstance(backend, MemoryBlobStore):
        backend.corrupt(KEY)
    elif isinstance(backend, LocalBlobStore):
        path = backend.root.joinpath(*KEY.namespace.split("/"))
        original = path.read_bytes()
        path.write_bytes(bytes([original[0] ^ 0xFF]) + original[1:])
    else:  # S3-compatible: overwrite the object out of band
        client = backend._client
        client.put_object(
            Bucket="cardioauth-test",
            Key=KEY.namespace,
            Body=b"tampered",
            Metadata={"cardioauth-sha256": store.head(KEY).stored_sha256},
        )
    with pytest.raises(BlobIntegrityError):
        store.get(KEY)


# --------------------------------------------------------------------------- keys
@pytest.mark.parametrize(
    "candidate",
    [
        "p/../../etc/passwd",
        "/etc/passwd",
        "p/11111111111141118111111111111111/document/../../x",
        "p/11111111111141118111111111111111/document/22222222222242228222222222222222\x00",
        "p/11111111111141118111111111111111/document/2222222222224222822222222222222g",
        "P/11111111111141118111111111111111/document/22222222222242228222222222222222",
        "p/11111111111141118111111111111111/document",
        "p/11111111111141118111111111111111/document/22222222222242228222222222222222/extra",
        "p/１１１１１１１１１１１１１１１１１１１１１１１１１１１１１１１１/document/x",
        "p/11111111111141118111111111111111/../../document/22222222222242228222222222222222",
        "",
    ],
)
def test_key_injection_is_rejected_by_construction(candidate: str) -> None:
    with pytest.raises(InvalidBlobKey):
        BlobKey.parse(candidate)


def test_a_key_cannot_be_built_from_a_string_practice_id() -> None:
    with pytest.raises(InvalidBlobKey):
        BlobKey(practice_id="../../etc", kind="document", blob_id=uuid.uuid4())  # type: ignore[arg-type]
    with pytest.raises(InvalidBlobKey):
        BlobKey(practice_id=PRACTICE, kind="../document", blob_id=uuid.uuid4())


def test_key_text_form_is_canonical_and_phi_free() -> None:
    key = BlobKey.generate(practice_id=PRACTICE, kind="document")
    assert BlobKey.parse(key.namespace) == key
    assert str(key) == key.namespace
    assert "patient" not in key.namespace and "TEST-ONLY" not in key.namespace


def test_store_refuses_a_key_it_cannot_parse(store) -> None:  # noqa: ANN001
    with pytest.raises(InvalidBlobKey):
        store.put("../escape", io.BytesIO(b"x"), content_type="text/plain")


# --------------------------------------------------------------------------- practice scope
def test_one_practice_cannot_address_anothers_object(backend) -> None:  # noqa: ANN001
    scoped = PracticeScopedBlobStore(backend, practice_id=PRACTICE)
    foreign = BlobKey.generate(practice_id=OTHER_PRACTICE, kind="document")
    scoped.put(KEY, io.BytesIO(PAYLOAD), content_type="application/pdf")
    for call in (
        lambda: scoped.get(foreign),
        lambda: scoped.head(foreign),
        lambda: scoped.exists(foreign),
        lambda: scoped.delete(foreign),
        lambda: scoped.put(foreign, io.BytesIO(b"x"), content_type="text/plain"),
    ):
        with pytest.raises(BlobAccessDenied):
            call()
    # ...and the foreign key is still absent from the store.
    assert backend.exists(foreign) is False
