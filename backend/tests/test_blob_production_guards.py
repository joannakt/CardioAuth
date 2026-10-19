"""The production storage guards (M1b-3 item 5) — proven to be guards, not blanket refusals.

Each refusal test is paired with the matching acceptance in dev/test, so a guard that simply
refused everything would fail this file. The guards live in
:meth:`cardioauth.settings.Settings.storage_problems` and are enforced twice: at startup
(``assert_runtime_safe``) and in the factory (``get_blob_store``), so a worker or a script
cannot build a backend the process was never allowed to select.
"""

from __future__ import annotations

import pytest

from cardioauth.blobs import get_blob_store
from cardioauth.settings import Environment, Settings, SettingsError

SAFE_PRODUCTION = {
    "cardioauth_env": Environment.production,
    "cardioauth_phi_logging": "off",
    "llm_provider": "bedrock",
    "llm_model": "some-baa-model",
    "blob_backend": "s3",
    "s3_bucket": "cardioauth-prod",
    "s3_region": "us-east-1",
    "s3_server_side_encryption": "aws:kms",
    "app_key": "not-the-dev-key-but-long-enough-for-real-use-ok",
    "database_require_tls": True,
    "session_cookie_secure": True,
}


def production(**overrides: object) -> Settings:
    base = dict(SAFE_PRODUCTION)
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


def test_a_safe_production_storage_configuration_is_accepted() -> None:
    settings = production()
    settings.assert_runtime_safe()
    settings.assert_storage_safe()


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"blob_backend": "local"}, "BLOB_BACKEND=local"),
        ({"blob_backend": "memory"}, "development backend"),
        ({"s3_bucket": None}, "S3_BUCKET"),
        ({"s3_region": None}, "S3_REGION"),
        ({"s3_server_side_encryption": None}, "server-side encryption"),
        ({"blob_app_encryption": False}, "BLOB_APP_ENCRYPTION=false"),
        ({"s3_create_bucket_if_missing": True}, "S3_CREATE_BUCKET_IF_MISSING=true"),
        ({"s3_use_ssl": False}, "S3_USE_SSL=false"),
        ({"s3_kms_key_id": "arn:aws:kms:...", "s3_server_side_encryption": None}, "S3_KMS_KEY_ID"),
        ({"s3_access_key_id": "AKIA-test", "s3_secret_access_key": None}, "must be set together"),
    ],
)
def test_production_refuses_unsafe_storage(overrides: dict, expected: str) -> None:
    settings = production(**overrides)
    with pytest.raises(SettingsError) as startup:
        settings.assert_runtime_safe()
    assert expected in str(startup.value)
    assert "refusing to start" in str(startup.value)
    # ...and the factory refuses too, so a script that skips startup cannot build it either.
    with pytest.raises(SettingsError):
        get_blob_store(settings)


@pytest.mark.parametrize("tier", [Environment.dev, Environment.test, Environment.ci])
@pytest.mark.parametrize("backend", ["local", "memory"])
def test_the_same_configurations_are_accepted_outside_production(tier: Environment, backend: str) -> None:
    """The matching acceptance: the guard is a guard, not a blanket refusal."""
    settings = Settings(_env_file=None, cardioauth_env=tier, blob_backend=backend)  # type: ignore[arg-type]
    settings.assert_runtime_safe()
    store = get_blob_store(settings)
    assert store.name == backend


def test_dev_accepts_s3_without_server_side_encryption_but_production_does_not() -> None:
    dev = Settings(
        _env_file=None,
        cardioauth_env=Environment.dev,
        blob_backend="s3",
        s3_bucket="cardioauth-dev",
        s3_region="us-east-1",
        s3_endpoint_url="http://localhost:9000",
        s3_addressing_style="path",
    )
    dev.assert_storage_safe()  # MinIO in compose has no SSE configured
    with pytest.raises(SettingsError):
        production(s3_server_side_encryption=None).assert_storage_safe()


def test_the_factory_is_where_the_guard_bites_not_only_startup() -> None:
    """A worker that never calls assert_runtime_safe still cannot build a local store."""
    with pytest.raises(SettingsError) as excinfo:
        get_blob_store(production(blob_backend="local"))
    assert "refusing to use the configured storage" in str(excinfo.value)


def test_production_store_is_encrypted_and_scoped() -> None:
    """Composition check: a production store is encrypted and practice-scoped."""
    from cardioauth.blobs import EncryptedBlobStore, PracticeScopedBlobStore
    from cardioauth.blobs.s3 import S3BlobStore

    import boto3
    moto = pytest.importorskip("moto")
    import uuid

    with moto.mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="cardioauth-prod")
        settings = production(s3_use_ssl=True)
        store = get_blob_store(settings, practice_id=uuid.uuid4(), client=client)
        assert isinstance(store, PracticeScopedBlobStore)
        assert isinstance(store.inner, EncryptedBlobStore)
        assert isinstance(store.inner.inner, S3BlobStore)
        assert store.inner.encryption == "app-envelope-aes-256-gcm-v1"
