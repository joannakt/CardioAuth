"""Single source of truth for every environment variable, plus the production guards.

Nothing else in the codebase reads ``os.environ`` (enforced by
``tests/test_settings_guards.py``). Every variable has a safe default so a clean clone
runs with no ``.env``; the defaults are *dev* defaults and are refused under
``CARDIOAUTH_ENV=production``.
"""

from __future__ import annotations

import functools
import logging
from enum import Enum
from typing import ClassVar, Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

DEV_APP_KEY = "dev-only-insecure-app-key-change-me"  # noqa: S105 - dev default, refused in production
#: Minimum APP_KEY length in bytes. Mirrors ``security.crypto.MIN_APP_KEY_BYTES`` (kept here
#: too so the production guard can state the requirement without importing the crypto stack).
MIN_APP_KEY_BYTES = 32


class Environment(str, Enum):
    dev = "dev"
    test = "test"
    ci = "ci"
    production = "production"


class SettingsError(RuntimeError):
    """Raised when the selected configuration is not safe to run. Fails the process."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env",),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- environment tier (§1.3) -------------------------------------------
    cardioauth_env: Environment = Environment.dev

    # --- app ---------------------------------------------------------------
    app_key: SecretStr = SecretStr(DEV_APP_KEY)
    log_level: str = "INFO"
    log_format: Literal["json", "console"] = "json"
    public_origin: str = "http://localhost:3000"

    # --- database ----------------------------------------------------------
    database_url: str = "postgresql+psycopg://cardioauth:cardioauth@localhost:5432/cardioauth"
    database_echo: bool = False
    database_pool_size: int = 5
    database_max_overflow: int = 5
    database_connect_timeout_s: int = 5
    database_require_tls: bool = False
    # Used only by the test suite; never read by the application.
    cardioauth_test_database_url: str | None = None

    # --- jobs / workers ----------------------------------------------------
    jobs_inline: bool = True  # dev default: no worker container needed
    worker_poll_interval_s: float = 2.0

    # --- PHI logging (§4.2, §7.5) ------------------------------------------
    # 'dev' permits LLM prompt/response bodies under logs/llm/ (git-ignored) in dev only.
    cardioauth_phi_logging: Literal["off", "dev"] = "dev"

    # --- LLM provider (§4.1, §4.2) ----------------------------------------
    llm_provider: str = "mock"
    llm_model: str = "mock-extract-v1"
    llm_api_key: SecretStr | None = None
    llm_base_url: str | None = None
    llm_temperature: float = 0.0
    llm_timeout_s: int = 120
    llm_max_retries: int = 2
    llm_fallback_provider: str | None = None
    llm_task_model_extract: str | None = None
    llm_task_model_verify: str | None = None

    # --- OCR (§5.1) --------------------------------------------------------
    ocr_backend: str = "pdf_text_layer"  # pdf_text_layer | tesseract | textract
    ocr_tesseract_lang: str = "eng"
    ocr_max_pages_per_document: int = 200

    # --- blob storage (§1.3) ----------------------------------------------
    # 'local' (dev/test filesystem) and 'memory' (in-process, tests only) are refused under
    # CARDIOAUTH_ENV=production by storage_problems(); 's3' is the HIPAA-eligible path.
    blob_backend: Literal["local", "s3", "memory"] = "local"
    blob_local_root: str = "./data/blobs"
    #: Application-level envelope encryption on top of the backend (§1.3). On by default and
    #: refused when disabled in production: the bucket's server-side encryption protects the
    #: volume, this protects the bytes from a misconfigured bucket, a stray backup or an
    #: operator with read access. See cardioauth/blobs/envelope.py.
    blob_app_encryption: bool = True
    #: Streaming chunk for reads and for one AES-GCM record.
    blob_chunk_size_bytes: int = 64 * 1024
    s3_endpoint_url: str | None = None
    s3_bucket: str | None = None
    s3_region: str | None = None
    s3_access_key_id: str | None = None
    s3_secret_access_key: SecretStr | None = None
    s3_use_ssl: bool = True
    s3_server_side_encryption: str | None = None  # e.g. 'aws:kms' (or 'AES256')
    s3_kms_key_id: str | None = None
    #: 'path' is what MinIO wants; 'virtual' is what AWS prefers; 'auto' lets botocore decide.
    s3_addressing_style: Literal["auto", "path", "virtual"] = "auto"
    #: Dev convenience only: create the bucket on first use. Refused in production, where
    #: bucket creation is infrastructure's job and an implicit create hides a typo.
    s3_create_bucket_if_missing: bool = False

    # --- sessions and second factor (§7.1, §7.2, §11 Q4) -------------------
    session_cookie_name: str = "cardioauth_session"
    session_cookie_secure: bool = False  # dev default; forced true under production
    session_cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    session_idle_minutes: int = 15
    session_absolute_hours: int = 8
    session_reauth_minutes: int = 5
    totp_issuer: str = "CardioAuth"
    # --- password policy, Argon2id and lockout (§7.1) ----------------------
    # Argon2id parameters are the design's (memory 64 MiB, time 3, parallelism 4).
    argon2_memory_kib: int = 65536
    argon2_time_cost: int = 3
    argon2_parallelism: int = 4
    argon2_hash_len: int = 32
    password_min_length: int = 12
    password_max_length: int = 128
    # None = use the list bundled with the package; set a path for the full top-100k list.
    password_breach_list_path: str | None = None
    auth_lockout_threshold: int = 5
    auth_lockout_base_minutes: int = 15
    auth_lockout_max_minutes: int = 1440
    # --- TOTP (§7.1) -------------------------------------------------------
    totp_digits: int = 6
    totp_period_seconds: int = 30
    totp_drift_steps: int = 1  # ±1 step, per the design
    totp_recovery_code_count: int = 10
    # Roles that must have a second factor enrolled to complete a login. Coordinators are
    # prompted (and flagged) rather than blocked — §7.1 and §11 Q4.
    totp_required_roles: str = "physician,admin"

    # --- data locations ----------------------------------------------------
    criteria_dir: str = "./data/criteria"
    synthetic_dir: str = "./data/synthetic"
    artifacts_dir: str = "./data/exports"
    document_max_bytes: int = 50 * 1024 * 1024

    @model_validator(mode="after")
    def _coerce_tier(self) -> Settings:
        # A test/CI run must never be able to point at a production database tier.
        if self.cardioauth_env in (Environment.test, Environment.ci) and self.database_require_tls is False:
            object.__setattr__(self, "database_require_tls", self.database_require_tls)
        return self

    @property
    def is_production(self) -> bool:
        return self.cardioauth_env is Environment.production

    @property
    def cookie_secure(self) -> bool:
        return self.is_production or self.session_cookie_secure

    @property
    def totp_required_role_set(self) -> frozenset[str]:
        return frozenset(part.strip() for part in self.totp_required_roles.split(",") if part.strip())

    @property
    def app_key_bytes(self) -> bytes:
        return self.app_key.get_secret_value().encode("utf-8")

    def assert_runtime_safe(self) -> None:
        """Refuse to start when the configuration is unsafe. Called at startup and by
        Alembic before it opens a connection (§1.3, §4.2)."""
        problems: list[str] = []

        if self.is_production:
            if self.llm_provider in {"mock", "recording"}:
                problems.append(
                    f"LLM_PROVIDER={self.llm_provider} is a development provider and is refused "
                    "under CARDIOAUTH_ENV=production (§4.2)"
                )
            if self.cardioauth_phi_logging == "dev":
                problems.append(
                    "CARDIOAUTH_PHI_LOGGING=dev would write document text; it is refused under "
                    "CARDIOAUTH_ENV=production (§7.5)"
                )
            if self.app_key.get_secret_value() == DEV_APP_KEY:
                problems.append("APP_KEY is still the development default; it protects TOTP secrets at rest")
            elif len(self.app_key_bytes) < MIN_APP_KEY_BYTES:
                # Key material for the identity core: TOTP secrets are AES-GCM encrypted with a
                # key derived from APP_KEY and every keyed digest uses it. Production must not
                # start with a short key (crypto.CryptoKeyError would otherwise surface at the
                # first enrolment instead of at startup).
                problems.append(
                    f"APP_KEY is {len(self.app_key_bytes)} bytes; at least {MIN_APP_KEY_BYTES} "
                    "bytes of key material are required (TOTP secret encryption, keyed hashing)"
                )
            if self.database_require_tls is False:
                problems.append("DATABASE_REQUIRE_TLS=false: production database traffic must be encrypted in transit")
            if self.session_cookie_secure is False:
                problems.append("SESSION_COOKIE_SECURE=false: production session cookies must be Secure")
        else:
            if self.cardioauth_phi_logging == "dev":
                logger.warning(
                    "CARDIOAUTH_PHI_LOGGING=dev: LLM prompt/response bodies may be written under logs/llm/ "
                    "(env=%s). This must never be selected outside dev.",
                    self.cardioauth_env.value,
                )

        # Storage rules live in one place so the startup guard and the BlobStore factory
        # cannot disagree about what "safe" means (see storage_problems()).
        problems.extend(self.storage_problems())

        if problems:
            raise SettingsError(
                "refusing to start: " + "; ".join(problems) + ". Fix the configuration or change CARDIOAUTH_ENV."
            )

    #: Backends that keep PHI somewhere this build does not manage (a local volume) or nowhere
    #: at all (in-process memory). Both are fine in dev/test and refused in production.
    DEV_ONLY_BLOB_BACKENDS: ClassVar[frozenset[str]] = frozenset({"local", "memory"})

    def storage_problems(self) -> list[str]:
        """Every reason the configured storage is not safe, as human-readable strings.

        One list, two callers: :meth:`assert_runtime_safe` (startup, which fails the process)
        and :func:`cardioauth.blobs.get_blob_store` (the factory, which refuses to build a
        backend that the process should never have been allowed to select). A guard that only
        exists at startup is a guard a script or a worker can bypass; a guard that only exists
        in the factory is a guard that fails at first upload instead of at boot.
        """
        problems: list[str] = []

        if self.is_production:
            if self.blob_backend == "local":
                problems.append(
                    "BLOB_BACKEND=local stores PHI on an unmanaged filesystem; it is refused under "
                    "CARDIOAUTH_ENV=production (§4.2)"
                )
            elif self.blob_backend in self.DEV_ONLY_BLOB_BACKENDS:
                problems.append(
                    f"BLOB_BACKEND={self.blob_backend} is a development backend (no durable storage, "
                    "no encryption at rest); it is refused under CARDIOAUTH_ENV=production"
                )
            if not self.blob_app_encryption:
                problems.append(
                    "BLOB_APP_ENCRYPTION=false leaves documents protected only by the provider's "
                    "bucket configuration; application-level envelope encryption is required under "
                    "CARDIOAUTH_ENV=production (it layers on top of server-side encryption, it does "
                    "not replace it)"
                )
            if self.s3_create_bucket_if_missing:
                problems.append(
                    "S3_CREATE_BUCKET_IF_MISSING=true is a development convenience; in production the "
                    "bucket is created by infrastructure, and creating it implicitly would hide a typo "
                    "in S3_BUCKET"
                )
            if self.blob_backend == "s3" and not self.s3_use_ssl:
                problems.append("S3_USE_SSL=false: document bytes must be encrypted in transit")

        if self.blob_backend == "s3":
            missing = [
                name
                for name, value in (
                    ("S3_BUCKET", self.s3_bucket),
                    ("S3_REGION", self.s3_region),
                )
                if not value
            ]
            if self.is_production and not self.s3_server_side_encryption:
                missing.append("S3_SERVER_SIDE_ENCRYPTION")
            if missing:
                problems.append(
                    "BLOB_BACKEND=s3 is incompletely configured: missing "
                    + ", ".join(missing)
                    + ". Server-side encryption (S3_SERVER_SIDE_ENCRYPTION, e.g. 'aws:kms') is "
                    "required under CARDIOAUTH_ENV=production"
                )
            if self.s3_kms_key_id and not self.s3_server_side_encryption:
                problems.append(
                    "S3_KMS_KEY_ID is set but S3_SERVER_SIDE_ENCRYPTION is not: the key would be "
                    "ignored, so the objects would not be encrypted with the key you selected"
                )

        # Credentials are a pair: one without the other is a misconfiguration that would fail at
        # the first upload (or, worse, silently fall back to an anonymous request) in any tier.
        if bool(self.s3_access_key_id) != bool(self.s3_secret_access_key):
            problems.append(
                "S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY must be set together (or both left unset "
                "to use the instance role); exactly one is set"
            )
        if self.document_max_bytes <= 0:
            problems.append("DOCUMENT_MAX_BYTES must be positive: the store refuses every object otherwise")
        if self.blob_chunk_size_bytes <= 0:
            problems.append("BLOB_CHUNK_SIZE_BYTES must be positive")
        return problems

    def assert_storage_safe(self) -> None:
        """Refuse to build a storage backend the configuration does not permit."""
        problems = self.storage_problems()
        if problems:
            raise SettingsError(
                "refusing to use the configured storage: "
                + "; ".join(problems)
                + ". Fix the configuration or change CARDIOAUTH_ENV."
            )

    def bucket_configured_for_production(self) -> bool:
        if self.blob_backend != "s3":
            return True
        return bool(self.s3_bucket and self.s3_region and self.s3_server_side_encryption)

    def assert_lab_role(self) -> None:
        """Refuse to load synthetic/placeholder fixtures outside dev, test and CI (§1.3)."""
        if self.is_production:
            raise SettingsError(
                "refusing to load synthetic fixtures or placeholder criteria under "
                "CARDIOAUTH_ENV=production"
            )


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings accessor. Tests call ``get_settings.cache_clear()``."""
    return Settings()
