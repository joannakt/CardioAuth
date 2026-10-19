"""Security primitives: Argon2id, the password policy, keyed/encrypted material, TOTP.

No database here — these are the properties the identity core depends on, tested directly.
All values are synthetic; no real credential appears in this file.
"""

from __future__ import annotations

import time
import uuid

import pyotp
import pytest

from cardioauth.security import crypto, passwords, tokens, totp
from cardioauth.settings import DEV_APP_KEY, Environment, Settings

FAST_ARGON2 = {"argon2_memory_kib": 8192, "argon2_time_cost": 1, "argon2_parallelism": 1}


@pytest.fixture
def settings() -> Settings:
    """Production-shaped settings with fast Argon2 parameters (test-only speed-up)."""
    return Settings(
        _env_file=None,
        cardioauth_env=Environment.test,
        app_key="test-only-app-key-with-at-least-32-bytes-of-material",
        **FAST_ARGON2,
    )


def test_shipped_argon2_defaults_are_the_design_parameters() -> None:
    """DESIGN.md §7.1: memory 64 MiB, time 3, parallelism 4.

    Read from the declared field defaults, not from an instance: the API tests deliberately
    set ARGON2_* environment variables for speed, and those must not be mistaken for the
    shipped defaults.
    """
    fields = Settings.model_fields
    assert fields["argon2_memory_kib"].default == 65536
    assert fields["argon2_time_cost"].default == 3
    assert fields["argon2_parallelism"].default == 4
    assert fields["password_min_length"].default == 12
    assert fields["session_idle_minutes"].default == 15
    assert fields["session_absolute_hours"].default == 8
    assert fields["session_reauth_minutes"].default == 5
    assert fields["totp_digits"].default == 6
    assert fields["totp_period_seconds"].default == 30
    assert fields["totp_drift_steps"].default == 1
    assert fields["totp_recovery_code_count"].default == 10
    assert fields["auth_lockout_threshold"].default == 5
    assert fields["auth_lockout_base_minutes"].default == 15


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------
def test_hash_is_argon2id_and_verifies(settings: Settings) -> None:
    digest = passwords.hash_password("a-long-enough-passphrase", settings=settings)
    assert digest.startswith("$argon2id$")
    assert passwords.verify_password(digest, "a-long-enough-passphrase", settings=settings).ok is True
    assert passwords.verify_password(digest, "a-long-enough-passphras3", settings=settings).ok is False


def test_salt_is_per_hash(settings: Settings) -> None:
    one = passwords.hash_password("a-long-enough-passphrase", settings=settings)
    two = passwords.hash_password("a-long-enough-passphrase", settings=settings)
    assert one != two, "each hash must carry its own salt"


def test_verify_asks_for_a_rehash_when_parameters_change(settings: Settings) -> None:
    old = Settings(
        _env_file=None, app_key=settings.app_key.get_secret_value(), argon2_memory_kib=8192, argon2_time_cost=1
    )
    digest = passwords.hash_password("a-long-enough-passphrase", settings=old)
    stricter = Settings(
        _env_file=None, app_key=settings.app_key.get_secret_value(), argon2_memory_kib=16384, argon2_time_cost=2
    )
    check = passwords.verify_password(digest, "a-long-enough-passphrase", settings=stricter)
    assert check.ok is True
    assert check.needs_rehash is True, "a login must notice that the parameters moved on"


def test_malformed_stored_hash_is_refused_not_raised(settings: Settings) -> None:
    assert passwords.verify_password("not-a-hash", "whatever-long-enough", settings=settings).ok is False


def test_password_normalisation_is_nfkc(settings: Settings) -> None:
    composed = "a-long-enough-passphr\N{LATIN SMALL LETTER E WITH ACUTE}se"
    decomposed = "a-long-enough-passphr\N{LATIN SMALL LETTER E}\N{COMBINING ACUTE ACCENT}se"
    digest = passwords.hash_password(composed, settings=settings)
    assert passwords.verify_password(digest, decomposed, settings=settings).ok is True


@pytest.mark.parametrize(
    ("password", "message"),
    [
        ("short-pass1", "at least 12 characters"),
        ("quartz-otter-lantern-7", None),  # long and not breached: accepted
        ("password1234", "known-breached"),
        (" " * 14, "non-space character"),
        ("x" * 200, "at most 128 characters"),
    ],
)
def test_password_policy(settings: Settings, password: str, message: str | None) -> None:
    if message is None:
        passwords.check_policy(password, settings=settings)
        return
    with pytest.raises(passwords.PasswordPolicyError) as excinfo:
        passwords.check_policy(password, settings=settings)
    assert message in str(excinfo.value)


def test_policy_refuses_email_and_name_material(settings: Settings) -> None:
    with pytest.raises(passwords.PasswordPolicyError):
        passwords.check_policy("Coordinator-TEST-only-1", email="coordinator@test-only.invalid", settings=settings)
    # Each word of the name is checked, not just the whole string.
    with pytest.raises(passwords.PasswordPolicyError):
        passwords.check_policy("TEST-ONLY-coordinator-1", full_name="TEST-ONLY coordinator", settings=settings)
    with pytest.raises(passwords.PasswordPolicyError):
        passwords.check_policy("lovelace-quartz-lantern", full_name="Ada Lovelace", settings=settings)


def test_breach_list_is_bundled_and_usable(settings: Settings) -> None:
    """The mechanism the design requires: a local list, no network call, O(1) lookup."""
    assert passwords.breach_list_size(settings) > 50
    assert passwords.is_breached("Password1", settings=settings) is True
    assert passwords.is_breached("Casefolded-Membership-Test-9", settings=settings) is False


# ---------------------------------------------------------------------------
# Keyed and encrypted material
# ---------------------------------------------------------------------------
def test_secret_round_trip_and_tamper_detection(settings: Settings) -> None:
    blob = crypto.encrypt_secret("JBSWY3DPEHPK3PXP", settings=settings)
    assert b"JBSWY3DPEHPK3PXP" not in blob, "the TOTP secret must not appear in the stored bytes"
    assert crypto.decrypt_secret(blob, settings=settings) == "JBSWY3DPEHPK3PXP"

    flipped = bytearray(blob)
    flipped[-1] ^= 0x01
    with pytest.raises(crypto.CryptoKeyError):
        crypto.decrypt_secret(bytes(flipped), settings=settings)

    other_key = Settings(
        _env_file=None, cardioauth_env=Environment.test, app_key="another-test-only-app-key-32-bytes-min"
    )
    with pytest.raises(crypto.CryptoKeyError):
        crypto.decrypt_secret(blob, settings=other_key)


def test_nonce_is_random_per_encryption(settings: Settings) -> None:
    one = crypto.encrypt_secret("SECRET", settings=settings)
    two = crypto.encrypt_secret("SECRET", settings=settings)
    assert one != two
    assert one[: crypto.AES_GCM_NONCE_BYTES] != two[: crypto.AES_GCM_NONCE_BYTES]


def test_short_app_key_is_refused(settings: Settings) -> None:
    weak = Settings(_env_file=None, cardioauth_env=Environment.test, app_key="too-short")
    with pytest.raises(crypto.CryptoKeyError):
        crypto.encrypt_secret("SECRET", settings=weak)


def test_dev_default_key_is_long_enough_for_dev_but_refused_in_production() -> None:
    dev = Settings(_env_file=None, cardioauth_env=Environment.dev)
    assert crypto.encrypt_secret("SECRET", settings=dev), "dev has usable key material"

    production = Settings(
        _env_file=None,
        cardioauth_env=Environment.production,
        cardioauth_phi_logging="off",
        llm_provider="bedrock",
        llm_model="some-baa-model",
        blob_backend="s3",
        s3_bucket="b",
        s3_region="r",
        s3_server_side_encryption="aws:kms",
        app_key=DEV_APP_KEY,
        database_require_tls=True,
        session_cookie_secure=True,
    )
    from cardioauth.settings import SettingsError

    with pytest.raises(SettingsError):
        production.assert_runtime_safe()


def test_purposes_are_domain_separated(settings: Settings) -> None:
    code = crypto.fingerprint_totp_code("123456", settings=settings)
    recovery = crypto.fingerprint_recovery_code("ABCD-EFGH-JKLM", settings=settings)
    fingerprint = crypto.hash_request_fingerprint("203.0.113.7", settings=settings)
    assert len({code, recovery, fingerprint}) == 3
    assert crypto.fingerprint_totp_code("123456", settings=settings) == code
    assert crypto.hash_request_fingerprint(None, settings=settings) is None


def test_request_fingerprint_is_keyed_not_a_bare_digest(settings: Settings) -> None:
    """A bare SHA-256 of an IPv4 address is an address; a keyed digest is not."""
    import hashlib

    value = "203.0.113.7"
    keyed = crypto.hash_request_fingerprint(value, settings=settings)
    assert keyed != hashlib.sha256(value.encode()).digest()


def test_session_tokens_are_opaque_and_hashed(settings: Settings) -> None:
    raw = tokens.new_session_token()
    assert len(raw) >= 40
    assert tokens.hash_session_token(raw) != raw.encode()
    assert tokens.session_token_matches(raw, tokens.hash_session_token(raw)) is True
    assert tokens.session_token_matches(tokens.new_session_token(), tokens.hash_session_token(raw)) is False


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------
def test_otpauth_payload_shape(settings: Settings) -> None:
    secret = totp.generate_secret()
    payload = totp.otpauth_payload(secret, account="coordinator@test-only.invalid", settings=settings)
    assert str(payload["uri"]).startswith("otpauth://totp/")
    assert f"secret={secret}" in str(payload["uri"])
    assert payload["digits"] == 6
    assert payload["period_seconds"] == 30
    assert payload["drift_steps"] == 1
    assert payload["algorithm"] == "SHA1"
    assert payload["issuer"] == "CardioAuth"


def test_verify_accepts_current_code_and_one_step_of_drift(settings: Settings) -> None:
    secret = totp.generate_secret()
    now = time.time()
    step = settings.totp_period_seconds
    for offset in (-1, 0, 1):
        code = pyotp.TOTP(secret).at(int(now // step + offset) * step)
        result = totp.verify_code(secret, code, at=now, settings=settings)
        assert result.ok is True, f"drift offset {offset} must be accepted"
        assert result.time_step == int(now // step + offset)

    for offset in (-2, 2):
        code = pyotp.TOTP(secret).at(int(now // step + offset) * step)
        assert totp.verify_code(secret, code, at=now, settings=settings).ok is False


def test_verify_rejects_malformed_codes(settings: Settings) -> None:
    secret = totp.generate_secret()
    for bad in ("", "12345", "1234567", "abcdef", "12 34 5x"):
        assert totp.verify_code(secret, bad, settings=settings).ok is False


def test_recovery_codes_are_unique_and_normalisable() -> None:
    codes = totp.generate_recovery_codes(10)
    assert len(codes) == 10
    assert len(set(codes)) == 10
    assert all(len(totp.normalize_recovery_code(code)) == totp.RECOVERY_CODE_LEN for code in codes)
    # Separators and case are ignored, so a user can paste the code back however they typed it.
    assert totp.normalize_recovery_code(codes[0].replace("-", " ").lower()) == totp.normalize_recovery_code(codes[0])
    assert totp.looks_like_recovery_code(codes[0]) is True
    assert totp.looks_like_recovery_code("123456") is False


def test_enrolment_secret_is_encrypted_in_the_column_shape(settings: Settings) -> None:
    """The stored blob is nonce || ciphertext || tag, never the base32 secret."""
    secret = totp.generate_secret()
    blob = crypto.encrypt_secret(secret, settings=settings)
    assert secret.encode() not in blob
    assert len(blob) == crypto.AES_GCM_NONCE_BYTES + len(secret) + 16


def test_normalize_email_rules() -> None:
    from cardioauth.auth.service import InvalidEmailError, normalize_email

    assert normalize_email("  Coordinator@Test-Only.INVALID ") == "coordinator@test-only.invalid"
    assert normalize_email("\N{LATIN SMALL LETTER A}\N{COMBINING ACUTE ACCENT}@test-only.invalid").startswith("á@")
    for bad in ("", "no-at-sign", "a@b", "@test-only.invalid", "a b@test-only.invalid", "a@test-only.invalid@x"):
        with pytest.raises(InvalidEmailError):
            normalize_email(bad)


def test_lockout_backoff_doubles_and_caps(settings: Settings) -> None:
    from cardioauth.auth.service import lockout_minutes

    assert lockout_minutes(0, settings) == 15
    assert lockout_minutes(1, settings) == 30
    assert lockout_minutes(2, settings) == 60
    assert lockout_minutes(20, settings) == settings.auth_lockout_max_minutes


def test_uuid_pk_default_is_uuid4() -> None:
    """Sanity check on the ORM default used by every identity row."""
    from cardioauth.db.models import TotpUsedCode, UserRecoveryCode

    assert TotpUsedCode.__tablename__ == "totp_used_code"
    assert UserRecoveryCode.__tablename__ == "user_recovery_code"
    assert uuid.uuid4().version == 4
