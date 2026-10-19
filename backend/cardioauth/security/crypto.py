"""Cryptographic primitives for the identity core (DESIGN.md §7.1).

One rule for everything in this module: a secret is either *encrypted* (recoverable, for a
value the application must replay — the TOTP shared secret) or *hashed* (never recoverable —
session tokens, TOTP codes, recovery codes, IP and user-agent fingerprints). Nothing is
stored in the clear, and nothing is hashed with a bare ``sha256`` where the input space is
small enough to enumerate offline (an IPv4 address, a 6-digit TOTP code): those use a
keyed HMAC whose key is derived from ``APP_KEY`` and never leaves the process.

Key separation: every purpose has its own HKDF ``info`` string, so the encryption key, the
IP-fingerprint key and the TOTP-code key are different keys even though all are derived
from the same ``APP_KEY``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cardioauth.settings import MIN_APP_KEY_BYTES as MIN_APP_KEY_BYTES
from cardioauth.settings import Settings, get_settings

#: HKDF salts/info strings — one per purpose (key separation).
_KDF_SALT = b"cardioauth/kdf/v1"
_PURPOSE_TOTP_SECRET = b"totp-secret-encryption/v1"
_PURPOSE_TOTP_CODE = b"totp-code-ledger/v1"
_PURPOSE_RECOVERY_CODE = b"recovery-code/v1"
_PURPOSE_REQUEST_FINGERPRINT = b"request-fingerprint/v1"

AES_GCM_NONCE_BYTES = 12


class CryptoKeyError(RuntimeError):
    """APP_KEY is missing or too weak for the key material this build requires.

    Raised at startup (see :meth:`Settings.assert_runtime_safe`) rather than degrading to a
    weaker scheme: a production run without key material must not silently fall back.
    """


def _app_key_bytes(settings: Settings) -> bytes:
    raw = settings.app_key.get_secret_value().encode("utf-8")
    if len(raw) < MIN_APP_KEY_BYTES:
        raise CryptoKeyError(
            f"APP_KEY is {len(raw)} bytes; at least {MIN_APP_KEY_BYTES} are required for the "
            "identity core (TOTP secret encryption and keyed hashing). Set a strong APP_KEY."
        )
    return raw


@lru_cache(maxsize=16)
def _derived_key(app_key: bytes, purpose: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KDF_SALT,
        info=purpose,
    ).derive(app_key)


def _key_for(settings: Settings, purpose: bytes) -> bytes:
    return _derived_key(_app_key_bytes(settings), purpose)


def encrypt_secret(plaintext: str, *, settings: Settings | None = None) -> bytes:
    """AES-256-GCM encrypt a recoverable secret (the TOTP shared secret).

    Output layout: ``nonce(12) || ciphertext || tag(16)``. The nonce is random per call.
    """
    settings = settings or get_settings()
    key = _key_for(settings, _PURPOSE_TOTP_SECRET)
    nonce = os.urandom(AES_GCM_NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ciphertext


def decrypt_secret(blob: bytes, *, settings: Settings | None = None) -> str:
    """Reverse :func:`encrypt_secret`. Raises :class:`CryptoKeyError` on tamper or wrong key."""
    settings = settings or get_settings()
    key = _key_for(settings, _PURPOSE_TOTP_SECRET)
    if len(blob) <= AES_GCM_NONCE_BYTES:
        raise CryptoKeyError("stored secret is truncated; refusing to decrypt a partial blob")
    nonce, ciphertext = blob[:AES_GCM_NONCE_BYTES], blob[AES_GCM_NONCE_BYTES:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")
    except InvalidTag as exc:
        raise CryptoKeyError(
            "stored secret failed authentication (wrong APP_KEY or tampered ciphertext)"
        ) from exc


def _keyed_digest(purpose: bytes, value: str, *, settings: Settings | None = None) -> bytes:
    settings = settings or get_settings()
    key = _key_for(settings, purpose)
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()


def fingerprint_totp_code(code: str, *, settings: Settings | None = None) -> bytes:
    """Keyed digest of a 6-digit TOTP code for the single-use ledger.

    A plain SHA-256 of a 6-digit code is a 10^6 lookup table; the keyed digest is not.
    """
    return _keyed_digest(_PURPOSE_TOTP_CODE, code.strip(), settings=settings)


def fingerprint_recovery_code(code: str, *, settings: Settings | None = None) -> bytes:
    """Keyed digest of a recovery code (normalised: separators and case removed)."""
    from cardioauth.security.totp import normalize_recovery_code  # local: avoids a cycle

    return _keyed_digest(_PURPOSE_RECOVERY_CODE, normalize_recovery_code(code), settings=settings)


def hash_request_fingerprint(value: str | None, *, settings: Settings | None = None) -> bytes | None:
    """Keyed digest of an IP address or user-agent string (``user_session.ip_hash`` etc.).

    Keyed, not plain: the IPv4 space is small enough to enumerate, so an unkeyed digest of
    an address is an address. A plain SHA-256 of the *session cookie* is fine (256 bits of
    entropy) and is done in :mod:`cardioauth.security.tokens`.
    """
    if not value:
        return None
    return _keyed_digest(_PURPOSE_REQUEST_FINGERPRINT, value, settings=settings)


def constant_time_equals(left: bytes, right: bytes) -> bool:
    return hmac.compare_digest(left, right)
