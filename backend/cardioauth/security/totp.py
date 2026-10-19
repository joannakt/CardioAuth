"""TOTP second factor (RFC 6238) — DESIGN.md §7.1, §11 Q4.

Parameters are the design's: SHA-1 (what authenticator apps assume), 6 digits, 30-second
step, **±1 step drift**. ``pyotp`` generates the secret and the provisioning URI; the
verification and replay logic are here so the drift window and the single-use rule are
explicit and testable rather than inherited from a library default.

Explicitly decided here (design silent):
* a code is consumed at most once *per matched time step* — the ledger row is
  (user, keyed-hash(code), step), so a replay inside the same step always fails, while a
  coincidental repeat of a 6-digit value in a later step is still accepted;
* recovery codes are 10 codes of 12 characters from a 32-character alphabet
  (60 bits each), hashed with a keyed HMAC-SHA256 — see ``security/crypto.py`` for why a
  fast keyed digest (not Argon2) is the right primitive for a high-entropy machine-generated
  code.
"""

from __future__ import annotations

import hmac
import secrets
import time
from dataclasses import dataclass
from urllib.parse import quote, urlencode

import pyotp

from cardioauth.settings import Settings, get_settings

RECOVERY_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I
RECOVERY_CODE_GROUPS = 3
RECOVERY_CODE_GROUP_LEN = 4
RECOVERY_CODE_LEN = RECOVERY_CODE_GROUPS * RECOVERY_CODE_GROUP_LEN


@dataclass(frozen=True)
class TotpVerification:
    ok: bool
    time_step: int | None = None  # the RFC 6238 step the code matched


def generate_secret() -> str:
    """A fresh base32 TOTP shared secret (160 bits, what authenticator apps expect)."""
    return pyotp.random_base32()


def _issuer(settings: Settings, issuer: str | None) -> str:
    return issuer or settings.totp_issuer


def provisioning_uri(secret: str, *, account: str, issuer: str | None = None, settings: Settings | None = None) -> str:
    """``otpauth://`` URI for an authenticator app. Contains the secret — never log it."""
    settings = settings or get_settings()
    return pyotp.TOTP(
        secret, digits=settings.totp_digits, interval=settings.totp_period_seconds
    ).provisioning_uri(name=account, issuer_name=_issuer(settings, issuer))


def otpauth_payload(
    secret: str, *, account: str, issuer: str | None = None, settings: Settings | None = None
) -> dict[str, object]:
    """Everything a client needs to render the enrolment screen (no QR library dependency).

    The payload is the standard ``otpauth`` label/parameters so any client can build the QR
    code itself; the URI is the canonical form of the same values.
    """
    settings = settings or get_settings()
    resolved_issuer = _issuer(settings, issuer)
    uri = provisioning_uri(secret, account=account, issuer=resolved_issuer, settings=settings)
    return {
        "type": "totp",
        "secret": secret,
        "uri": uri,
        "issuer": resolved_issuer,
        "account": account,
        "algorithm": "SHA1",
        "digits": settings.totp_digits,
        "period_seconds": settings.totp_period_seconds,
        "drift_steps": settings.totp_drift_steps,
        "manual_entry_key": " ".join(secret[i : i + 4] for i in range(0, len(secret), 4)),
        "label": f"{quote(resolved_issuer)}:{quote(account)}",
        "parameters": urlencode(
            {
                "secret": secret,
                "issuer": resolved_issuer,
                "algorithm": "SHA1",
                "digits": str(settings.totp_digits),
                "period": str(settings.totp_period_seconds),
            }
        ),
    }


def current_step(settings: Settings, at: float | None = None) -> int:
    return int((time.time() if at is None else at) // settings.totp_period_seconds)


def verify_code(
    secret: str,
    code: str,
    *,
    at: float | None = None,
    settings: Settings | None = None,
) -> TotpVerification:
    """Verify a 6-digit code inside the configured drift window.

    Returns the RFC 6238 step that matched (the caller records it in the single-use ledger)
    or ``ok=False`` when no step in the window produces the code. Comparison is
    constant-time, so a wrong code cannot be narrowed down by timing.
    """
    settings = settings or get_settings()
    candidate = (code or "").strip().replace(" ", "")
    if not (candidate.isdigit() and len(candidate) == settings.totp_digits):
        return TotpVerification(ok=False)
    totp = pyotp.TOTP(secret, digits=settings.totp_digits, interval=settings.totp_period_seconds)
    reference = time.time() if at is None else at
    for offset in range(-settings.totp_drift_steps, settings.totp_drift_steps + 1):
        step = int(reference // settings.totp_period_seconds) + offset
        expected = totp.at(step * settings.totp_period_seconds)
        if hmac.compare_digest(expected, candidate):
            return TotpVerification(ok=True, time_step=step)
    return TotpVerification(ok=False)


def normalize_recovery_code(code: str) -> str:
    """Upper-case and strip separators/spaces, so ``abcd-efgh`` == ``ABCDEFGH``."""
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def generate_recovery_codes(count: int | None = None, *, settings: Settings | None = None) -> list[str]:
    """Plaintext recovery codes, shown once at issue. Formatted ``XXXX-XXXX-XXXX``."""
    settings = settings or get_settings()
    total = count if count is not None else settings.totp_recovery_code_count
    codes: list[str] = []
    for _ in range(total):
        raw = "".join(secrets.choice(RECOVERY_CODE_ALPHABET) for _ in range(RECOVERY_CODE_LEN))
        codes.append("-".join(raw[i : i + RECOVERY_CODE_GROUP_LEN] for i in range(0, RECOVERY_CODE_LEN,
                                                                              RECOVERY_CODE_GROUP_LEN)))
    return codes


def looks_like_recovery_code(value: str, *, settings: Settings | None = None) -> bool:
    """Distinguishes a recovery code from a 6-digit TOTP code on the same endpoint."""
    settings = settings or get_settings()
    return len(normalize_recovery_code(value)) == RECOVERY_CODE_LEN
