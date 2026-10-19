"""Password hashing and the password policy (DESIGN.md §7.1).

Hashing: **Argon2id**, per-user random salt, parameters from settings (design default:
memory 64 MiB, time cost 3, parallelism 4). A successful login verifies with the *stored*
parameters and re-hashes transparently when the configured parameters have moved on, so
tightening the parameters does not invalidate existing passwords.

Policy (this build):
* minimum 12 characters (design §7.1) and a 128-character ceiling;
* must not appear in the locally bundled breach list (no network call with a candidate
  password, ever — design §7.1);
* must not be the user's email local part or their full name, and must not contain them;
* NFKC-normalised before hashing, so a password typed on another keyboard/locale hashes
  identically.

Deliberately *not* in the policy: mandatory character-class composition and forced expiry.
Both are discouraged by NIST SP 800-63B (they push users toward predictable patterns);
length plus a breach list is the stronger pair. Recorded here because the design is silent
on composition rules.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from argon2 import PasswordHasher
from argon2 import exceptions as argon2_exceptions
from argon2.low_level import Type

from cardioauth.settings import Settings, get_settings

#: Bundled starter list. The full top-100k list is dropped in at deployment; see the file's
#: own header and ``Settings.password_breach_list_path``.
BUNDLED_BREACH_LIST = Path(__file__).resolve().parent / "data" / "common_passwords_small.txt"


class PasswordPolicyError(ValueError):
    """The candidate password is refused by policy. Message is safe to return to a user."""


def normalize_password(password: str) -> str:
    """NFKC-normalise (not strip: leading/trailing spaces are legitimate password material)."""
    return unicodedata.normalize("NFKC", password)


@lru_cache(maxsize=4)
def _load_breach_list(path: str, mtime: float) -> frozenset[str]:
    """Casefolded entries, loaded once per (path, mtime). ``mtime`` is part of the cache key
    so replacing the file at runtime is picked up without a restart."""
    entries: set[str] = set()
    file = Path(path)
    if not file.exists():
        return frozenset()
    for line in file.read_text(encoding="utf-8", errors="ignore").splitlines():
        entry = line.strip()
        if entry and not entry.startswith("#"):
            entries.add(normalize_password(entry).casefold())
    return frozenset(entries)


def _breach_list(settings: Settings) -> frozenset[str]:
    path = _breach_path(settings)
    mtime = path.stat().st_mtime if path.exists() else 0.0
    return _load_breach_list(str(path), mtime)


def _breach_path(settings: Settings) -> Path:
    """The configured list when one is set, otherwise the bundled starter list."""
    return Path(settings.password_breach_list_path) if settings.password_breach_list_path else BUNDLED_BREACH_LIST


def breach_list_size(settings: Settings | None = None) -> int:
    return len(_breach_list(settings or get_settings()))


def is_breached(password: str, *, settings: Settings | None = None) -> bool:
    """Case-insensitive membership test against the bundled breach list."""
    return normalize_password(password).casefold() in _breach_list(settings or get_settings())


def hasher(settings: Settings | None = None) -> PasswordHasher:
    settings = settings or get_settings()
    return PasswordHasher(
        time_cost=settings.argon2_time_cost,
        memory_cost=settings.argon2_memory_kib,
        parallelism=settings.argon2_parallelism,
        hash_len=settings.argon2_hash_len,
        salt_len=16,
        type=Type.ID,  # Argon2id
    )


def hash_password(password: str, *, settings: Settings | None = None) -> str:
    return hasher(settings).hash(normalize_password(password))


@dataclass(frozen=True)
class PasswordCheck:
    ok: bool
    needs_rehash: bool = False


def verify_password(stored_hash: str, password: str, *, settings: Settings | None = None) -> PasswordCheck:
    """Verify a password against a stored Argon2 hash.

    A malformed or unknown-algorithm stored hash returns ``ok=False`` (never an exception
    with hash material in the message).
    """
    ph = hasher(settings)
    try:
        ph.verify(stored_hash, normalize_password(password))
    except (argon2_exceptions.VerifyMismatchError, argon2_exceptions.InvalidHashError):
        return PasswordCheck(ok=False)
    except argon2_exceptions.VerificationError:  # pragma: no cover - defensive
        return PasswordCheck(ok=False)
    except argon2_exceptions.HashingError:  # pragma: no cover - defensive
        return PasswordCheck(ok=False)
    try:
        return PasswordCheck(ok=True, needs_rehash=ph.check_needs_rehash(stored_hash))
    except (argon2_exceptions.InvalidHashError, argon2_exceptions.HashingError):  # pragma: no cover
        return PasswordCheck(ok=True, needs_rehash=False)


def check_policy(
    password: str,
    *,
    email: str | None = None,
    full_name: str | None = None,
    settings: Settings | None = None,
) -> None:
    """Raise :class:`PasswordPolicyError` when *password* is unacceptable. Returns None."""
    settings = settings or get_settings()
    normalized = normalize_password(password)
    if len(normalized) < settings.password_min_length:
        raise PasswordPolicyError(
            f"password must be at least {settings.password_min_length} characters"
        )
    if len(normalized) > settings.password_max_length:
        raise PasswordPolicyError(
            f"password must be at most {settings.password_max_length} characters"
        )
    if not normalized.strip():
        raise PasswordPolicyError("password must contain a non-space character")
    if is_breached(normalized, settings=settings):
        raise PasswordPolicyError("password appears in a known-breached password list; choose another")
    local_part = (email or "").split("@")[0].strip().casefold()
    if local_part and len(local_part) >= 3 and local_part in normalized.casefold():
        raise PasswordPolicyError("password must not contain the email address")
    # Every word of the account holder's name, not only the full string: "Ada Lovelace" should
    # reject "lovelace-2026" as firmly as "adalovelace2026".
    lowered = normalized.casefold()
    name_tokens = [token for token in (full_name or "").replace(",", " ").split() if len(token) >= 3]
    for token in name_tokens:
        if token.casefold() in lowered:
            raise PasswordPolicyError("password must not contain the user's name")


def enforce_and_hash(
    password: str,
    *,
    email: str | None = None,
    full_name: str | None = None,
    settings: Settings | None = None,
) -> str:
    check_policy(password, email=email, full_name=full_name, settings=settings)
    return hash_password(password, settings=settings)
