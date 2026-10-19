"""Opaque session tokens and their at-rest representation (DESIGN.md §7.1, §2.1).

A session token is 256 bits from :func:`secrets.token_urlsafe`. Only its SHA-256 digest is
persisted (``user_session.token_hash``); the raw value exists only in the client's cookie.
A plain digest is correct *here* (unlike for an IP or a TOTP code) because the input space
is 2**256: there is nothing to enumerate.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

#: Bytes of entropy in a session token (design: "opaque 256-bit cookie value").
SESSION_TOKEN_BYTES = 32
TOKEN_HASH_BYTES = 32


def new_session_token() -> str:
    """A fresh opaque session token. Returned once; never stored in this form."""
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def hash_session_token(raw_token: str) -> bytes:
    """The value stored in ``user_session.token_hash``."""
    return hashlib.sha256(raw_token.encode("utf-8")).digest()


def session_token_matches(raw_token: str, stored_hash: bytes) -> bool:
    """Constant-time comparison of a presented token against a stored digest."""
    return hmac.compare_digest(hash_session_token(raw_token), bytes(stored_hash))


def new_one_time_secret(nbytes: int = 32) -> str:
    """Generic single-use URL-safe secret (invitations, out-of-band reset codes)."""
    return secrets.token_urlsafe(nbytes)
