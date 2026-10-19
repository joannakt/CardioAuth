"""Security primitives for the identity core (M1b-1, DESIGN.md §7.1).

* :mod:`cardioauth.security.passwords` — Argon2id hashing and the password policy
* :mod:`cardioauth.security.crypto`    — AES-GCM secret encryption and keyed digests
* :mod:`cardioauth.security.tokens`    — opaque session tokens, hashed at rest
* :mod:`cardioauth.security.totp`      — TOTP verification, drift window, recovery codes

Nothing here reads the process environment: every key and parameter arrives through
:class:`cardioauth.settings.Settings`.
"""

from __future__ import annotations

__all__: list[str] = []
