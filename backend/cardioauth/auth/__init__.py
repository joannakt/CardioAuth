"""The identity and session core (M1b-1, DESIGN.md §2.1, §7.1, §7.2).

* :mod:`cardioauth.auth.service` — policy: passwords, lockout, TOTP, sessions, step-up
* :mod:`cardioauth.auth.deps`    — the dependencies protected routes use
* :mod:`cardioauth.auth.router`  — ``/api/auth`` endpoints
* :mod:`cardioauth.auth.schemas` — request/response models
"""

from __future__ import annotations

__all__: list[str] = []
