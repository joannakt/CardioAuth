"""Pydantic domain schemas (§3) — the single source of truth for API bodies, the JSON
Schema handed to an LLM provider, and worker payloads. Arrives in M1b (auth/session
schemas) and M3/M4 (extraction, criteria evaluation, letter AST, claim verification).

No schema is defined in M1a on purpose: an invented schema now would constrain the
milestones that own it, and nothing in M1a needs one.
"""

from __future__ import annotations

__all__: list[str] = []
