#!/usr/bin/env python3
"""Verify the CardioAuth audit hash chain from the command line.

Thin entry point over ``cardioauth.audit.chain`` so the same code path the application
uses is the one an operator runs. Non-zero exit means the chain is broken.

    python scripts/audit_chain_verify.py --database-url postgresql+psycopg://user:pw@host/db

With no ``--database-url`` the URL comes from Settings (``DATABASE_URL``).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from cardioauth.audit.chain import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
