#!/usr/bin/env python3
"""Re-validate every stored source span in the database (§2.5.5, invariant INV-1).

A "span" is the evidence that ties a clinical fact to one exact place in one version of
one document's page text (document / page / text version / offsets). If a span does not
validate, the fact it supports may not be used in a letter.

Checks, all read-only:
  1. every span's offsets are within the length of the page text version it cites;
  2. the span's quote is exactly the slice ``text_normalized[start:end]`` it points at;
  3. every fact has at least one span.

Exit codes: 0 = all spans valid, 1 = invalid spans found, 2 = could not run.

    python scripts/check_span_integrity.py --database-url postgresql+psycopg://user:pw@host/db
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from sqlalchemy import create_engine, text  # noqa: E402

ORPHAN_FACTS_SQL = text(
    """
    SELECT count(*) FROM cardioauth.document_fact f
    WHERE NOT EXISTS (SELECT 1 FROM cardioauth.fact_span s WHERE s.fact_id = f.id)
    """
)

OFFSET_SQL = text(
    """
    SELECT s.id,
           length(t.text_normalized) AS text_len,
           s.start_offset,
           s.end_offset
    FROM cardioauth.fact_span s
    JOIN cardioauth.page_text_version t ON t.id = s.page_text_version_id
    WHERE s.start_offset < 0
       OR s.end_offset < s.start_offset
       OR s.end_offset > length(t.text_normalized)
    """
)

QUOTE_SQL = text(
    """
    SELECT s.id
    FROM cardioauth.fact_span s
    JOIN cardioauth.page_text_version t ON t.id = s.page_text_version_id
    WHERE s.quote_text IS DISTINCT FROM
          substring(t.text_normalized FROM s.start_offset + 1 FOR s.end_offset - s.start_offset)
    """
)

COUNT_SQL = text("SELECT count(*) FROM cardioauth.fact_span")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Re-validate stored source spans.")
    parser.add_argument("--database-url", default=None, help="SQLAlchemy URL (default: Settings)")
    args = parser.parse_args(argv)

    url = args.database_url
    if not url:
        from cardioauth.settings import get_settings

        url = get_settings().database_url

    engine = create_engine(url)
    problems: list[str] = []
    with engine.connect() as conn:
        try:
            total = conn.execute(COUNT_SQL).scalar_one()
            orphans = conn.execute(ORPHAN_FACTS_SQL).scalar_one()
            bad_offsets = [row[0] for row in conn.execute(OFFSET_SQL)]
            bad_quotes = [row[0] for row in conn.execute(QUOTE_SQL)]
        except Exception as exc:  # pragma: no cover - operator-facing diagnostics
            print(f"span integrity check could not run: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
    engine.dispose()

    if orphans:
        problems.append(f"{orphans} fact(s) have no span (a fact must cite its source)")
    if bad_offsets:
        problems.append(f"{len(bad_offsets)} span(s) point outside the page text: {bad_offsets[:10]}")
    if bad_quotes:
        problems.append(f"{len(bad_quotes)} span(s) quote text that is not at their offsets: {bad_quotes[:10]}")

    if problems:
        for problem in problems:
            print(f"SPAN INTEGRITY FAILURE: {problem}", file=sys.stderr)
        return 1

    print(f"span integrity OK: {total} span(s) checked, 0 invalid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
