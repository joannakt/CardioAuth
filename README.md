# CardioAuth

CardioAuth is a prior-authorization and appeal assistant for small, independent cardiology
practices. A prior-authorization coordinator uploads a patient's documents (PDFs, scans,
pasted text); the system extracts clinical facts, checks them against a **versioned,
admin-editable library of payer medical-necessity criteria**, shows a checklist labelled
Met / Not met / Insufficient documentation with the supporting quoted text, reports exactly
which documentation is missing, and drafts the letter of medical necessity or the denial
appeal. Every clinical statement in a generated letter must trace back to an extracted fact
and its source span (document, page, text version, character offsets). A human always
reviews, edits, e-signs and submits — CardioAuth never contacts a payer and never submits
anything on its own.

## Status: M1a — foundation only, not a working product

This repository is at the **end of milestone M1a**. It is a schema-and-scaffolding
milestone. Treat it as an engineering foundation, not a product you can show a practice.

**Built and verified today**

- The authoritative PostgreSQL schema (`backend/cardioauth/db/sql/001_schema.sql`): the
  full data model plus database-enforced invariants — source spans validated against the
  page text they quote, facts that cannot exist without a span, append-only page text /
  letters / audit log, immutable-once-published criteria, revocable-once sign-offs, a
  hash-chained audit log, and a single-effective-published-version exclusion constraint.
- Alembic baseline migration that applies that DDL (and downgrades cleanly), with an
  ORM/DDL drift test.
- A partial SQLAlchemy ORM mapping for the tables M1 touches.
- Settings with production guards (refuses dev defaults, placeholder criteria, insecure
  cookies or a mock LLM provider in production), and a PHI log filter.
- The audit hash chain: canonical payload, PHI-shaped detail-key screen, writer, verifier,
  and a `cardioauth-audit-verify` CLI.
- `docker compose` development environment, `deploy/` Caddy config, maintenance scripts.
- 55 backend tests covering the above, all passing against a real PostgreSQL 16.

**Not built yet (M1b and later)**

- No user-facing web application. The FastAPI app currently serves health/readiness only.
- No authentication, RBAC, sessions or 2FA yet (schema and settings exist, endpoints do not).
- No document upload, OCR, extraction, criteria evaluation, gap report, letter generation,
  claim verification UI, or status board.
- No LLM provider integration (only the settings/interface scaffolding).
- No evaluation harness, no synthetic case corpus, no frontend beyond a placeholder page.
- No billing, no EHR/FHIR integration, no payer portal submission.

## ⚠️ The criteria library is UNVERIFIED PLACEHOLDER data

Every criterion in this repository is placeholder content marked
`UNVERIFIED — requires clinical review before use`. There is no licensed source behind it,
and no clinician has reviewed it. **Do not use this software, or any output from it, for
real patient care, real prior authorizations, or real appeals.** Development and testing
use synthetic data only. Replacing the placeholder library with a real, cited, clinically
reviewed criteria set (and naming the reviewer) is an open owner decision.

## Prerequisites

- Python 3.12
- PostgreSQL 16 with the `citext` and `btree_gist` extensions available
- Docker + Docker Compose (for the one-command dev environment), or a local PostgreSQL
- Node.js 20+ (only for the frontend skeleton; not needed for the backend or tests)

## Local development

Copy the environment template and start the database:

```bash
cp .env.example .env            # edit secrets for anything beyond local dev
docker compose up -d db         # PostgreSQL 16 on localhost:5432
```

Install the backend and apply the schema:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e "./backend[dev]"          # or: pip install -r requirements.lock
export CARDIOAUTH_ENV=dev
alembic -c backend/alembic.ini upgrade head
```

Run the app and the tests:

```bash
uvicorn cardioauth.api.main:app --reload --port 8000     # from backend/, after install
cd backend && python -m pytest -q                        # full suite (needs PostgreSQL)
```

Database-backed tests are marked `db` and are skipped with a loud reason when no PostgreSQL
is reachable. To point them at a specific server:

```bash
export CARDIOAUTH_TEST_ADMIN_URL="postgresql+psycopg://cardioauth:cardioauth@localhost:5432/postgres"
```

`docs/DEV.md` has the Docker-free setup (the exact commands that were run and verified in
this sandbox), the migration command, and the known sandbox limitations.

## Repository layout

```
backend/
  cardioauth/
    api/            FastAPI app and health/readiness endpoints
    audit/          hash-chained audit log: canonical payload, writer, verifier CLI
    blobs/          document storage abstraction (local now, object storage later)
    db/             declarative base, ORM models, sql/001_schema.sql (authoritative DDL)
    domain/         domain services (M1b)
    export/         PDF/DOCX export (M2)
    llm/            provider-agnostic LLM interface (M2)
    ocr/            pluggable OCR interface (M2)
    services/       application services (M1b+)
    workers/        background worker entrypoint
    logging_setup.py  JSON logging + PHI log filter
    settings.py     settings object, production guards
  migrations/       Alembic environment and versions (0001 baseline)
  tests/            pytest suite (schema invariants, migrations, settings, audit chain)
docker-compose.yml  PostgreSQL + API dev stack
deploy/             reverse-proxy config for a deployment
design/             placeholder criteria shape (illustrative only)
docs/DEV.md         Docker-free setup, migrations, tests, hygiene notes
scripts/            maintenance CLIs (span integrity sweep, audit chain verify)
DESIGN.md           the full design document this code implements
```

## Licence / use

Internal project. Not licensed for redistribution or clinical use.
