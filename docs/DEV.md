# Development setup

Everything in this file was run in the team sandbox while completing M1a, except where it
is explicitly marked otherwise. The commands are given in the order they worked.

## 1. Database without Docker (verified)

The sandbox has the Docker CLI but **no Docker daemon**, so `docker compose up -d db`
cannot run here. A local PostgreSQL 16 was installed and a throwaway cluster started
instead. This is also the recommended path for any machine without Docker.

```bash
# 1. Install the server (Ubuntu 24.04 package: PostgreSQL 16.15)
apt-get install -y --no-install-recommends postgresql

# 2. A cluster whose data directory lives outside the repo, so nothing PHI-shaped
#    or large can ever be committed. Run initdb as the postgres user (it refuses root).
mkdir -p /tmp/pgdata /tmp/pgrun && chown postgres:postgres /tmp/pgdata /tmp/pgrun
su postgres -c "/usr/lib/postgresql/16/bin/initdb -D /tmp/pgdata -U postgres \
    --auth-local=trust --auth-host=trust"

# 3. Start it on 127.0.0.1:5432
su postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D /tmp/pgdata \
    -o '-p 5432 -k /tmp/pgrun -c listen_addresses=127.0.0.1' -l /tmp/pg.log start"

# 4. The role the tests and the app expect (see .env.example defaults)
/usr/lib/postgresql/16/bin/psql -h 127.0.0.1 -p 5432 -U postgres \
    -c "CREATE ROLE cardioauth LOGIN SUPERUSER PASSWORD 'cardioauth';"
```

`SUPERUSER` is only for a throwaway local cluster: the schema creates the `citext` and
`btree_gist` extensions and the tests drop/create databases. Never grant this in a real
environment — see COMPLIANCE notes in `DESIGN.md`.

Verify:

```bash
/usr/lib/postgresql/16/bin/psql -h 127.0.0.1 -p 5432 -U postgres -tAc "select version();"
# PostgreSQL 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1) on x86_64-pc-linux-gnu, ...
```

To stop and discard it: `su postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D /tmp/pgdata stop"`.

### With Docker (not run in the sandbox — no daemon)

```bash
cp .env.example .env
docker compose up -d db
```

## 2. Python environment (verified)

The repo lives on a small volume, so the virtualenv is kept **outside** it. Do not create
`.venv/` under the repository.

```bash
python3 -m venv /tmp/ca-venv
/tmp/ca-venv/bin/pip install -e "/path/to/repo/backend[dev]"
# or, for the exact versions this commit was tested with:
# /tmp/ca-venv/bin/pip install -r requirements.lock
```

`requirements.lock` is a `pip freeze` of the environment the suite passed in. It is a
snapshot, not a curated constraint set — regenerate it when dependencies move.

## 3. Migrations (verified)

The baseline revision applies `backend/cardioauth/db/sql/001_schema.sql` verbatim, which is
the authoritative schema. The URL is resolved, in order, from `alembic -x db_url=...`, then
`CARDIOAUTH_MIGRATION_DATABASE_URL`, then the `Settings` object (never from `alembic.ini`).

```bash
cd backend
export CARDIOAUTH_ENV=dev
alembic upgrade head                                  # apply the baseline
alembic current                                       # -> 0001 (head)
alembic downgrade base                                # drops both schemas; round-trips
```

Against a specific database without changing your settings:

```bash
alembic -x db_url="postgresql+psycopg://cardioauth:cardioauth@localhost:5432/cardioauth" upgrade head
```

The migration test does exactly this against a scratch database
(`cardioauth_test_roundtrip`), then downgrades and re-upgrades to prove the round trip.

## 4. Tests (verified)

```bash
cd backend
python -m pytest -q
# 55 passed, 9 warnings in 2.09s        (with PostgreSQL reachable)
```

- Database-backed tests are marked `db`. Without a reachable server they are **skipped with
  a loud reason** naming the URL — they never fail or silently pass.
- Point them elsewhere with `CARDIOAUTH_TEST_ADMIN_URL` (default
  `postgresql+psycopg://cardioauth:cardioauth@localhost:5432/postgres`) and
  `CARDIOAUTH_TEST_DB_NAME` (default `cardioauth_test`).
- The tests create and drop their own databases; the admin role therefore needs `CREATEDB`.

Lint (not part of the gate yet, and currently noisy — see limitations):

```bash
cd backend && ruff check .
```

## 5. Known sandbox limitations

- **No Docker daemon.** `docker compose up` is documented in the README but was not
  exercised here; only the Docker-free path above was verified.
- **PostgreSQL is a throwaway cluster in `/tmp`.** It does not survive a reboot, and the
  tests drop/create databases on it.
- **No network push / no GitHub remote.** The repository is GitHub-ready but has no remote
  configured. All git work so far is local only.
- **Frontend is source-only.** `frontend/` has no `node_modules` and has never been
  `next build`-ed, because the volume has ~100 MB free. It is a skeleton, not a working app.
- **`ruff check` reports ~90 issues** (mostly `E501` long lines and `S603`/`S608` on
  deliberately dynamic SQL and subprocess use in tests). Formatting was not mass-reformatted
  during M1a to keep this commit reviewable; it is not a test gate.

## 6. Repository hygiene (verified before the first commit on `main`)

Checked on the M1a completion commit:

- Branch is `main` (renamed from `master`); working tree clean.
- No secret-bearing file is tracked: the only env-shaped tracked file is `.env.example`,
  which contains placeholder values only. `.env`, `.env.*` (other than the example) are
  ignored.
- No tracked file is larger than ~1 MB (largest: `DESIGN.md`, ~144 KB).
- `.gitignore` covers `node_modules/`, `.next/`, `.env*`, `__pycache__/`, `*.egg-info/`,
  `.pytest_cache/`, `.mypy_cache/`, coverage output, and runtime/PHI-prone artefacts
  (`logs/`, `data/blobs/`, `data/exports/`, `*.sqlite`, `*.dump`, `reports/eval-*.json`).
- No database dumps, uploaded documents, exported letters or OCR text are tracked.
- The virtualenv and the PostgreSQL data directory live outside the repository.
