# CardioAuth — Design Document

**Prior-authorization and appeal assistant for small independent cardiology practices**
Revision D1 · 2026-10-18 · Author: engineer · Status: **for owner review and approval** · Design only, no code written.

---

## 0. How to read this document

This document is written to be **approved and then built from**, not to survey options. Every design choice is stated as a decision with a one-line rationale. Where something is genuinely the owner's call, it appears in **§11 Open questions** with a *proposed default* — approve the default or change it; no questionnaire to fill in.

**Status legend used throughout:**

| Tag | Meaning |
|---|---|
| **[FIXED]** | Owner-specified requirement. Not open for redesign. |
| **[DECIDED]** | Design decision made here, with rationale. Changeable, but the default is buildable. |
| **[ASSUMED]** | Assumption made because the information is not available yet. Stated so it can be corrected cheaply. |
| **[RECOMMENDED]** | Non-binding recommendation, usually infrastructure/procurement (BAA path). |

**Non-negotiable invariants.** These reappear as schema constraints, trigger functions and CI gates, not as good intentions:

- **INV-1** No clinical fact exists in the system without a verifiable source span (document → page → text version → character offsets → quoted text).
- **INV-2** No medical-necessity rule exists in application code, configuration defaults, prompt text, or model memory. Criteria live only in the criteria library (§2.6).
- **INV-3** No letter sentence reaches an export without passing claim verification, or being explicitly marked by a human as non-factual.
- **INV-4** Nothing is exported or e-signed without an authenticated human action, and the system never contacts a payer.
- **INV-5** In production mode (`CARDIOAUTH_ENV=production`) no PHI is written to application logs, ever.
- **INV-6** Dev and test use synthetic data only. No real PHI in the repository, containers, fixtures or logs.

**Deliberate scope honesty.** This is a documentation-and-tooling MVP, not a certified system. §10 states plainly what stands between this design and real PHI, and `COMPLIANCE.md` (§9, M7) will carry the authoritative checklist. Nothing in this design should be read as a compliance claim.

---

## 0.1 Summary of decisions (one page for the reviewer)

| Area | Decision |
|---|---|
| Shape | Single FastAPI backend + Next.js frontend + PostgreSQL + S3-compatible object storage, all behind one origin; Docker Compose for dev. |
| Criteria | Versioned, immutable-on-publish criteria sets in PostgreSQL, admin-editable, per (procedure, payer, effective window). Application code never contains a rule. Letters cite the criteria set version ID + fingerprint. |
| Fact provenance | `fact_span` rows with character offsets into an immutable `page_text_version`; validated by a DB trigger against the stored page text; insert rejected on mismatch. No span → no fact → no sentence. |
| Export safety | Letters stored as a structured block AST (source of truth). Every block carries `claim_type` and `fact_ids`. A verification pass over the AST produces per-sentence verdicts; export is blocked while any sentence is `UNSUPPORTED` or `UNVERIFIED`. Coordinator edits create a new letter version and are re-verified identically. |
| LLM | `LLMProvider` Protocol; provider, model, base URL, temperature and timeout all from env vars; a `null`/mock provider is the dev default. Production logging off unless `CARDIOAUTH_PHI_LOGGING=dev`. |
| OCR | `OcrBackend` Protocol. Tesseract in dev; a managed document-AI service in production. Text-layer PDFs bypass OCR and use the embedded text, which preserves offsets exactly. |
| Storage | `BlobStore` Protocol: local disk in dev, S3-compatible in production. Documents addressed by content hash, never rewritten. |
| Auth | Self-hosted email/password (Argon2id) + TOTP 2FA, server-side sessions in Postgres, 15 min idle / 8 h absolute timeout, re-auth required for export and sign-off. No managed auth vendor selected or required. |
| Status | Explicit state machine on `case.status` with a role-gated transition table and append-only `case_status_history`. |
| Audit | Append-only, hash-chained `audit_log`, `UPDATE`/`DELETE` revoked at the DB role level, in its own schema. |
| Evaluation | Harness runs the whole pipeline over 20 synthetic cases + 5 denial letters and emits `reports/eval-<date>.md`; gates in CI. Target: **zero unflagged unsupported claims**. |
| Deviations from owner stack | None material. Additions: WeasyPrint + python-docx for export, MinIO for S3-compatible dev storage, Tiptap for the rich-text editor. See §12. |

---

## 1. Architecture

### 1.1 Components [DECIDED]

```
┌─────────────────────────────── single origin (port 3000 dev / one domain prod) ───────────────────────────────┐
│                                                                                                               │
│  Browser ── Next.js (React + TS + Tailwind)                                                                   │
│             ├─ coordinator app: cases, upload, checklist, gap report, editor, tracker                         │
│             ├─ physician view: review + e-sign                                                                 │
│             └─ admin views: users, criteria library, audit log                                                │
│                      │  fetch /api/*  (httpOnly session cookie, CSRF token)                                   │
│                      ▼                                                                                        │
│  FastAPI (Python 3.12) ── ASGI ── uvicorn                                                                     │
│    api/         routers: auth, practices, cases, documents, extractions, evaluations,                      │
│                          letters, verification, signoffs, tracker, criteria_admin, audit, health             │
│    services/    case_service, ingest_service, extraction_service, criteria_service,                           │
│                 letter_service, verification_service, tracker_service, audit_service                          │
│    domain/      Pydantic schemas (single source of truth for API + LLM IO)                                     │
│    llm/         LLMProvider Protocol + providers/{mock,openai_compatible,bedrock,azure}                        │
│    ocr/         OcrBackend Protocol + backends/{pdf_text_layer,tesseract,textract}                             │
│    storage/     BlobStore Protocol + backends/{local,s3}                                                       │
│    export/      ast → docx (python-docx) · ast → pdf (WeasyPrint)                                              │
│    workers/     in-process arq/RQ-style queue backed by Postgres (dev: inline execution allowed)               │
│                      │                    │                        │                        │                  │
│             PostgreSQL 16            BlobStore               OCR backend          LLM provider                │
│             (SQLAlchemy + Alembic)   (local / S3-compat)     (Tesseract/API)       (mock/BAA-capable)          │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Why a single origin.** Only one public port is available and it also avoids CORS, cookie `SameSite` complications and mixed-content issues with PHI. In production the Next.js server runs on a private loopback port and the reverse proxy routes `/` to it and `/api/*` to FastAPI, so the browser sees one origin. In Docker Compose the same topology is reproduced by the nginx/Caddy service. *This is why the dev proxy config and the Compose proxy config are the same file* — the swap is a config change, not a rewrite.

**Why a job queue at all.** OCR, extraction and verification are multi-second operations. They run as queued jobs so a browser refresh does not lose work, and so the harness can run them headlessly. Dev default is inline execution (`CARDIOAUTH_JOBS_INLINE=true`) to keep the stack small; production runs a worker container. The job table is Postgres-backed, so no extra broker is needed.

### 1.2 The coordinator's loop — request flow [FIXED]

Numbered steps match the owner's workflow exactly. Side column notes what is persisted and what is audited.

| # | Step | Backend call(s) | Persisted | Audit event |
|---|---|---|---|---|
| 1 | **Create case** — procedure, payer, CPT, demographics-lite, ordering provider, date of service, urgency, prior-auth reference | `POST /api/cases`; `GET /api/criteria/resolve?procedure&payer&dos` | `case` row; resolved `criteria_set_version_id` pinned on the case | `case.created` |
| 2 | **Upload documents** — PDFs, scans (JPG/PNG/TIFF/HEIC), pasted text | `POST /api/cases/{id}/documents` (multipart or `text` body) | `document` + `document_page` rows; blob in `BlobStore`; `ingest_job` | `document.uploaded`, `document.text_pasted` |
| 3 | **Extract facts** | `POST /api/cases/{id}/extractions` → worker: page text → LLM structured extraction → span validation → `fact` + `fact_span` | `extraction_run`, `fact`, `fact_span` | `extraction.completed` (counts only, no PHI) |
| 4 | **Evaluate criteria** | `POST /api/cases/{id}/evaluations` → worker: facts + criteria set → per-criterion verdict with fact citations | `criteria_evaluation`, `criterion_verdict` | `evaluation.completed` |
| 5 | **Gap report** | `GET /api/cases/{id}/gaps` (derived) | derived from verdicts; `gap_item` rows materialised for tracking/acknowledgement | `gap.report_viewed` |
| 6 | **Draft outputs** — LMN, appeal, P2P summary | `POST /api/cases/{id}/letters` (kind, denial input) → worker → AST + verification | `letter`, `letter_version`, `verification_run`, `claim_verdict` | `letter.generated`, `letter.edited`, `letter.exported` |
| 7 | **Human review + e-sign** | `POST /api/letters/{id}/versions/{v}/submit-for-review`; physician `POST .../signoffs` (requires re-auth) | `signoff` | `letter.submitted_for_review`, `letter.signed`, `letter.exported` |
| 8 | **Track** | `POST /api/cases/{id}/transitions`; `GET /api/tracker` | `case.status`, `case_status_history`, `due_date` derived | `case.status_changed` |

**Sequence for step 6 (the feature the owner cares most about):**

```
coordinator clicks "Draft appeal"
        │
        ▼
letter_service.build_letter_request(case, criteria_set_version, denial_input?)
        │   only facts whose spans are valid and fresh (text_version current) are eligible
        ▼
LLMProvider.complete_structured(LetterDraft, prompt, evidence_bundle)   ← provider-agnostic, JSON-schema-constrained
        │   returns blocks; each factual block MUST carry fact_ids chosen from evidence_bundle ids
        ▼
block_validator: drop/reject blocks citing unknown or stale fact ids
        │
        ▼
verification_service.verify(letter_version)  → per-sentence verdicts (§8.3)
        │
        ▼
letter_version persisted (AST), verification_run persisted, UI shows flags inline
        │
        ▼
export allowed only when no sentence is UNSUPPORTED / UNVERIFIED
```

### 1.3 Deployment sketch

**Local dev [DECIDED]** — `docker compose up` starts: `db` (Postgres 16), `minio` (S3-compatible blob store), `api` (FastAPI/uvicorn, reload), `worker`, `web` (Next.js dev), `proxy` (Caddy, publishes **only** port 3000). OCR = Tesseract inside the `worker` image. LLM = `mock` provider by default so a clean clone runs with no API key and no network. Synthetic fixtures live in `data/synthetic/` (dev/test only, git-tracked, clearly labelled).

**Production path [RECOMMENDED, not procurement]** — same images, different configuration:

| Seam | Dev implementation | Production implementation | How it is swapped |
|---|---|---|---|
| Blob storage | `LocalBlobStore` (bind mount) | `S3BlobStore` → AWS S3 (HIPAA-eligible, server-side encryption with KMS, BAA available) | `BLOB_BACKEND=s3` + `S3_*` env vars |
| Database | Postgres container | Amazon RDS for PostgreSQL, encrypted at rest, automated backups, private subnets | `DATABASE_URL` (+ TLS params) |
| LLM | `MockLLMProvider` | Provider that signs a BAA — see §11 Q10 | `LLM_PROVIDER`, `LLM_MODEL`, `LLM_API_KEY` |
| OCR | Tesseract | Managed document AI (AWS Textract / Azure Document Intelligence) — both BAA-eligible | `OCR_BACKEND` |
| Secrets | `.env` file (dev only, git-ignored) | AWS Secrets Manager / SSM Parameter Store | env vars injected at container start |
| TLS | none (loopback) | ALB/ACM or Caddy + Let's Encrypt; TLS 1.2+ enforced, HSTS | proxy config |
| Sessions/cookies | `Secure` off in dev | `Secure`, `HttpOnly`, `SameSite=Lax`, short-lived | env-driven cookie flags |

**Honesty about the unselected pieces.** No managed database, no managed auth service and no LLM/OCR vendor has been pre-selected or contracted for this project. The compinit above says what the *code seam* is; choosing the vendor, signing a BAA and validating HIPAA-eligibility is an owner decision (§11 Q10, and the plan's own "what the owner needs to decide"). **There is no auth vendor at all by design** — authentication is implemented in-process (Argon2id + TOTP + server-side sessions), which avoids a third-party PHI processor and one more BAA. The cost is that the team owns session security; §7 specifies exactly what that means.

**Environment tiers [DECIDED]:** `dev`, `test`, `ci`, `production`. `CARDIOAUTH_ENV` drives: log redaction (always on except dev), cookie flags, whether mock providers are permitted (refused in production — startup fails if `LLM_PROVIDER=mock` under `production`), and whether synthetic fixtures can be loaded (refused in production).

---

## 2. Data model

PostgreSQL 16, SQLAlchemy 2.x declarative, Alembic migrations. Two schemas: `cardioauth` (application) and `cardioauth_audit` (audit, separate DB role). All tables carry `created_at`/`updated_at` (UTC, `timestamptz`) unless noted. UUID v7 primary keys (`uuid` type, generated in Python) so IDs sort by creation time and do not leak counts.

### 2.1 Tenancy and identity

```
practice
  id                uuid pk
  name              text not null
  npi               text null                       -- practice NPI, validated if present
  timezone          text not null default 'America/New_York'
  settings          jsonb not null default '{}'     -- e.g. default payer turnaround days
  created_at, updated_at

app_user
  id                uuid pk
  practice_id       uuid fk -> practice(id)         -- null only for platform_admin
  email             citext not null
  password_hash     text not null                   -- Argon2id, params recorded in hash string
  full_name         text not null
  role              text not null check (role in ('coordinator','physician','admin','platform_admin'))
  npi               text null                       -- required for physician role (app-level check)
  totp_secret_enc   bytea null                      -- encrypted with APP_KEY, never logged
  totp_enrolled_at  timestamptz null
  is_active         bool not null default true
  failed_login_count int not null default 0
  locked_until      timestamptz null
  unique (practice_id, email)

user_session                                        -- server-side sessions, opaque token
  id                uuid pk
  user_id           uuid fk -> app_user
  token_hash        bytea not null unique           -- sha256 of the cookie value; raw token never stored
  issued_at         timestamptz not null
  last_seen_at      timestamptz not null
  absolute_expires_at timestamptz not null
  idle_expires_at   timestamptz not null
  ip_hash           bytea null                      -- hashed, not raw
  user_agent_hash   bytea null
  revoked_at        timestamptz null
  reauth_at         timestamptz null                -- last step-up authentication

user_invitation
  id, practice_id, email, role, token_hash, invited_by, expires_at, accepted_at
```

**Why `token_hash` and hashed IP/UA:** session table contents are not PHI-adjacent by accident. The raw session cookie value exists only in the browser.

### 2.2 Cases and status

```
case_record                                          -- "case" is a reserved-ish word; table named case_record
  id                  uuid pk
  practice_id         uuid fk -> practice
  case_number         text not null                  -- human ref, per-practice sequence, e.g. "CAR-2026-0042"
  patient_ref         text not null                  -- SYNTHETIC in dev; MRN-like label, not a name field
  patient_display     jsonb not null default '{}'    -- {"initials":"J.D.","dob_year":1958} minimal-by-design
  procedure_code_id   uuid fk -> procedure
  payer_id            uuid fk -> payer
  cpt_code            text not null                  -- snapshot of the CPT used at creation
  date_of_service     date null
  ordering_provider   text null                      -- free text; NPI optional
  urgency             text not null default 'routine' check (urgency in ('routine','urgent','emergent'))
  criteria_set_version_id uuid fk -> criteria_set_version   -- PINNED at creation (§2.6)
  status              text not null default 'draft'  -- see §6 state machine
  priority_rank       int not null default 100
  submitted_at        timestamptz null
  submission_ref      jsonb null                     -- §11 Q6: portal name, confirmation no., notes
  due_date            date null                      -- derived; see §6.4
  closed_at           timestamptz null
  close_reason        text null                      -- approved | denied | withdrawn | duplicate
  created_by          uuid fk -> app_user
  unique (practice_id, case_number)
  index on (practice_id, status, due_date)
  index on (practice_id, procedure_code_id, payer_id)

case_status_history                                  -- append-only
  id, case_id, from_status, to_status, reason text null,
  changed_by uuid, changed_at timestamptz not null default now()
  -- no UPDATE/DELETE grants

case_party                                           -- who is involved, for assignment & physician routing
  id, case_id, user_id, case_role text check (case_role in ('coordinator','physician','reviewer','admin')),
  assigned_at, removed_at
```

**Immutability:** `case_status_history` is insert-only. `case_record.status` changes only via `tracker_service.transition()`, which writes history in the same transaction and rejects transitions not in the table in §6.2.

**Deliberate data minimisation [DECIDED]:** the case does not store a patient name, address, phone or full DOB. It stores a per-practice `patient_ref` and a small `patient_display` JSON (initials + birth year) sufficient to let staff disambiguate cases. Full identifiers, where they exist, live inside uploaded documents — where they are needed clinically — not in indexed columns. This shrinks the blast radius and makes synthetic/dev operation trivially distinguishable from real data. (If a future EHR integration requires full demographics, that is a deliberate, documented change, not a default.)

### 2.3 Reference data: procedures and payers

```
procedure                                            -- MVP: 5 rows; a 6th is DATA, not code
  id              uuid pk
  code            text not null unique               -- 'tte','spect_mpi','ccta','cardiac_pet','cardiac_mri'
  display_name    text not null
  cpt_codes       text[] not null default '{}'       -- candidate CPTs; multiple per procedure (e.g. 78452)
  modality        text not null                      -- 'echo','nuclear','ct','pet','mr'
  default_criterion_categories text[] not null default '{}'
  fact_fields     jsonb not null                     -- which extraction fields are clinically relevant (§2.5)
  booster_letter_kind text null
  is_active       bool not null default true
  display_order   int not null default 100

payer
  id            uuid pk
  name          text not null                        -- e.g. 'PLACEHOLDER-PAYER-A'
  payer_type    text not null check (payer_type in ('commercial','medicare_advantage','medicaid','other'))
  state         text null                            -- 2-letter; payer policies are often state/plan specific
  plan_hint     text null
  turnaround_days int not null default 14             -- drives due_date (§6.4)
  is_active     bool not null default true
  unique (name, state, plan_hint)
```

**Adding a sixth procedure is a configuration change**: insert one `procedure` row (code, display name, CPT list, `fact_fields`), optionally add criteria sets/criteria rows, optionally add synthetic cases. No Python is touched; no migration is required because the shape is already general. The extraction prompt receives the procedure's `fact_fields` as the requested field list, so a new procedure does not need a new prompt either.

### 2.4 Documents, pages and page text (the offset-preserving core)

```
document
  id                uuid pk
  case_id           uuid fk -> case_record
  kind              text not null check (kind in (
                      'clinic_note','echo_report','stress_report','cath_report','ecg','med_list','labs',
                      'imaging_report','denial_letter','prior_auth_form','insurance_card','other','pasted_text'))
  original_filename text null                        -- sanitised; never used as a path
  mime_type         text not null
  byte_size         bigint not null
  sha256            bytea not null                   -- content address; used for dedupe + integrity
  blob_key          text not null                    -- BlobStore key (opaque)
  page_count        int not null
  ingest_status     text not null check (ingest_status in ('uploaded','processing','ready','failed','needs_review'))
  ingest_error      text null                        -- redacted, non-PHI
  source            text not null check (source in ('upload','paste'))
  uploaded_by       uuid fk -> app_user
  uploaded_at       timestamptz not null default now()
  deleted_at        timestamptz null                 -- soft delete; blob retained while referenced by facts
  unique (case_id, sha256)                           -- identical file uploaded twice is deduped
  index on (case_id, kind)

document_page
  id                uuid pk
  document_id       uuid fk -> document on delete restrict
  page_number       int not null                     -- 1-based, stable, never renumbered
  width_px, height_px int null
  render_dpi        int null                         -- for image pages
  image_blob_key    text null                        -- normalised PNG/page image, for span highlighting
  ocr_method        text not null                    -- 'text_layer' | 'tesseract' | 'textract' | 'pasted'
  ocr_confidence    numeric(5,4) null                -- mean word confidence, null for text_layer/pasted
  current_text_version_id uuid fk -> page_text_version   -- deferred FK; the ""live"" text
  unique (document_id, page_number)

page_text_version                                    -- append-only; re-OCR creates a NEW row
  id                uuid pk
  page_id           uuid fk -> document_page
  version_no        int not null
  text_normalized   text not null                    -- the canonical text spans index into
  char_count        int not null
  ocr_method        text not null
  ocr_confidence    numeric(5,4) null
  produced_by_job   uuid null
  created_at        timestamptz not null default now()
  unique (page_id, version_no)
  index on (page_id, version_no desc)
```

**Text normalisation rules [DECIDED]** — applied *once* when a `page_text_version` is created, then frozen:

1. Line endings → `\n`. 2. Unicode NFC. 3. Strip trailing whitespace per line. 4. Collapse runs of ≥3 spaces to one, but **never** alter a character's position semantics by deleting content silently — deletions are only trailing spaces and collapsed runs, both recorded in `normalization_notes` JSON alongside counts. 5. No case folding, no de-hyphenation, no OCR post-correction of clinical tokens. *Rationale: offsets must remain reproducible byte-for-byte from the stored text, so normality must be a pure function recorded with the version.*

Every span therefore means: `page_text_version.text_normalized[start_offset:end_offset]`.

### 2.5 Facts and their source spans

```
extraction_run
  id              uuid pk
  case_id         uuid fk
  procedure_code_id uuid fk -> procedure
  status          text not null check (status in ('queued','running','succeeded','partially_failed','failed'))
  llm_provider    text not null                      -- 'mock' | 'bedrock' | ...
  llm_model       text not null
  prompt_version  text not null                      -- e.g. 'extract-v1'
  input_document_ids uuid[] not null
  page_text_version_ids uuid[] not null              -- exact text versions fed in
  token_input, token_output int null                 -- cost telemetry, no PHI
  error           text null
  started_at, finished_at timestamptz
  -- an extraction_run is immutable once finished

fact
  id              uuid pk
  case_id         uuid fk -> case_record
  extraction_run_id uuid fk -> extraction_run
  field_key       text not null                      -- controlled vocabulary, see below
  value_text      text null                          -- canonical text form ("55", "2024-03-12", "dobutamine")
  value_typed     jsonb null                         -- {"kind":"number","value":55,"unit":"percent"}
  value_date      date null                          -- when the fact IS a date
  polarity        text not null default 'present' check (polarity in ('present','absent','negated','unknown'))
  confidence      numeric(4,3) not null check (confidence between 0 and 1)
  is_current      bool not null default true         -- false when superseded or stale after re-OCR
  superseded_by   uuid null fk -> fact
  created_at      timestamptz not null default now()
  index on (case_id, field_key) where is_current

fact_span                                            -- a fact may have >1 span (synthesis across docs)
  id              uuid pk
  fact_id         uuid fk -> fact on delete cascade
  page_text_version_id uuid fk -> page_text_version
  page_id         uuid fk -> document_page
  document_id     uuid fk -> document
  start_offset    int not null check (start_offset >= 0)
  end_offset      int not null check (end_offset > start_offset)
  quote_text      text not null                      -- must equal text_normalized[start:end]
  span_role       text not null default 'support' check (span_role in ('support','contradict','context'))
  verified_at     timestamptz not null default now() -- set by the validating trigger
  unique (fact_id, page_text_version_id, start_offset, end_offset)
```

**How INV-1 is enforced at the schema level, not in a prompt [DECIDED, the key mechanism]:**

1. **Insert-time trigger.** A `BEFORE INSERT OR UPDATE` row trigger `validate_fact_span()` on `fact_span` looks up `page_text_version.text_normalized` and asserts
   `substring(text_normalized from start_offset + 1 for (end_offset - start_offset)) = quote_text` (Postgres `substring` is 1-based; offsets are 0-based half-open, so `+1` and no `-1`).
   On mismatch it raises an exception → the whole transaction fails. There is no code path, no ORM call, and no raw SQL insert that can create a fact span that does not match the stored text.
2. **Cross-table consistency trigger.** Same trigger asserts that `page_id` and `document_id` agree with `page_text_version.page_id` and its document.
3. **Fact requires a span.** `fact` has no "source-less" state: extraction persists facts and spans in one transaction, and a deferred `CONSTRAINT TRIGGER` at commit time asserts every inserted `fact` has ≥1 `fact_span` row. A fact that the model reports without a quotable span is **not stored as a fact at all** — it becomes a `gap_item` of kind `unsourced_mention` and is surfaced in the gap report ("the documents mention something here that could not be pinned to a page").
4. **Freshness.** A trigger on `page_text_version` insert (re-OCR) marks every `fact_span` bound to older versions as `stale = true` (a column on `fact_span`, added by migration at M4) and sets the owning `fact.is_current = false` when *all* its spans are stale. Stale facts are excluded from letter generation and shown in the UI with a "re-anchor" action.
5. **Integrity sweep.** `scripts/check_span_integrity.py` re-validates every span in a database and is run in CI and as a nightly job; a single mismatch fails the build.

**Controlled vocabulary for `field_key` [DECIDED]** — the extraction schema's enum, aligned to the owner's list, extended only by design review:

`symptom.present`, `symptom.type`, `symptom.onset_date`, `symptom.frequency`, `symptom.severity`, `symptom.anginal_equivalent`,
`prior_test.type`, `prior_test.date`, `prior_test.result_summary`, `prior_test.abnormal`, `prior_test.percent_stenosis`, `prior_test.ischemia_present`, `prior_test.ischemia_extent`, `prior_test.ecg_findings`,
`lvef.value`, `lvef.method`, `lvef.date`,
`risk_factor.present`, `risk_factor.type`, `risk_factor.detail`,
`medication.name`, `medication.dose`, `medication.frequency`, `medication.duration`, `medication.failed_reason`,
`diagnosis.icd10`, `diagnosis.description`, `diagnosis.onset_date`,
`exercise_capacity.mets`, `exercise_capacity.duration_min`, `exercise_capacity.protocol`, `exercise_capacity.limiting_symptom`,
`contraindication.present`, `contraindication.type`, `contraindication.detail`,
`physical_limitation.type`, `physical_limitation.detail`,
`device.present`, `device.type`,
`demographic.age_years`, `demographic.sex`,
`plan_requested_study`, `plan_requested_date`, `order.signing_provider`.

Each key has a declared type, unit and whether it is required for each procedure (`procedure.fact_fields`); that mapping drives the extraction prompt and the "insufficient documentation" logic. **Every key is clinical-descriptive; none of the keys encodes a medical-necessity rule.** Thresholds and durations that decide Met/Not met live in the criteria library, never here. [INV-2]

### 2.6 Criteria library

```
criteria_set
  id            uuid pk
  key           text not null                       -- stable logical identity, e.g. 'spect_mpi.placeholder'
  name          text not null
  procedure_code_id uuid null fk -> procedure        -- null = applies to all procedures (rare)
  payer_id      uuid null fk -> payer                -- null = 'general' (payer-agnostic)
  scope         text not null default 'global' check (scope in ('global','practice'))
  practice_id   uuid null fk -> practice             -- required iff scope='practice'
  created_by, created_at, updated_at
  unique (key, scope, coalesce(practice_id, '00000000-0000-0000-0000-000000000000'::uuid))

criteria_set_version                                -- the versioned, citable object
  id              uuid pk
  criteria_set_id uuid fk -> criteria_set
  version_no      int not null
  status          text not null check (status in ('draft','published','retired'))
  is_placeholder  bool not null default true          -- TRUE for the seed pack
  verification_label text not null default 'UNVERIFIED — requires clinical review before use'
  source_citation jsonb not null                      -- {doc_name, publisher, version, date, url, retrieved_at}
  effective_from  date not null
  effective_to    date null                           -- null = open-ended
  published_at    timestamptz null
  published_by    uuid null fk -> app_user
  fingerprint     text not null                       -- sha256 over canonical JSON of all criteria in this version
  notes           text null
  unique (criteria_set_id, version_no)
  index on (procedure_code_id? no — via set), (effective_from, effective_to), (status)
  -- immutability: once status='published', rows in this table and its criterion rows cannot change (trigger)

criterion
  id            uuid pk
  version_id    uuid fk -> criteria_set_version on delete restrict
  code          text not null                        -- e.g. 'SPECT-01'; stable within the set
  ordinal       int not null                         -- display order
  category      text not null check (category in (
                   'indication','symptom','prior_testing','conservative_therapy','risk_stratification',
                   'contraindication','technical_eligibility','documentation','other'))
  plain_text    text not null                        -- the human-readable rule the coordinator reads
  logic         jsonb not null                       -- machine-evaluable predicate, see below
  required_fields text[] not null default '{}'       -- field_keys that must be documented for this criterion
  met_rationale_hint text null                       -- neutral guidance, no rule content
  unique (version_id, code)

criteria_set_version_selection                       -- resolved selection, pinned on the case
  id, case_id, criteria_set_version_id, resolved_at,
  resolver_reason text not null                      -- 'payer+specific' | 'payer-general' | 'practice-overlay' | 'fallback-latest'
  unique (case_id)
```

**Criterion anatomy → procedure and payer [FIXED design property].** A criterion never stands alone; it is reachable only through its version and set. The anatomy is:

```
practice (optional)          ── scope='practice' + practice_id set ⇒ an overlay that beats global
  └─ criteria_set  key, name, scope
       ├─ procedure_code_id  ── which study this governs ('tte' | 'spect_mpi' | 'ccta' | 'cardiac_pet' | 'cardiac_mri'; NULL = all)
       ├─ payer_id           ── who this governs (NULL = 'general', i.e. payer-agnostic)
       └─ criteria_set_version  version_no, status, is_placeholder, effective_from/to, fingerprint, source_citation
            └─ criterion  code, ordinal, category, plain_text, logic, required_fields, met_rationale_hint
```

So the pair `(procedure, payer)` selects the *set*; `effective_from/effective_to` select the *version* against the case's date of service; the criterion's `code` — and only that code, in that version — is what a letter cites. A case therefore resolves to exactly one version, and every verdict and every letter sentence is attributable to one criterion code inside that version. Adding a sixth procedure means adding a `procedure` row plus (optionally) a criteria set for it — configuration, not code (§2.3).

**`logic` — the machine-evaluable predicate [DECIDED].** A small, declarative, whitelisted expression language stored as JSON that is interpreted by `criteria_service`. It contains **data**, never code. Example shape (values here are placeholders and unverified):

```json
{
  "op": "any_of",
  "of": [
    {"op": "exists", "field": "prior_test.type", "equals": "stress_ecg", "within_days_of": "case.date_of_service", "max_days": 180},
    {"op": "exists", "field": "symptom.present", "equals": true},
    {"op": "gt", "field": "lvef.value", "value": 40}
  ]
}
```

Permitted operators are a closed set: `all_of`, `any_of`, `not`, `exists`, `equals`, `in`, `gt`, `gte`, `lt`, `lte`, `within_days_of`, `absent_or_negated`. The interpreter:

- only reads `fact` rows that are `is_current` and whose spans are non-stale;
- returns **`insufficient_documentation`** rather than `not_met` whenever a referenced `field` has zero current facts, and whenever a date needed for a window comparison is missing;
- records, per referenced field, the fact IDs and span IDs that satisfied it (the supporting quotes shown in the UI);
- rejects unknown operators/fields at *save* time in the admin UI (validation on write, so a broken criterion can never be published).

**This is the anti-hardcoding mechanism [INV-2]:** `criteria_service` is procedure-agnostic and rule-agnostic. It knows operators, not cardiology. To change what counts as medically necessary, an admin publishes a new criteria set version. There is no branch in the application on procedure code, no threshold constant, no clinical threshold in a prompt.

**Versioning / immutability rules [DECIDED]:**

| Rule | Enforcement |
|---|---|
| A `draft` version is freely editable. | UI + service allow edits only when `status='draft'`. |
| Publishing is one-way: `draft → published → retired`. | Trigger blocks status changes out of `published` except to `retired`. |
| Published versions and their `criterion` rows are immutable. | Trigger raises on `UPDATE`/`DELETE` of a `criterion` whose version is published; `criteria_set_version` allows only `status`, `effective_to`, `published_at`, `published_by` transitions. |
| Editing a published set creates a **new draft version** copying criteria forward, `version_no = max+1`. | Service function; the old version stays exactly as it was. |
| There is always at most one `published` version of a set effective on any given date. | Exclusion constraint on `(criteria_set_id, daterange(effective_from, effective_to))` for published rows. |
| Letters cite the exact version used: `version_no`, `fingerprint`, `source_citation`, `is_placeholder` and `verification_label`. | Letter AST carries a `criteria_citation` block; the fingerprint lets a reviewer confirm years later which text was applied. |

**Criteria selection for a case [DECIDED]** (`criteria_service.resolve(case)`), ordered, first match wins, reason recorded:

1. A `criteria_set` with `scope='practice'` matching `(practice_id, procedure, payer)` and a published version effective on the case's `date_of_service` (or today, if DOS is unknown).
2. `scope='global'` matching `(procedure, payer)` with an effective published version.
3. `scope='global'` matching `(procedure, payer=NULL)` — the "general" set.
4. No set found → the case is created but flagged `criteria_missing`; evaluation is refused with a clear message and the gap report says "no criteria loaded for this procedure/payer". **The system never falls back to model knowledge or a built-in default rule.** (If several candidate versions are effective, the highest `version_no` wins; ties are impossible by the exclusion constraint.)

The selection is **pinned** to the case at creation, so a criteria update mid-flight does not silently change an in-progress determination. Re-resolving is an explicit, audited action (`case.criteria_repinned`) that invalidates existing evaluations for that case (a `criteria_set_version_id` change on the case forces re-evaluation; stale evaluations are marked `superseded`).

**Illustrative seed file.** The shape of a seed pack, mapped across all five MVP procedures with the logic operators spelled out, is at `design/criteria-seed-example.yaml` (shape only, all placeholder).

**Seed pack [FIXED: PLACEHOLDER, unverified].** Shipped as data in `data/criteria/seed/*.yaml`, loaded by a management command, with `is_placeholder=true` and `verification_label='UNVERIFIED — requires clinical review before use'`. It is loosely structured on publicly available appropriate-use *categories* (e.g. ACC AUC categories of appropriate/uncertain/rarely-appropriate indications, screening-vs-symptomatic indication, prior-testing-before-advanced-imaging, contraindication checks). **No rule text is authored by the system or the model; the seed criteria are illustrative shapes with dummy thresholds, intended to be deleted and replaced by the owner's licensed criteria source after clinical review.** The UI displays the unverified banner on the checklist, the gap report and the exported letters whenever `is_placeholder` is true, and the exported letter's criteria citation block prints the same warning. Placeholder criteria must not be shown to a payer.

### 2.7 Evaluations and gap items

```
criteria_evaluation
  id                 uuid pk
  case_id            uuid fk
  criteria_set_version_id uuid fk
  extraction_run_id  uuid fk
  status             text not null check (status in ('queued','running','succeeded','failed','superseded'))
  llm_provider, llm_model, prompt_version text not null
  summary            jsonb not null              -- counts by verdict, placeholder flag, timestamp
  created_at, finished_at
  index on (case_id, created_at desc)

criterion_verdict
  id              uuid pk
  evaluation_id   uuid fk -> criteria_evaluation
  criterion_id    uuid fk -> criterion
  verdict         text not null check (verdict in ('met','not_met','insufficient_documentation','not_applicable'))
  confidence      numeric(4,3) not null
  rationale       text not null                  -- LLM explanation; itself not a fact
  is_deterministic bool not null default false   -- true when logic interpreter alone decided
  -- supporting evidence is NOT a free-text field: quotes come from spans
  unique (evaluation_id, criterion_id)

criterion_verdict_fact                            -- the "with supporting quotes" linkage
  id              uuid pk
  verdict_id      uuid fk -> criterion_verdict on delete cascade
  fact_id         uuid fk -> fact
  fact_span_id    uuid fk -> fact_span            -- UI renders quote_text + document name + page number
  role            text not null check (role in ('supports','contradicts','missing_for'))
  unique (verdict_id, fact_span_id, role)

gap_item
  id              uuid pk
  case_id         uuid fk
  evaluation_id   uuid null fk -> criteria_evaluation
  kind            text not null check (kind in ('missing_field','unsourced_mention','unreadable_document',
                                                 'expired_prior_test','contradictory_evidence',
                                                 'criteria_missing','low_ocr_confidence'))
  field_key       text null
  criterion_code  text null
  description     text not null                  -- "No EF value found in any document."
  suggested_source text null                     -- "Ask referring office for the most recent TTE report."
  severity        text not null default 'blocking' check (severity in ('blocking','advisory'))
  status          text not null default 'open' check (status in ('open','acknowledged','resolved','waived'))
  resolved_by     uuid null fk -> app_user
  resolution_note text null
  created_at, updated_at
  index on (case_id, status, severity)
```

**Gap derivation [DECIDED]:** gaps are *derived* from verdicts and extraction gaps on demand (so they reflect current facts), then materialised into `gap_item` rows the first time the report is viewed for a given `evaluation_id`, so that acknowledgement and waiver are durable and auditable. Acknowledgement never deletes a gap; it changes its status and records who accepted the risk. A `blocking` gap does not technically forbid exporting a letter — the coordinator may have legitimately chased the document and know something the documents don't show — but the case **cannot** move to `ReadyForReview` while any `blocking` gap is `open` unless the coordinator explicitly waives it with a reason (§6.3), and the letter then omits the unsupported claim rather than asserting it.

### 2.8 Letters, versions, verification, sign-offs

```
letter
  id            uuid pk
  case_id       uuid fk
  kind          text not null check (kind in ('lmn','appeal','p2p_summary'))
  status        text not null default 'draft' check (status in ('draft','in_review','signed','exported','superseded'))
  current_version_no int not null default 0
  created_by, created_at, updated_at

letter_version
  id              uuid pk
  letter_id       uuid fk -> letter
  version_no      int not null
  source          text not null check (source in ('generated','edited','imported'))
  ast             jsonb not null                  -- the structured document model (§8.1) — SOURCE OF TRUTH
  ast_sha256      bytea not null
  criteria_set_version_id uuid null fk            -- which criteria version this letter cites
  extraction_run_id uuid null fk
  denial_input    jsonb null                      -- pasted/parsed denial reasons for appeals
  created_by      uuid fk -> app_user
  created_at      timestamptz not null default now()
  unique (letter_id, version_no)

verification_run
  id                uuid pk
  letter_version_id uuid fk -> letter_version
  status            text not null check (status in ('queued','running','succeeded','failed'))
  verifier_provider, verifier_model text not null
  method_version    text not null                 -- 'verify-v1'
  counts            jsonb not null                -- {sentences, supported, unsupported, unverified, exempt, coverage}
  created_at, finished_at
  index on (letter_version_id, created_at desc)

claim_verdict                                        -- one row per sentence of the letter AST
  id                uuid pk
  verification_run_id uuid fk -> verification_run
  sentence_index    int not null
  block_id          text not null                  -- stable id of the AST block
  sentence_text     text not null
  claim_type        text not null check (claim_type in ('clinical_fact','criteria_reference','administrative','attestation','quoted_denial'))
  verdict           text not null check (verdict in ('supported','unsupported','unverified','exempt'))
  confidence        numeric(4,3) not null
  reason            text not null                  -- short machine reason: 'numeric_mismatch', 'no_fact_ref', ...
  unique (verification_run_id, sentence_index)

claim_verdict_fact
  id, claim_verdict_id, fact_id, fact_span_id, match_kind text check (match_kind in ('bound','entailed','lexical','numeric'))

signoff
  id              uuid pk
  case_id         uuid fk
  letter_id       uuid fk
  letter_version_id uuid fk
  signer_id       uuid fk -> app_user                 -- must have role physician (or admin w/ attestation right)
  signer_npi      text null
  method          text not null check (method in ('typed_attestation'))  -- §11 Q5
  attestation_text text not null                      -- exact text the signer agreed to, stored verbatim
  signature_hash  bytea not null                      -- sha256(user_id|letter_version.ast_sha256|attestation_text|signed_at)
  signed_at       timestamptz not null default now()
  reauth_at       timestamptz not null                -- step-up auth timestamp, must be < 5 min before signed_at
  verification_run_id uuid not null fk -> verification_run  -- the verification the signer saw
  revoked_at      timestamptz null
  revoke_reason   text null
  unique (letter_version_id) where revoked_at is null
```

**Immutability:** `letter_version` rows are never updated (edits create a new version). `verification_run`, `claim_verdict`, `claim_verdict_fact` and `signoff` are insert-only. Revoking a sign-off inserts a new `signoff` row? No — it flips `revoked_at` and requires the letter to be re-signed; the original row's other columns are protected by trigger (only `revoked_at`/`revoke_reason` may be set, once).

### 2.9 Audit log

```
cardioauth_audit.audit_log
  id              bigserial pk
  occurred_at     timestamptz not null default now()
  practice_id     uuid null
  actor_user_id   uuid null                     -- null for system events
  actor_role      text null
  action          text not null                 -- 'case.viewed','document.uploaded','letter.exported', ...
  object_type     text not null                 -- 'case','document','letter_version','criterion', ...
  object_id       uuid null
  case_id         uuid null                     -- denormalised for query convenience
  outcome         text not null default 'success' check (outcome in ('success','denied','error'))
  detail          jsonb not null default '{}'   -- ids, counts, field names — NEVER PHI values
  request_id      text null                     -- correlates with app logs (which contain no PHI)
  session_id      uuid null
  prev_hash       bytea not null                -- hash chain: sha256(prev.entry_hash)
  entry_hash      bytea not null                -- sha256(canonical_json(this row minus entry_hash) || prev_hash)
  index on (case_id, occurred_at desc), (actor_user_id, occurred_at desc), (action, occurred_at desc)
```

Append-only is enforced by grants, not convention: the application DB role has `INSERT` and `SELECT` on `cardioauth_audit.audit_log` and no `UPDATE`/`DELETE`; the audit schema is owned by a separate role the app cannot assume. The hash chain makes silent deletion or in-place edits detectable; `scripts/audit_chain_verify.py` walks the chain and is run nightly and in CI (see §11 Q7 for external anchoring).

### 2.10 Relationship summary

```
practice 1─* app_user                     practice 1─* case_record
case_record 1─* document 1─* document_page 1─* page_text_version
case_record 1─* extraction_run 1─* fact 1─* fact_span *─1 page_text_version
case_record 1─1 criteria_set_version (pinned)   criteria_set 1─* criteria_set_version 1─* criterion
case_record 1─* criteria_evaluation 1─* criterion_verdict 1─* criterion_verdict_fact *─1 fact_span
case_record 1─* gap_item        case_record 1─* letter 1─* letter_version
letter_version 1─* verification_run 1─* claim_verdict 1─* claim_verdict_fact
letter_version 1─0..1 signoff (active)
* audit_log (all of the above)
```

### 2.11 Indexes and constraints that exist for correctness, not speed

| Constraint | Purpose |
|---|---|
| `fact_span` validating trigger | INV-1: a span that does not literally match stored page text cannot exist. |
| Deferred constraint trigger: every `fact` has ≥1 `fact_span` | INV-1: eliminates source-less facts categorically. |
| `document_page.page_number` unique per document, never renumbered | Page numbers in citations are stable. |
| `page_text_version` append-only, unique `(page_id, version_no)` | Re-OCR cannot rewrite history under an existing span. |
| Exclusion constraint on published criteria version date ranges | Exactly one effective version; no ambiguity in citation. |
| Trigger forbidding writes to published criteria | INV-2: a signed letter's criteria text cannot change after the fact. |
| `letter_version` insert-only | Audit trail of what was actually signed. |
| `signoff` requires `verification_run_id` and `reauth_at` near `signed_at` | INV-3/INV-4: nobody signs an unverified letter, and not on a stale session. |
| `audit_log` grants + hash chain | Tamper evidence. |
| Partial index `fact(case_id, field_key) where is_current` | Correctness of "current facts" queries; also keeps evaluation fast on large cases. |

---

## 3. JSON schemas (Pydantic models)

These models are the **single source of truth** for three things at once: the API request/response bodies, the JSON Schema handed to the LLM provider, and the worker-queue payloads. `domain/schemas/*.py`. `model_config = ConfigDict(extra="forbid")` everywhere — an LLM that invents a field fails validation rather than having it silently ignored.

### 3.1 Extraction output

```python
# domain/schemas/extraction.py
from __future__ import annotations

from datetime import date
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

Strict = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Polarity(StrEnum):
    PRESENT = "present"
    ABSENT = "absent"          # explicitly documented as not present / not indicated
    NEGATED = "negated"        # "no chest pain"
    UNKNOWN = "unknown"


class SpanRef(BaseModel):
    """A pointer into one page of one document. The ONLY way to source a fact."""
    model_config = Strict
    document_id: UUID
    page_number: Annotated[int, Field(ge=1)]
    quote_text: Annotated[str, Field(min_length=1, max_length=600)]
    start_offset: Annotated[int | None, Field(ge=0)] = None   # null => server locates the quote
    end_offset: Annotated[int | None, Field(ge=0)] = None
    occurrence: Annotated[int, Field(ge=1)] = 1               # nth occurrence, when offsets are null


class ExtractedFact(BaseModel):
    model_config = Strict
    field_key: str                                  # must be in FACT_FIELD_VOCABULARY (§2.5)
    value_text: Annotated[str, Field(max_length=500)] | None = None
    value_number: Decimal | None = None
    value_unit: str | None = None                   # 'percent','mets','minutes','mg','days'
    value_date: date | None = None
    value_code: str | None = None                   # ICD-10 / CPT / RxNorm when applicable
    polarity: Polarity = Polarity.PRESENT
    confidence: Annotated[float, Field(ge=0, le=1)]
    spans: Annotated[list[SpanRef], Field(min_length=1)]        # HARD RULE: at least one span
    comment: str | None = None                      # model's uncertainty notes; never rendered in letters

    @model_validator(mode="after")
    def _one_value_form(self) -> "ExtractedFact":
        if self.value_text is None and self.value_number is None and self.value_date is None:
            raise ValueError("fact must carry value_text, value_number or value_date")
        return self


class UnsourcedMention(BaseModel):
    """Something clinically relevant the model saw but could not pin to a span.
    It is NOT stored as a fact; it becomes a gap item."""
    model_config = Strict
    field_key: str | None = None
    description: Annotated[str, Field(max_length=400)]
    why_unsourced: Literal["no_matching_text", "ambiguous_document", "illegible", "model_uncertain"]


class DocumentReadResult(BaseModel):
    model_config = Strict
    document_id: UUID
    document_kind: str
    readable: bool
    pages_read: list[int]
    pages_unreadable: list[int] = []                 # low OCR confidence, blank, or corrupted
    notes: str | None = None


class ExtractionOutput(BaseModel):
    """Response schema of extraction (prompt_version 'extract-v1')."""
    model_config = Strict
    procedure_code: str                              # echoed back; mismatch => run rejected
    document_reads: list[DocumentReadResult]
    facts: list[ExtractedFact] = []
    unsourced_mentions: list[UnsourcedMention] = []
    missing_fields: list[str] = []                   # field_keys in the procedure's required set with no fact
    contradictions: list[str] = []                   # human-readable notes, e.g. "EF differs between two reports"


class StoredFact(BaseModel):
    """Server-side result after span validation. Note there is no unsourced variant."""
    model_config = Strict
    fact_id: UUID
    field_key: str
    value_text: str | None
    polarity: Polarity
    confidence: float
    spans: list[StoredSpan]


class StoredSpan(BaseModel):
    model_config = Strict
    fact_span_id: UUID
    page_text_version_id: UUID
    document_id: UUID
    page_number: int
    start_offset: int
    end_offset: int
    quote_text: str


class ExtractionRunResult(BaseModel):
    model_config = Strict
    extraction_run_id: UUID
    status: Literal["succeeded", "partially_failed", "failed"]
    facts: list[StoredFact]
    rejected_fact_count: int                         # spans that failed validation
    rejected_reasons: list[str]                      # machine reasons only
    gap_item_ids: list[UUID]
    unsourced_mention_count: int
```

**Validation order after the LLM responds [DECIDED]:**

1. JSON Schema / Pydantic validation. Failure → retry once with the validation errors appended (max 2 attempts); then the run fails loudly, never partially silently.
2. `field_key` ∈ vocabulary for that `procedure` (reject unknown keys — they are not stored).
3. `document_id`/`page_number` must exist and belong to the case.
4. Span resolution: if offsets are `null`, locate `quote_text` in `page_text_version.text_normalized` (exact match; then whitespace-insensitive match producing exact offsets around the matched text; then fuzzy match with ≥0.95 similarity **reported as `fuzzy_recovered`, lowering `confidence` and raising an advisory gap**). If no offset can be found → the fact is rejected and the quoted text is stored as an `unsourced_mention` gap.
5. Span insert → the trigger re-validates against stored text (belt and braces; the service layer is not trusted).
6. Rejected facts are counted, logged (counts only, no text), and shown in the run summary in the UI ("3 extracted items could not be sourced and were not used").

### 3.2 Criteria evaluation output

```python
# domain/schemas/evaluation.py
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

Strict = ConfigDict(extra="forbid")


class Verdict(StrEnum):
    MET = "met"
    NOT_MET = "not_met"
    INSUFFICIENT = "insufficient_documentation"
    NOT_APPLICABLE = "not_applicable"


class EvidenceRef(BaseModel):
    model_config = Strict
    fact_id: UUID                       # must be one of the fact ids supplied in the evidence bundle
    span_id: UUID


class CriterionDecision(BaseModel):
    model_config = Strict
    criterion_code: str                 # must exist in the pinned criteria_set_version
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    rationale: str = Field(max_length=600)     # explanation; NOT a clinical fact source
    supporting: list[EvidenceRef] = []         # facts that argue the criterion is met
    contradicting: list[EvidenceRef] = []      # facts that argue against
    missing_field_keys: list[str] = []         # required documentation not found
    forms_necessary_basis: bool = False        # may this criterion be cited as the necessity basis?


class EvaluationOutput(BaseModel):
    """Response schema of criteria evaluation (prompt_version 'evaluate-v1').
    The LLM classifies; it never decides what the criteria ARE."""
    model_config = Strict
    criteria_set_version_id: UUID
    criteria_fingerprint: str
    decisions: list[CriterionDecision]
    overall: Literal["criteria_met", "criteria_not_met", "insufficient_documentation"]
    overall_rationale: str = Field(max_length=800)
    gaps: list["GapSuggestion"] = []


class GapSuggestion(BaseModel):
    model_config = Strict
    kind: Literal["missing_field", "unsourced_mention", "expired_prior_test",
                  "contradictory_evidence", "unreadable_document"]
    field_key: str | None = None
    criterion_code: str | None = None
    description: str
    suggested_source: str | None = None
    severity: Literal["blocking", "advisory"] = "blocking"
```

**Division of labour [DECIDED].** For criteria whose `logic` predicate is fully evaluable from current facts, the deterministic interpreter decides (fast, free, reproducible) and `is_deterministic=true`. The LLM is asked to rule **only** on criteria the interpreter cannot fully decide (e.g. "documentation must include the ordering provider's clinical assessment") and to explain. Both paths must return `EvidenceRef`s drawn from the supplied bundle: any `fact_id` not in the bundle is a validation error, not a warning. The judge is always the criteria text — the LLM receives the criterion's `plain_text` verbatim in the prompt, so the rule being applied is always visible and versioned.

### 3.3 Letter generation output (the structured document AST)

The LLM returns blocks, not prose. Blocks are the unit of editing, citation and verification.

```python
# domain/schemas/letter.py
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

Strict = ConfigDict(extra="forbid")


class ClaimType(StrEnum):
    CLINICAL_FACT = "clinical_fact"        # must be grounded in fact_ids
    CRITERIA_REFERENCE = "criteria_reference"  # quotes the criteria library; grounded in criterion ids
    ADMINISTRATIVE = "administrative"      # addresses, greetings, dates, case/CPT references
    ATTESTATION = "attestation"            # signer's own words: "I certify that..."
    QUOTED_DENIAL = "quoted_denial"        # verbatim restatement of the payer's own words


class TextRun(BaseModel):
    model_config = Strict
    text: str


class Paragraph(BaseModel):
    model_config = Strict
    block_id: str                                   # stable, server-assigned (e.g. 'blk_7f3a')
    type: Literal["paragraph"] = "paragraph"
    runs: list[TextRun]
    claim_type: ClaimType
    fact_ids: list[UUID] = []                       # required when claim_type == clinical_fact
    criterion_codes: list[str] = []                 # required when claim_type == criteria_reference
    generation_prompt_id: str | None = None          # which generator produced it ('lmn-v1', 'appeal-v1')


class BulletBlock(BaseModel):
    model_config = Strict
    block_id: str
    type: Literal["bullets"] = "bullets"
    items: list[Paragraph]                          # each bullet verified independently
    claim_type: ClaimType = ClaimType.CLINICAL_FACT


class TableBlock(BaseModel):
    model_config = Strict
    block_id: str
    type: Literal["table"] = "table"
    caption: str | None = None
    headers: list[str]
    rows: list[list[str]]
    claim_type: ClaimType
    fact_ids: list[UUID] = []


class DenialResponseBlock(BaseModel):
    """One numbered response to one payer denial reason — the appeal's backbone."""
    model_config = Strict
    block_id: str
    type: Literal["denial_response"] = "denial_response"
    denial_reason_index: int                        # index into letter_version.denial_input.reasons
    denial_reason_text: str                         # reproduced verbatim from the payer's letter
    response: list[Paragraph]
    fact_ids: list[UUID] = []
    criterion_codes: list[str] = []


class CriteriaCitation(BaseModel):
    model_config = Strict
    criteria_set_version_id: UUID
    set_name: str
    version_no: int
    fingerprint: str
    source_citation: dict[str, str | None]           # doc_name, publisher, version, date, url
    is_placeholder: bool
    verification_label: str
    cited_criterion_codes: list[str]


class Block(BaseModel):
    model_config = Strict
    discriminator: Literal["paragraph", "bullets", "table", "denial_response"]
    block: Paragraph | BulletBlock | TableBlock | DenialResponseBlock


class LetterDraftOutput(BaseModel):
    """Response schema of letter generation (prompt_version 'lmn-v1' / 'appeal-v1' / 'p2p-v1')."""
    model_config = Strict
    kind: Literal["lmn", "appeal", "p2p_summary"]
    recipient: dict[str, str | None]                 # {"name":..., "org":..., "address_block":...}
    subject: str
    blocks: list[Block]
    criteria_citation: CriteriaCitation
    unresolved_gaps: list[str] = []                  # gap descriptions the letter deliberately does NOT claim
    generator_notes: str | None = None               # internal only; never exported


class LetterVersionCreate(BaseModel):
    """What the editor PUTs back. Same AST, human-authored."""
    model_config = Strict
    ast: list[Block]
    edit_summary: str | None = None
    base_version_no: int                             # optimistic concurrency
```

**The AST is the source of truth [DECIDED].** HTML is a *render*; Markdown is an *import/export interchange*; the PDF and DOCX are *derivations*. Rationale: PDF/DOCX export fidelity and sentence-level verification both need a structure that carries per-sentence provenance, and neither HTML (whose whitespace is ambiguous) nor Markdown (which loses `claim_type`/`fact_ids`) can hold that. The editor works on a Tiptap document whose node attributes mirror these fields, so a human edit cannot drop provenance — the attribute travels with the block, and any *new* text the human types lands in a block that the server marks `claim_type` unchanged but with `fact_ids` emptied unless the coordinator attaches a source (§8.4).

### 3.4 Claim verification output

```python
# domain/schemas/verification.py
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

Strict = ConfigDict(extra="forbid")


class MatchKind(StrEnum):
    BOUND = "bound"          # sentence was generated from these exact facts
    ENTAILED = "entailed"    # verifier found the facts entail the sentence
    LEXICAL = "lexical"      # quoted text matches a source span ≈ verbatim
    NUMERIC = "numeric"      # every number/date/code in the sentence appears in the cited spans


class CheckResult(BaseModel):
    model_config = Strict
    check: Literal["binding", "numeric", "lexical", "entailment", "administrative"]
    passed: bool
    reason: str = Field(max_length=300)


class SentenceVerdict(BaseModel):
    model_config = Strict
    sentence_index: int
    block_id: str
    sentence_text: str
    claim_type: Literal["clinical_fact", "criteria_reference", "administrative", "attestation", "quoted_denial"]
    verdict: Literal["supported", "unsupported", "unverified", "exempt"]
    confidence: float = Field(ge=0, le=1)
    reason_code: Literal[
        "ok", "no_fact_ref", "unknown_fact_ref", "stale_fact_ref", "numeric_mismatch",
        "date_mismatch", "code_mismatch", "medication_mismatch", "not_in_cited_span",
        "negation_mismatch", "too_specific", "verifier_uncertain", "verifier_unavailable",
        "exempt_administrative", "exempt_attestation", "exempt_criteria_quote", "exempt_denial_quote",
    ]
    checks: list[CheckResult]
    cited_fact_ids: list[UUID] = []


class VerificationOutput(BaseModel):
    """Internal verifier schema (prompt_version 'verify-v1'); the LLM only supplies the
    entailment judgement — binding, numeric, date and code checks are deterministic."""
    model_config = Strict
    sentences: list[SentenceVerdict]


class VerificationSummary(BaseModel):
    model_config = Strict
    verification_run_id: UUID
    letter_version_id: UUID
    counts: dict[str, int]                           # {"sentences":..,"supported":..,"unsupported":..,"unverified":..,"exempt":..,"flagged":..}
    coverage: float                                  # supported / (supported+unsupported+unverified)
    export_blocked: bool
    blocking_verdicts: list[int]                     # sentence indices
    method_version: str
```

**`export_blocked` = any sentence with verdict in {`unsupported`, `unverified`}** unless the coordinator resolved it in a later version (§8.4). The evaluation harness's "hallucination rate" is `unsupported_open / total_sentences` measured on the *final* exported version — i.e. what a payer would actually read.

---

## 4. Provider-agnostic LLM interface

### 4.1 The protocol [DECIDED]

```python
# llm/base.py
from dataclasses import dataclass
from typing import Any, Protocol, Sequence, TypeVar, runtime_checkable

from pydantic import BaseModel

TModel = TypeVar("TModel", bound=BaseModel)


@dataclass(frozen=True)
class LLMMessage:
    role: str          # 'system' | 'user' | 'assistant'
    content: str


@dataclass(frozen=True)
class LLMRequest:
    messages: Sequence[LLMMessage]
    response_model: type[BaseModel]      # JSON Schema is derived from this
    max_output_tokens: int = 8000
    temperature: float = 0.0             # clinical extraction/generation: deterministic by default
    timeout_s: int = 120
    purpose: str = "generic"             # 'extract' | 'evaluate' | 'generate' | 'verify' — for telemetry only
    cache_key: str | None = None         # harness/test determinism


@dataclass(frozen=True)
class LLMUsage:
    input_tokens: int | None
    output_tokens: int | None
    model: str
    provider: str
    latency_ms: int
    stop_reason: str | None = None


@dataclass(frozen=True)
class LLMResponse:
    parsed: BaseModel                   # already validated against LLMRequest.response_model
    raw_text: str | None                # retained ONLY when PHI logging flag permits; else None
    usage: LLMUsage


class LLMProvider(Protocol):
    name: str

    def health(self) -> bool: ...

    def complete_structured(self, request: LLMRequest) -> LLMResponse:
        """Structured JSON output validated with Pydantic. MUST raise LLMValidationError
        (not return partial data) when the response cannot be parsed/validated."""
        ...


class LLMError(Exception): ...
class LLMTimeoutError(LLMError): ...
class LLMValidationError(LLMError):
    def __init__(self, message: str, validation_errors: list[str]) -> None: ...
class LLMRefusedError(LLMError): ...      # provider safety refusal — surfaced to the user, never silently retried
```

**Contract requirements every provider must meet:**

1. Return JSON matching the Pydantic model's JSON Schema, or raise `LLMValidationError`. No best-effort coercion of clinical values.
2. Never stream partial clinical output into the database.
3. Support `temperature=0` semantics where the API allows; where a provider only supports temperature > 0, the provider declares `supports_temperature: bool` and the service adds a warning to the run record (`nondeterministic_provider: true`).
4. Carry provider/model identifiers back in `LLMUsage` so every `extraction_run`, `criteria_evaluation` and `verification_run` records exactly which model produced it. This matters: the evaluation report is meaningless if the model is not recorded.
5. Implement `health()` cheaply and never with PHI.

### 4.2 Providers and configuration

| Provider class | Use | Notes |
|---|---|---|
| `MockLLMProvider` | dev default, CI, Playwright, harness unit runs | Deterministic canned responses keyed by `cache_key` + `purpose`, read from `data/synthetic/llm_fixtures/*.json`. No network. **Startup fails if selected under `CARDIOAUTH_ENV=production`.** |
| `OpenAICompatibleProvider` | local models (Ollama/vLLM) and any vendor exposing an OpenAI-shaped API | `base_url` configurable; used for the owner's own evaluation of a candidate provider at no lock-in |
| `BedrockProvider` | production candidate | AWS Bedrock, structured output via tool-use; BAA-eligible service [RECOMMENDED] |
| `AzureOpenAIProvider` | production candidate | Azure OpenAI in a BAA-covered subscription [RECOMMENDED] |
| `RecordingProvider` | wrapper | Decorator that wraps any provider and writes request/response pairs to disk for harness analysis — allowed only when `CARDIOAUTH_PHI_LOGGING=dev` |

```ini
# .env.example (dev)
CARDIOAUTH_ENV=dev
LLM_PROVIDER=mock
LLM_MODEL=mock-extract-v1
LLM_API_KEY=                       # never committed; dev mock needs none
LLM_BASE_URL=                      # e.g. http://localhost:11434/v1 for Ollama
LLM_TEMPERATURE=0.0
LLM_TIMEOUT_S=120
LLM_MAX_RETRIES=2
LLM_FALLBACK_PROVIDER=             # optional; must be BAA-capable in production
CARDIOAUTH_PHI_LOGGING=dev         # 'off' in production; startup refuses 'dev' in production
CARDIOAUTH_LLM_TASK_MODEL_EXTRACT= # per-task model override, falls back to LLM_MODEL
CARDIOAUTH_LLM_TASK_MODEL_VERIFY=
```

**Dev-vs-production logging [FIXED requirement]:**

| | `CARDIOAUTH_ENV=dev` | `CARDIOAUTH_ENV=production` |
|---|---|---|
| Prompt / completion bodies | Logged only when `CARDIOAUTH_PHI_LOGGING=dev`; written to `logs/llm/` (git-ignored) with a rotation cap | **Never** written, at any level. The provider receives `log_body=False` and the log filter raises on any attempt |
| Log content | IDs, counts, token usage, latencies, field keys, verdict codes | IDs, counts, token usage, latencies, field keys, verdict codes |
| Startup guard | Warns if `CARDIOAUTH_PHI_LOGGING=dev` | **Process exits** if `CARDIOAUTH_PHI_LOGGING=dev` or `LLM_PROVIDER=mock` or `BLOB_BACKEND=local` |

**Enforcement, not discipline.** A `logging.Filter` installed on the root logger refuses any record whose `msg` or `args` contain substrings from a denylist and whose origin is a service module handling document text (the ingress points are enumerated: `ingest_service`, `extraction_service`, `letter_service`, `verification_service`). Those modules are linted to forbid f-string formatting of document text into log calls (a custom ruff rule `no-phi-in-logs`), and a test greps the codebase and asserts every log call in those modules uses an allowlisted set of fields. The practical rule for the whole codebase: **log identifiers, never values.**

**Adding a new provider** is: (1) subclass/implement `complete_structured`, (2) map provider errors to the `LLMError` hierarchy, (3) register in `llm/registry.py`, (4) add a row to the env table and to the provider test matrix (`tests/llm/test_provider_conformance.py`, which every provider must pass against a fake transport). No service code changes. Adding a provider is explicitly a **configuration + adapter** change; the promise to the owner is that switching to a BAA-capable vendor does not touch the clinical pipeline.

---

## 5. OCR and document pipeline

### 5.1 The interface [DECIDED]

```python
# ocr/base.py
from dataclasses import dataclass
from typing import Protocol

@dataclass(frozen=True)
class PageText:
    page_number: int
    text: str
    method: str                 # 'text_layer' | 'tesseract' | 'textract' | 'pasted'
    mean_confidence: float | None
    word_confidences: list[tuple[str, float]] | None = None   # for per-word highlighting
    image_blob_key: str | None = None

@dataclass(frozen=True)
class OcrResult:
    page_count: int
    pages: list[PageText]
    warnings: list[str]

class OcrBackend(Protocol):
    name: str
    def extract(self, blob_key: str, mime_type: str, *, dpi: int = 300) -> OcrResult: ...
```

| Backend | Dev/prod | Behaviour |
|---|---|---|
| `PdfTextLayerBackend` | both | If a PDF page has ≥ `MIN_TEXT_LAYER_CHARS` (default 80) extractable characters, use the embedded text verbatim. Offsets are then exact and OCR is never involved. |
| `TesseractBackend` | **dev default** | Rasterise page at 300 dpi (pdf2image/poppler), OCR with `--oem 1 --psm 3`, capture per-word confidence via `image_to_data`. No network, no PHI egress. |
| `TextractBackend` / `AzureDocIntelBackend` | production | BAA-eligible; returns page text + confidence + tables/forms. Same `OcrResult` contract. |
| `PasteBackend` | both | Text typed/pasted by the coordinator. One page, method `pasted`, `mean_confidence=None` (treated as reliable, because a human supplied it and it is displayed for confirmation). |

Selection is `OCR_BACKEND` env var; per-page fallback is automatic: `text_layer → configured_backend`. A page that yields < 80 chars from the text layer is treated as a scan even inside a digital PDF (common with faxed-and-rescanned reports).

### 5.2 How page numbers and character offsets stay valid

1. **Page identity is created once.** `document_page` rows are created at ingest with `page_number` 1..N in the order the renderer/OCR backend emits, and are never renumbered or deleted while the document is alive. A citation's `(document, page)` therefore points at the same pixels forever.
2. **Text is versioned, not mutated.** Text always lands in a *new* `page_text_version`. Nothing ever updates `text_normalized` of an existing row (trigger-enforced).
3. **Offsets are half-open, 0-based, into `text_normalized` only.** Spans never address the raw PDF byte stream, never address an image, and never address a "cleaned" copy. Normalisation is applied once and recorded (§2.4), so the mapping text→offsets is a pure function of a stored string.
4. **Page images are kept** (`image_blob_key`) so the UI can render the exact page with the span highlighted — the reviewer sees the quote in context, which is the real defence against a plausible-but-wrong extraction.
5. **The UI never asks the model for a quote.** It renders `quote_text` from `fact_span`, with a "view in document" link that opens the page image at the span's bounding box (word boxes from `word_confidences`, when available; otherwise the text-layer position from `pdfplumber`).

### 5.3 Failure and low-confidence handling [DECIDED]

| Situation | Behaviour |
|---|---|
| Text layer present | Use it, `ocr_confidence` null, no flag. |
| Scanned, OCR mean confidence ≥ 0.80 | Accept. `ocr_method` recorded per page. |
| Scanned, OCR mean confidence 0.60–0.80 | Accept but create an advisory `gap_item` of kind `low_ocr_confidence` naming the page, and show the page with a warning so the coordinator can check the scan. Extraction on that page proceeds (spans on low-confidence text are marked `low_confidence_source` and any fact sourced *only* from such a page gets an advisory gap). |
| Scanned, OCR mean confidence < 0.60 | Do **not** extract from that page. Mark the `document_page` unreadable, create a blocking `gap_item` (`unreadable_document`), and offer "re-upload a better scan" and "type the relevant text" (paste flow, which creates a `pasted` page and a new text version — a legitimate path because a human supplied it). The letter cannot claim anything from that page. |
| Page blank / image corrupt / encrypted PDF | Ingest `failed` with a redacted error; the case shows "1 of 6 documents could not be read"; extraction runs on the readable subset and reports `pages_unreadable`. |
| OCR backend unavailable (network/API) | Job retries with backoff; after `OCR_MAX_RETRIES` the document stays `needs_review` with an actionable message; extraction for the case does not silently proceed as if the document were empty — the run records which documents were unavailable. |
| Re-OCR (coordinator requests it, or a better backend is configured) | `POST /api/pages/{id}/reocr` inserts a **new `page_text_version`** and (optionally) makes it current. Every `fact_span` bound to the old version is marked `stale`; the affected facts stop being eligible as letter evidence and appear in the UI with a **re-anchor** action that tries exact `quote_text` search in the new version (then fuzzy ≥0.95). Auto-re-anchored spans keep their fact; unrecoverable ones are quarantined (fact `is_current=false`) and produce an advisory gap, never a silent drop. The generating letter is invalidated: if a signed letter used a quarantined fact, the letter version is marked `evidence_invalidated` and its sign-off is flagged for review rather than deleted (§8.5). This is the honest answer to "the OCR was bad, we re-ran it": provenance never lies about which text it came from. |
| Pasted text | Single page, method `pasted`, confidence treated as 1.0, and the UI shows the pasted text beside the facts extracted from it so the coordinator can correct typos. |

### 5.4 Limits (see §11 Q8 for the rationale and the number to approve)

Per document: 100 MB, 500 pages. Per case: 25 documents, 2 000 total pages, 2 GB total bytes. Rejections are explicit (HTTP 413 with a message that names the limit) and audited (`document.rejected_limits`). The limits exist because OCR and extraction cost scale with pages and the MVP's design assumption is a case that a coordinator assembles in minutes, not an entire chart dump.

---

## 6. Status model and case tracker

### 6.1 States [FIXED]

`draft` → `ready_for_review` → `submitted` → `approved` | `denied` → `appealed` → (terminal: `closed`) plus `withdrawn` and `cancelled`.

| State | Meaning | Exit criteria |
|---|---|---|
| `draft` | Case exists; documents may be arriving; work in progress | At least one document ingested **and** an evaluation exists **and** no blocking gap is `open` (or all waived) **and** at least one letter exists |
| `ready_for_review` | Coordinator declares the packet complete; a physician may review | All required letters have an active sign-off |
| `submitted` | The **coordinator** submitted to the payer outside this tool; recorded here | A payer decision is recorded |
| `approved` / `denied` | Payer decision recorded (with date and, for denials, the denial text) | approved → `closed`; denied → `appealed` or `closed` |
| `appealed` | An appeal letter was signed and submitted outside the tool | Payer decision recorded → `approved`/`denied`; `closed` after final decision |
| `withdrawn` / `cancelled` | Not submitted / duplicate or erroneous case | Terminal. Reason required. |

### 6.2 Transition table (enforced in `tracker_service`; the transition is validated before the row is written)

| From | To | Who may trigger | Preconditions |
|---|---|---|---|
| `draft` | `ready_for_review` | coordinator, admin | ≥1 evaluated criterion set; no `open` blocking gap unless waived with a reason; ≥1 letter with a verification run whose `export_blocked=false` or whose flags were accepted-with-reason (**approval of flags is not permitted** — see below); every document `ready` or explicitly ignored |
| `draft` | `cancelled` | coordinator, admin | reason required |
| `ready_for_review` | `draft` | coordinator, admin | reason required (reviewer sent it back) |
| `ready_for_review` | `submitted` | coordinator, admin | letter of medical necessity carries an active physician sign-off; `submitted_at` set; **`submission_ref` required** (portal name + confirmation number, or "mailed" + tracking, or "fax" + date) |
| `submitted` | `approved` | coordinator, admin, physician | decision date required; optional approval reference |
| `submitted` | `denied` | coordinator, admin, physician | denial text required (pasted or uploaded as a `denial_letter` document) or explicit "reasons not stated" |
| `submitted` | `withdrawn` | coordinator, admin | reason |
| `denied` | `appealed` | coordinator, admin | appeal letter signed (`kind='appeal'`); appeal submission recorded via `submission_ref` |
| `denied` | `closed` | coordinator, admin | reason (no appeal) |
| `approved` | `closed` | any role | — |
| `appealed` | `approved`/`denied` | coordinator, admin, physician | decision recorded |
| `appealed` | `closed` | coordinator, admin | final decision recorded or appeal abandoned, with reason |
| `any` | `cancelled` | admin | reason; audited loudly |

Every transition writes `case_status_history` and `case_status_changed`. Illegal transitions return `409` with the precondition that failed (e.g. `"signoff required for kind=lmn"`), naming the exact rule — never a generic error.

**Hard rule:** verification flags cannot be overridden into an export. There is no "accept risk and export" path for an unsupported sentence. The only ways past a flag are: edit the sentence, delete it, or attach it to a real source span (§8.4). This is intentional and is the feature, not an inconvenience.

### 6.3 Gap-blocking rule

`ready_for_review` requires no `open` blocking gap. The coordinator may `waive` a gap, which requires a free-text reason, is recorded in `gap_item.resolution_note` and audited as `gap.waived` with the reason. Waiving does **not** permit the letter to assert the missing item; the letter simply does not claim it — consistent with INV-1/INV-3.

### 6.4 Due dates and turnaround [DECIDED]

- `submitted_at` = the moment the coordinator records submission (historical truth, may be earlier than the recorded moment; the UI allows a back-dated `submitted_at` within 30 days and audits the difference).
- `due_date` = `submitted_at + payer.turnaround_days` calendar days (payer default 14; overridable per case). Medicare Advantage and commercial plans differ; the payer row carries the default so a placeholder default is data, not code.
- **Tracker buckets:** `overdue` (today > due_date), `due_soon` (≤3 days), `on_track`, `awaiting_decision` (submitted, no due date recorded).
- **Metrics on the dashboard:** median days to first submission, median payer decision turnaround, % of cases with ≥1 blocked gap at submission time, appeal rate, appeal overturn rate. All computed from `case_status_history` and `submission_ref`, so they need no extra columns.

---

## 7. Auth, RBAC, audit, and keeping PHI out of logs

### 7.1 Authentication [DECIDED]

- Email + password, **Argon2id** (memory 64 MiB, time 3, parallelism 4), per-user salt, rehash-on-login if params change. Password minimum 12 characters; breach-list check against a locally bundled top-100k list (no external API call with a candidate password, ever).
- **TOTP 2FA** (RFC 6238, `pyotp`), secret encrypted at rest with `APP_KEY` (AES-GCM), 6 digits, 30 s step, ±1 step drift, 10 single-use recovery codes stored hashed and shown once. **Enrolment is required for physician and admin roles and strongly prompted for coordinators** (see §11 Q4 for the default: enforced for all roles at first login, with a 1-case grace period).
- Server-side sessions: opaque 256-bit cookie value; only its SHA-256 is stored (`user_session.token_hash`). Cookie: `HttpOnly`, `SameSite=Lax`, `Secure` outside dev, `Path=/`. Rotation on login and on privilege change (role change, password change, TOTP re-enrolment revokes all sessions).
- Rate limiting / lockout: 5 failures → 15-minute lock (`locked_until`), exponential thereafter; IP-independent so a distributed attempt cannot be used to lock a known user out indefinitely (the lock is per-user but the endpoint is rate-limited per-IP too).
- CSRF: double-submit token on all state-changing requests, plus `SameSite=Lax` and origin checking. The API rejects cross-origin state changes.
- No password reset by email link in the MVP (no email provider, and PHI-free emails are still an infra dependency): **admin-initiated reset** that issues a one-time code out of band, forces a password change and revokes sessions. [ASSUMED — see §11 Q4.]

### 7.2 Session timeout [DECIDED — see §11 Q4]

- **Idle timeout: 15 minutes.** Server-side authoritative (`idle_expires_at`); each authenticated request slides it. The frontend shows a 60-second countdown modal, then logs out and returns to the login page with a benign return URL.
- **Absolute timeout: 8 hours** (`absolute_expires_at`), no extension by activity.
- **Step-up (re-auth) required for:** signing a letter, exporting PDF/DOCX, resolving/waiving a gap, editing the criteria library, changing users or roles, viewing the audit log, and re-pinning criteria. Step-up = password (and TOTP if enrolled) again, valid for **5 minutes**, recorded as `user_session.reauth_at`. Sign-offs store `reauth_at` and a DB constraint/tripwire requires it within 5 minutes of `signed_at`.
- Expiry behaviour: **no state is lost.** Sessions expiring do not discard work — draft letter versions are server-side, uploads are server-side, and unsaved editor keystrokes are autosaved client-side to `sessionStorage` every 5 s and replayed on re-login with a diff prompt. A session expiring mid-export fails the export (which never happens silently), it does not produce a partial file.

### 7.3 RBAC matrix [FIXED roles, DECIDED permissions]

Legend: ✅ allowed · 🔎 read-only · ⬜ denied · ⚠️ allowed with step-up or extra precondition.

| Action | coordinator | physician | admin |
|---|---|---|---|
| Create/edit case, upload documents | ✅ | ⬜ | ✅ |
| View case, documents, checklist, gaps | ✅ (own practice) | ✅ (assigned or any in practice) | ✅ |
| Run/cancel extraction, evaluation | ✅ | ⬜ | ✅ |
| View documents in the browser | ✅ | ✅ | ✅ |
| Download/export documents | ⚠️ audited | ⚠️ audited | ⚠️ audited |
| Generate letters (LMN/appeal/P2P) | ✅ | 🔎 (may generate a P2P summary) | ✅ |
| Edit letters | ✅ | ✅ (may edit before signing) | ✅ |
| Sign a letter | ⬜ | ✅ (physician NPI required) | ⚠️ only with an explicit "covering physician" attestation recorded in the sign-off |
| Export PDF/DOCX | ⚠️ step-up | ⚠️ step-up | ⚠️ step-up |
| Record payer decision / status transitions | ✅ per §6.2 | ✅ per §6.2 | ✅ |
| Waive a blocking gap | ⚠️ reason required | ⬜ | ⚠️ reason required |
| Criteria library read | 🔎 | 🔎 | ✅ |
| Criteria library create/edit/publish | ⬜ | ⬜ | ✅ |
| User management | ⬜ | ⬜ | ✅ (within practice) |
| View audit log | ⬜ | 🔎 own actions | ✅ (practice scope) |
| Delete/redact a case | ⬜ | ⬜ | ⚠️ soft-redact with mandatory reason; audit entry retained |

RBAC is enforced **server-side at the router dependency level** (`require(role, action)`) and re-checked in the service layer for state-changing operations — never by hiding UI. Every denial is audited with `outcome='denied'`, which makes privilege probing visible.

### 7.4 Audit log: what every entry records [FIXED]

`occurred_at`, `actor_user_id` + `actor_role`, `action` (closed vocabulary enum, ~60 values), `object_type` + `object_id`, `case_id`, `practice_id`, `outcome`, `detail` (JSON), `request_id`, `session_id`, hash-chain fields.

Mandatory audited actions (the vocabulary is enumerated in one module so it cannot drift):

- **View:** `case.viewed`, `document.viewed`, `letter.version_viewed`, `criteria.version_viewed`, `audit_log.viewed`, `gap.report_viewed`, `document.exported`, `letter.exported`.
- **Edit:** `case.created`, `case.updated`, `document.uploaded`, `document.text_pasted`, `document.deleted`, `page.reocr_requested`, `extraction.started/completed`, `evaluation.completed`, `criterion_verdict.overridden`, `gap.waived`, `gap.resolved`, `letter.generated`, `letter.edited`, `letter.version_created`, `verification.completed`, `criteria.set_created/version_published/criterion_updated`, `case.criteria_repinned`.
- **Export/sign:** `letter.exported` (format, version_no, ast_sha256, verification_run_id), `letter.submitted_for_review`, `letter.signed`, `letter.signoff_revoked`, `document.exported`.
- **Auth:** `auth.login_succeeded`, `auth.login_failed`, `auth.totp_failed`, `auth.logout`, `auth.session_expired`, `auth.step_up_succeeded/failed`, `auth.password_changed`, `user.created/deactivated/role_changed`.
- **Status:** `case.status_changed` (from, to, reason).

`detail` holds **identifiers, counts and field names** — e.g. `{"document_id":"…","pages":7,"ocr_method":"tesseract","mean_conf":0.91}` — and never document text, fact values, quotes or letter sentences. A test asserts no audited `detail` key can carry a free-text value from a denylist (`quote_text`, `value_text`, `sentence_text`, `rationale`, …).

### 7.5 Tamper resistance and PHI out of logs

**Tamper resistance [DECIDED]:** append-only grants (app role has no `UPDATE`/`DELETE` on `cardioauth_audit.*`); hash chain where `entry_hash = sha256(canonical_json(row_excluding_entry_hash) || prev_hash)`; `scripts/audit_chain_verify.py` verifies the chain and is run nightly (scheduled job) and in CI; the audit schema is owned by a role the app cannot assume, so an application compromise cannot rewrite history; the verifier reports the first divergent `id`, which identifies the earliest point of tampering. Weekly optional external anchor (off-site append of the latest `entry_hash`) — see §11 Q7 for the default position.

**PHI out of logs [INV-5]:** structured JSON logging with a fixed schema for `cardioauth.*` loggers; the log filter described in §4.2; identifiers only; request/response bodies never logged; exception handlers log the exception type and a correlation id, never `str(exception)` from a service that may embed text; Sentry-style error reporting, if added later, must be self-hosted or BAA-covered and is out of MVP scope; uvicorn access logs are configured to omit query strings (which could contain a search term that is PHI) and to log only method, path template, status and duration. A test suite (`tests/test_no_phi_in_logs.py`) drives the full pipeline over synthetic documents containing sentinel strings (`SENTINEL-PHI-<n>`) and asserts the sentinel appears in **no** log record, no audit `detail`, and no exception payload.

---

## 8. Letter generation and claim verification in detail

This is the section the owner cares about most. The design principle is blunt: **the generator is allowed to write only from a closed evidence bundle, and a separate stage assumes it did not.**

### 8.1 The letter AST and why it is structured

Represented in §3.3. Three properties matter:

1. Every factual block carries `fact_ids` pointing at `fact` rows, each of which has ≥1 validated span (INV-1). The bundle passed to the generator contains (a) the fact text, (b) the quote, (c) document kind and page — so the model is composing from sources, not from memory of the patient.
2. Every sentence can be located deterministically for verification: sentence indices are computed from block text by a server-side segmenter and stored in `claim_verdict.sentence_index`, so the UI can highlight the offending sentence and the harness can diff two versions sentence by sentence.
3. `claim_type` separates what must be grounded (clinical facts, criteria references) from what cannot be (administrative lines, the physician's attestation, the payer's own quoted words). Exempt categories are a **closed enumerate**, not a model choice: the generator may not label its own prose exempt. The server derives `claim_type` from the block's role in the template (`recipient`/`subject`/`signature` blocks → administrative; `criteria_citation` → criteria_reference; `denial_reason_text` copied verbatim from `denial_input` → quoted_denial; everything else → clinical_fact). The model's output schema has no `claim_type` field for free paragraphs — a deliberate omission.

### 8.2 Generation pipeline [DECIDED]

```
evidence_bundle = {
  "case": {procedure, cpt, payer, date_of_service, urgency, ordering_provider},
  "facts": [ {fact_id, field_key, value_text, polarity, quote, document_kind, page_number, confidence} ],
  "criteria": [ {code, category, plain_text, verdict, source_citation} ],   # verbatim from the pinned version
  "gaps": [ {description, severity} ],      # so the letter can avoid asserting absent items
  "patient_display": {initials, birth_year},  # never a full name from the model's imagination
  "denial": {reasons: [{index, text, category_hint}], payer_name, denial_date}   # appeals only
}
```

For each letter kind: `lmn` (initial request), `appeal` (point-by-point), `p2p_summary` (talking points for the physician, deliberately non-prose: a bulleted evidence list plus likely reviewer objections and the facts that answer them).

Prompt assembly rules: the system prompt contains the template skeleton (fixed sections, fixed ordering) and the hard constraints; the criteria library text enters **verbatim** from the pinned version with its citation; the evidence bundle enters as structured JSON with ids. The prompt instructs the model to produce blocks and to reference fact ids. **The prompt itself is versioned** (`lmn-v1`) and stored with the letter (`generation_prompt_id`), so a letter can always be explained.

Post-generation server-side validation, in order:

| # | Check | On failure |
|---|---|---|
| 1 | Pydantic validation of `LetterDraftOutput` | retry once with errors; then fail the run |
| 2 | Every `fact_ids` id exists in the bundle, is `is_current`, and has a non-stale span | drop the block's ungrounded ids; if a factual block is left with none, convert it to a **flag stub** (a visibly-marked placeholder paragraph) rather than keeping the sentence |
| 3 | `criterion_codes` exist in the pinned version | same handling |
| 4 | No `<script>`/HTML injection in runs; runs are plain text | sanitise, log |
| 5 | Placeholder check: if the criteria version `is_placeholder`, force the `verification_label` into the criteria citation block and add the banner block | automatic insert |
| 6 | Numeric/date/code sweep (§8.3 stage 2) as a pre-check | any failure already recorded, no retry — the verifier will flag it and the coordinator fixes the sentence |

Note what is deliberately *not* here: no "the model promised it was accurate" step. Step 2 means **the system cannot even store** a factual sentence whose cited fact does not exist.

### 8.3 The verification algorithm [DECIDED — the core of the feature]

`verification_service.verify(letter_version) -> VerificationSummary`, `method_version='verify-v1'`. Five stages, each storing its own `CheckResult`s. Stages 1–3 and 5 are fully deterministic (no LLM, no cost, no variance); stage 4 is the only LLM call.

**Stage 0 — decomposition.** Walk the AST. For each block, split its text into sentences with a deterministic segmenter (Unicode sentence-boundary rules; abbreviations list seeded with clinical ones — `Dr.`, `e.g.`, `vs.`, `approx.`, `No.`, `Hg.`). Bullets are split per item. Each sentence becomes a `claim_verdict` row with a global `sentence_index`. Assign `claim_type` server-side per §8.1.

**Stage 1 — binding check (deterministic).**
For a sentence with `claim_type='clinical_fact'`:
- No `fact_ids` on its block → `unsupported`, `reason_code='no_fact_ref'`. **This is the anti-hallucination rule.**
- Any id unknown to the case, or `is_current=false`, or whose spans are all stale → `unsupported`, `unknown_fact_ref` / `stale_fact_ref`.
- All ids valid → continue to stage 2.
For `criteria_reference`: the cited criterion codes must exist in the pinned version and the quoted text must match the criterion's `plain_text` (fuzzy ≥0.98 for paraphrases of the criterion text, since criteria are licensed text and should be quoted, not summarised); otherwise `unsupported` (`not_in_cited_span`). If `is_placeholder=true`, the sentence is additionally surfaced with the unverified banner.
For `administrative` / `attestation` / `quoted_denial` → `exempt` with the corresponding `exempt_*` reason code, **but only if the sentence contains no clinical quantity**: an exempt line is re-checked for numbers, dates, ICD-10/CPT patterns, units and drug names; if any appear, the sentence is demoted to `clinical_fact` and re-run through stages 1–4. (This stops "As you know, the patient's EF is 35%" from riding in on an administrative block.)

**Stage 2 — numeric / date / code / negation checks (deterministic).**
Extract from the sentence: all numerals with units (`%`, `mets`, `mmHg`, `mg`, `mcg`, `min`, `sec`, `weeks`, `months`, `years`, `g/dL`), all dates, all codes matching `[A-Z]\d{2}(\.\d+)?` (ICD-10), `\d{5}` (CPT), all medication names (against the fact `medication.name` values and a bundled RxNorm-ish name list), and negation cues (`no`, `denies`, `without`, `negative for`, `never`).
For each numeric/date/code token: it must appear either literally in one of the cited facts' `value_text`/`quote_text`, or be derivably equal (e.g. `55%` vs `55`; `03/12/2024` vs `2024-03-12`; `LVEF of 55` vs `lvef.value=55`) — comparison is on the *canonical* tuple (value, unit, ±0.0 tolerance for counts, ±1 for percentages to absorb trivial rounding only where the fact's `value_typed.unit` matches). Mismatch → `unsupported` with `numeric_mismatch` / `date_mismatch` / `code_mismatch` / `medication_mismatch`.
Negation check: if the sentence is negated but all cited facts have `polarity='present'` → `unsupported`, `negation_mismatch`. (And the converse: an affirmative sentence citing only `negated`/`absent` facts is flagged.) This catches the classic failure where a model writes "the patient has diabetes" from a note that says "no history of diabetes".
Any *numeric/date/code* token in a factual sentence that has no counterpart in any cited fact → `unsupported` (`too_specific`). This is the check that stops invented EFs, invented dates and invented ICD-10 codes.

**Stage 3 — lexical containment (deterministic).**
Compute token-level coverage: the fraction of the sentence's clinical content tokens (nouns/verbs except stopwords and template words) that appear in the union of the cited spans' `quote_text`. Record as `CheckResult(check='lexical')`. This is not itself a verdict, except in one case: coverage > 0 and the sentence introduces a *diagnostic or procedural claim* whose key noun appears in **none** of the cited spans (e.g. sentence says "stress-induced ischemia"; no cited span contains `ischemia`) → `unsupported`, `not_in_cited_span`. Rationale: paraphrase is legitimate, inventing a finding's name is not.

**Stage 4 — entailment check (LLM, the only non-deterministic stage).**
Only sentences that passed stages 1–3 reach here. Batch them (one call per letter version, or per 20 sentences) with their cited spans' quotes. The verifier model is asked, per sentence, for a strict three-way judgement plus a confidence and a one-line reason: `entailed` / `partially_entailed` / `not_entailed`, with the instruction that *partially* means "the quote supports part of the sentence and the rest is unsupported" and that hedged clinical reasoning ("would benefit from", "is likely to") must be judged on the facts it rests on, not on plausibility. Mapping:
- `entailed` and confidence ≥ 0.7 → `supported`.
- `entailed` and confidence < 0.7 → `unverified`, `verifier_uncertain` — the sentence **blocks export** until a human looks at it (a cautious default: uncertainty is treated as a problem, never as a pass).
- `partially_entailed` → `unsupported`, `not_in_cited_span`, with the reason naming the unsupported fragment.
- `not_entailed` → `unsupported`.
- Verifier provider unavailable / call fails → `unverified`, `verifier_unavailable`, and `export_blocked=true`. **There is no fail-open path.** The harness counts this as an unflagged-hallucination risk and the milestone gate treats any occurrence as a failure of the run.

**Stage 5 — assembly and gating.**
Counts and coverage computed; `export_blocked = any(verdict in {unsupported, unverified})`; blocking sentence indices stored; UI flags inline (red underline + hover reason + "View source" / "Attach source" / "Remove sentence" actions). The `verification_run` is stored against the exact `letter_version` it judged, and the letter's effective verification is always the latest run whose `letter_version_id` equals the letter's current version.

**Why zero unflagged is achievable.** A sentence reaches a payer only if (a) it is bound to facts that exist, (b) every number/date/code in it exists in those facts, (c) its key clinical noun appears in those facts' quotes, and (d) a second model judges the binding sound — with any uncertainty defaulting to "blocked". The realistic residual risk is a *wrong* source (a span that says something different from what the sentence claims in a way stages 2–3 cannot see — the "correct-looking but semantically off" case), which stage 4 targets and which the human reviewer catches by clicking through to the page image. The evaluation report breaks out exactly this residual (`unflagged_unsupported` measured against human-annotated ground truth) so it is measured, not assumed.

**Human-reviewed floor.** The verified claim set is never presented as "the letter is correct"; the UI states "all clinical sentences trace to sources in this case; N sentences could not be verified and are blocked". Honest framing is part of the design.

### 8.4 Editor and human edits [DECIDED]

- The editor edits the AST (Tiptap nodes carry `block_id`, `claim_type`, `fact_ids` as node attributes). Saving `PUT /api/letters/{id}/versions` with `base_version_no` creates a **new `letter_version`** (`source='edited'`), runs verification on it, and returns the verdicts. Optimistic concurrency: a stale `base_version_no` → `409` with the conflicting version, never a silent overwrite.
- **A human edit must never be able to drop provenance.** Server-side rules applied to every incoming version:
  - A block whose text changed since the base version has its `fact_ids` **cleared automatically** unless the client supplies an explicit `cite` object. Text that changed cannot keep a citation it was not written against.
  - A new block with no citation whose text contains clinical quantities or clinical nouns → its sentences verify as `unsupported` (`no_fact_ref`). A human-typed unsupported claim is flagged exactly like a generated one. **This is the requirement the owner stated, enforced structurally.**
  - The coordinator can fix a flag in three ways, all audited: (1) edit the sentence to follow the source, (2) delete the sentence, (3) **attach a source**: pick a fact/span from the case (searchable by field key or document) and mark the sentence as covered by it — this sets `fact_ids` and re-runs verification stages 2–4 on the new binding, which can still fail (attaching a span that does not contain the number still yields `unsupported`).
  - "Mark as non-factual" is available only for blocks whose text passes the exempt re-check in stage 1 (no quantities, no drug names, no codes). A coordinator cannot exempt a clinical claim into existence.
- Every edit produces `letter.edited` with `detail = {from_version, to_version, blocks_changed, sentences_added, sentences_removed, flags_introduced, flags_resolved}` — the audit trail shows whether a human *introduced* an unsupported claim.
- Non-blocking warnings stay visible after export: the exported PDF/DOCX is generated from the version whose verification had `export_blocked=false`; the export event records `verification_run_id` and `ast_sha256`, so the exact document text a payer received is reconstructible.

### 8.5 Appeals: responding to denial reasons point by point [DECIDED]

Input: denial reasons are either **pasted** into a text area or **uploaded** as a `denial_letter` document (PDF/scan → OCR → the reasons are extracted as `quoted_denial` spans; the extraction schema for denials is `DenialReasonsOutput`, whose reasons each carry a span). Input handling:

1. **Segmentation:** `denial_service.parse_reasons()` — LLM-assisted, returns an ordered list of `{index, text, category_hint}` where `text` must be a span-validated quote from the denial document (uploaded case) or the exact pasted text (pasted case, split on numbering/bullets, confirmed by the coordinator in the UI — a human confirms the split, so a bad split is visible rather than baked in).
2. `category_hint` ∈ a closed enumerate: `not_medically_necessary`, `insufficient_documentation`, `experimental_investigational`, `not_covered_benefit`, `prior_testing_required`, `medical_record_missing`, `coding_or_eligibility`, `other`. Categorisation is a *hint* that pre-selects which criteria the response should draw on; the coordinator can change it. The hint is not a clinical judgement.
3. **Generation** produces one `DenialResponseBlock` per reason, in order, each containing: the reason quoted verbatim (`quoted_denial`, exempt but quantity-checked), a response composed of blocks citing facts, and the criteria relied on. The template forces an explicit answer to each reason — the generator cannot merge or skip reasons; the validator rejects output whose `denial_reason_index` set ≠ the input set.
4. **Where the case genuinely cannot answer a reason** (e.g. "records missing" and they are missing), the block is generated as a **gap stub**: "Response requires: <cited criterion / missing field>. Not asserted." and it becomes a blocking gap. The letter then contains a visible, unmissable placeholder *in the coordinator's view* and cannot be exported until it is filled or the reason is answered honestly — an appeal that quietly ignores a denial reason is the failure mode this prevents.
5. Verification runs on appeals identically, plus an extra check: every `denial_reason_index` in `denial_input` has exactly one response block (`claim_type` aggregate check → `verification_run.counts['denial_reasons_answered']`).

**Denial-reason extraction schema** (uploaded denial letters; prompt `denial-parse-v1`):

```python
# domain/schemas/denial.py
class DenialReason(BaseModel):
    model_config = Strict
    index: int                                   # 1-based, order of appearance in the payer letter
    text: str                                    # verbatim quote; span-validated when from an upload
    span: SpanRef | None = None                  # required when the source is a document, not a paste
    category_hint: Literal["not_medically_necessary", "insufficient_documentation",
                           "experimental_investigational", "not_covered_benefit",
                           "prior_testing_required", "medical_record_missing",
                           "coding_or_eligibility", "other"]
    confidence: float = Field(ge=0, le=1)

class DenialReasonsOutput(BaseModel):
    model_config = Strict
    payer_name: str | None = None
    denial_date: date | None = None
    auth_reference: str | None = None
    reasons: list[DenialReason] = Field(min_length=1)
    unparsed_text: str | None = None             # shown to the coordinator when segmentation may be wrong

class DenialInput(BaseModel):                    # stored on letter_version.denial_input
    model_config = Strict
    source: Literal["pasted", "uploaded"]
    document_id: UUID | None = None
    confirmed_by: UUID                           # the human who confirmed the reason split
    confirmed_at: datetime
    reasons: list[DenialReason]
```

**Peer-to-peer summary** is a different shape: bulleted evidence list (each bullet a fact + quote), the criteria met with citations, the likely reviewer objections (derived from denial categories when present) and the facts that answer them, plus a "not documented" list so the physician does not walk into a question unprepared. It is never exported as a patient-facing letter and carries a header saying it is an internal preparation aid.

### 8.6 Export [DECIDED — see §11 Q3]

- `ast → DOCX` with python-docx: blocks map to Word styles (heading, paragraph, bullet list, table, signature); the letterhead comes from a practice template (`practice.settings.letterhead` incl. logo bytes in the blob store); page size/margins from the template; the criteria citation and the (placeholder) verification banner render as a footer appendix block.
- `ast → PDF` with WeasyPrint from an HTML render of the same AST plus a print CSS that mirrors the DOCX styles. Rationale: one renderer to maintain for PDF, no headless-browser dependency in the worker image, and the HTML render doubles as the editor's read view.
- Fidelity guarantee: one canonical render function per format, one shared style map, and a Playwright/pytest check that a letter with every block type exports in both formats with all block text present (text-extraction equality test: PDF text via `pdftotext`, DOCX text via python-docx) — a cheap automated guard against "the export dropped a paragraph".
- Filenames: `CAR-2026-0042-LMN-v3.pdf`. Every export writes a `letter.exported` audit entry with `format`, `version_no`, `ast_sha256`, `verification_run_id`.
- Exports are **never** sent anywhere by the system (INV-4). The UI says so: "Downloaded to your computer. CardioAuth does not submit to payers."

---

## 9. Milestone plan (owner's M1–M7) with acceptance criteria

Conventions: each milestone ends with a demo on synthetic data, `docker compose up` from a clean clone, `pytest` green, and (from M3) a fresh evaluation report committed under `reports/`. "Done" always means: merged to `main`, runnable by a teammate who did not write it, and the milestone's acceptance criteria demonstrated live.

### 9.1 The evaluation harness: inputs, outputs and where ground truth lives [DECIDED]

A required, first-class artefact — not a notebook. Runs at the end of every milestone that touches the AI pipeline (M3 onwards) and in CI.

**Invocation**

```bash
make eval                                   # mock provider, full dataset, gates enforced
python -m eval.run --manifest data/synthetic/manifest.json \
    --out reports/eval-$(date -u +%Y%m%dT%H%M%SZ).md \
    --provider configured --only CAR-SYN-003,CAR-SYN-011 --no-gates
```

**Inputs** (all versioned in the repo except the model itself):

| Input | Location | Notes |
|---|---|---|
| Case manifest | `data/synthetic/manifest.json` | case ids, procedure, payer, expected overall class, which denial letter (if any) belongs to the case, dataset hash |
| Synthetic documents | `data/synthetic/cases/<case_id>/docs/*.pdf\|*.png\|*.txt` | generated at M3; text-layer PDFs, scans, and pasted text all represented |
| Ground truth per case | `data/synthetic/cases/<case_id>/ground_truth.json` | `expected_facts` (field_key → value/date/polarity/acceptable source docs), `expected_verdicts` (criterion_code → met/not_met/insufficient), `injected_gaps` (exactly what the generator deliberately omitted or contradicted), `expected_denial_categories`, `acceptable_letter_facts` |
| Denial letters | `data/synthetic/denials/*.pdf\|*.txt` + `ground_truth.json` per denial | represented as both a text-layer PDF and a scan, to exercise both ingest paths |
| Criteria version under test | `data/criteria/seed/*.yaml` (or a practice export) | the harness records `criteria_set_version_id` + `fingerprint` in the report, because accuracy is meaningless without naming the ruleset |
| Pipeline configuration | env + prompt versions (`extract-v1`, `evaluate-v1`, `lmn-v1`, `appeal-v1`, `verify-v1`) | recorded verbatim in the report header |
| Gate thresholds | `eval/thresholds.yaml` | the numbers from §11 Q11, editable without code changes |
| Provider | `mock` (deterministic fixtures, CI default) or a configured real provider | the report states which; mock runs prove wiring, real runs prove quality |

**Ground truth is generated by construction, not annotated by hand.** `scripts/generate_synthetic.py` composes each case from a Synthea-derived patient core plus LLM-written notes/reports, and *records* what it deliberately left out, distorted or contradicted (e.g. "no EF value anywhere", "two reports disagree on EF", "stress test date is 14 months before date of service"). The injected gaps are the labels. Consequence: gap-detection recall is measurable exactly (`caught injected gaps / injected gaps`), and there is no annotation drift between document edits and labels because both come from one generator run whose `dataset_hash` is recorded in the report. A human spot-check at M3 confirms the generator's labels match a reading of the documents — a cheap check, and the only hand work involved.

**Pipeline executed per case** (identical code paths to production, no harness-only shortcuts): ingest → OCR (per configured backend, with the scan cases forced through OCR) → extraction with span validation → criteria resolution → evaluation → gap derivation → letter generation (LMN; and appeal where a denial exists) → claim verification → export rendering (asserted for fidelity, not written to a file per case).

**Outputs**

1. `reports/eval-<timestamp>.md` — the human-readable report, committed at each AI milestone. Sections: run metadata (git sha, provider, model per task, prompt versions, criteria version + fingerprint, dataset hash, wall-clock, tokens, estimated cost per case); aggregate metrics with target, actual and PASS/FAIL; per-case table (procedure, expected class, predicted class, extraction P/R, three-way confusion cell, gaps caught/injected, sentences, flagged sentences); **the residual section** listing every *unflagged* unsupported claim against ground truth (must be empty) and every *flagged* claim with its sentence and reason code, for human review; per-field extraction error breakdown (which `field_key`s fail most, on which document kinds); latency and cost percentiles.
2. `reports/eval-<timestamp>.json` — the same data machine-readable, so CI can diff runs and a dashboard can plot trends.
3. Exit code — non-zero when any gate fails, so a regression cannot be merged quietly.

**Metric definitions** (fixed formulas, so numbers are comparable across milestones):

- **Extraction recall** = `matched_expected_facts / expected_facts` per `field_key`, with a match requiring the right value (canonical comparison: exact for dates/codes, ±1 for percentages and small integers, normalised for units) and a span inside one of the acceptable source documents. **Invented facts** = extracted facts with no counterpart in `expected_facts`, reported separately and gated at 0 for facts carrying dates, numbers or codes.
- **Criteria classification accuracy** = cases where all criterion verdicts match ground truth / cases; plus a **three-way confusion matrix** and the asymmetric gate "no `met` where ground truth is `not_met`".
- **Gap-detection recall** = `injected_gaps_surfaced / injected_gaps`, where surfaced means a `gap_item` (any status) whose field/criterion matches the injected gap.
- **Hallucination rate** = sentences with `verdict ∈ {unsupported, unverified}` that remain in the **final exported version** of a letter / total sentences in that version. Target: **0 unflagged**. Reported alongside the *unflagged semantic-mismatch count* (sentences the verifier passed that human ground truth says are wrong) — the honest residual, reviewed by a human at each milestone.
- **Cost/latency per case** recorded for the extraction, evaluation, generation and verification stages separately, because the owner's model choice (Q10) depends on it.

**Anti-gaming rules.** The harness never reads `ground_truth.json` other than in the scoring module (asserted by an import check in CI), never patches the pipeline, and never compares to a cached expected output. If a scoring function needs a new field, the ground-truth schema is extended — never the pipeline's output schema to make scoring easier.

**M1 — Plan, data model, scaffolding, auth, audit.** *Buildable/testable at the end: a coordinator can log in with 2FA and see an empty practice dashboard; the audit log records it.*
- Deliverables: repo layout per §1.1; Alembic baseline for §2; Docker Compose (db, minio, api, worker, web, proxy); settings/env loading with the production startup guards (§4.2); Argon2id + TOTP + server-side sessions + RBAC dependency; audit service with hash chain; `/api/health`; `scripts/audit_chain_verify.py`; structured logging with PHI filter; `docs/` skeleton; this DESIGN.md committed into the repo.
- Acceptance: (1) `docker compose up` from a clean clone serves the login page on one origin; (2) login without TOTP is refused for a physician account; (3) a coordinator cannot call `POST /api/criteria/sets` (403 + audited `denied`); (4) `audit_chain_verify.py` passes, and tampering with a row in psql makes it fail loudly (demonstrated); (5) `pytest` green including `test_no_phi_in_logs.py`; (6) startup with `CARDIOAUTH_ENV=production CARDIOAUTH_PHI_LOGGING=dev` exits non-zero.

**M2 — Upload, OCR, storage, case creation, tracker.** *Buildable/testable: create a case, upload a synthetic PDF and a synthetic scan, see the pages and extracted text with page numbers, move it Draft → Cancelled and back.*
- Deliverables: `BlobStore` (local + S3), document ingest with dedupe by sha256, page rendering, `OcrBackend` (text-layer + Tesseract), `page_text_version` creation with normalisation, `document_page` UI with page image and text side by side, case CRUD, procedure/payer reference data + seed, status machine + history, tracker board UI, document limits and audited rejections, `paste` flow.
- Acceptance: (1) a scanned synthetic report yields page text with per-page page numbers stable across re-render; (2) a text-layer PDF bypasses OCR and its text matches the embedded text exactly; (3) re-OCR creates a new `page_text_version`, leaves the old row intact, and shows version history; (4) a document over the limit is rejected with a named limit and audited; (5) tracker transitions enforce §6.2 including the 409 preconditions (demonstrated by attempting an illegal transition); (6) Playwright: create case → upload → see pages → transition to cancelled.

**M3 — Synthetic data + ground truth + harness skeleton.** *Buildable/testable: `make eval` produces a Markdown report over 20 cases + 5 denial letters, with pipeline stages stubbed, proving the harness wiring end to end.*
- Deliverables: `scripts/generate_synthetic.py` (Synthea patient core + LLM-written clinic notes/reports with *programmatic* gap injection, so ground truth is generated by construction, not by annotation); 20 cases labelled meets / does-not-meet / missing-documentation; 5 denial letters; `data/synthetic/` layout with `manifest.json`; ground-truth JSON per case (`expected_facts`, `expected_verdicts`, `expected_gaps`, `expected_denial_categories`); harness runner with per-case timings, cost/token totals and a Markdown renderer; `MockLLMProvider` fixtures generated from ground truth so M4/M6 can be tested deterministically before a real provider is chosen; `EVAL.md` describing the metrics.
- Acceptance: (1) 20 cases + 5 denial letters exist, all clearly labelled synthetic, all with ground truth, no real patient data anywhere (a checker greps for identifiers and for the label); (2) `make eval` writes `reports/eval-<timestamp>.md` with all four metric sections populated by stubs and every case listed individually; (3) a deliberately broken pipeline stage makes the harness fail loudly (demonstrated); (4) harness runs in CI in under 5 minutes with the mock provider.

**M4 — Extraction with spans + evaluation.** *Buildable/testable: upload documents, get facts with clickable quotes on the page image, see rejected unsourced items as gaps, and see extraction accuracy measured.*
- Deliverables: extraction service + prompt `extract-v1`; span resolution (§3.1 step 4) incl. fuzzy recovery; facts/spans UI with "view in document"; rejected-fact reporting; `check_span_integrity.py` in CI; `extraction_run` telemetry; harness metric: extraction precision/recall per field key against ground truth (with "invented fact" counted separately, i.e. facts with no counterpart in ground truth — the number that must be zero-ish).
- Acceptance: (1) every displayed fact links to a page image with the quote highlighted; (2) attempting to insert a `fact_span` with wrong offsets via raw SQL fails (demonstrated in a test); (3) a fact the model reports without a locatable quote appears as a gap, never as a fact; (4) harness reports per-field extraction precision/recall and an explicit `invented_fact_count`; (5) re-OCR staleness behaviour demonstrated (§5.3).

**M5 — Criteria library admin UI + evaluation + gap report.** *Buildable/testable: an admin authors a criteria set, publishes a version, and a coordinator sees Met / Not met / Insufficient with quotes and a gap report.*
- Deliverables: criteria admin CRUD with `logic` validation on write, draft/publish/retire, version diff view, fingerprint, effective-date exclusion constraint, placeholder banner; seed pack loader with `is_placeholder=true`; deterministic `logic` interpreter; evaluate service + prompt `evaluate-v1`; verdict UI with supporting quotes; gap report with acknowledge/waive/resolve; case criteria re-pin flow invalidating evaluations; harness metrics: criteria classification accuracy per case and gap-detection recall.
- Acceptance: (1) publishing a version makes it immutable (a test attempts an edit and fails); (2) editing a published set creates a new draft version, and a case keeps its pinned version; (3) a valid criterion `logic` with an unknown field is rejected at save time; (4) verdicts show quotes for every `met`, and `insufficient_documentation` — not `not_met` — whenever the required field is simply absent (demonstrated on a missing-documentation synthetic case); (5) gap-detection recall ≥ target on the harness (§11 Q11 for the numeric target); (6) the placeholder label is visible on the checklist, the gap report and the letter preview.

**M6 — Letter generation + verification + editor + export.** *Buildable/testable: generate an LMN, see flags inline, fix them, export PDF and DOCX; generate a point-by-point appeal from a pasted denial.*
- Deliverables: `letter_service` (lmn/appeal/p2p), evidence bundle builder, post-generation validation, `verification_service` stages 0–5, Tiptap editor with provenance attributes and flag rendering, version history and diff, "attach source" flow, audit entries for edits with flag counts, `ast → docx` and `ast → pdf` exporters, export gating, harness metrics: hallucination rate (unflagged unsupported / total sentences) and unsupported-claim rate on final exported versions, plus a per-case list of any unsupported sentence for human review.
- Acceptance: (1) a generated letter that contains an ungrounded clinical sentence is flagged with the reason and cannot be exported until resolved (demonstrated by injecting a fixture response); (2) a human edit that adds a new unsupported claim is flagged identically (demonstrated twice: typed text and a pasted sentence with a number); (3) verifier-unavailable injection results in `unverified` + blocked export, not a pass; (4) every appeal reason from a pasted denial receives a response block, and an unanswerable one produces a blocking gap stub; (5) export produces both formats with all block text present (automated fidelity test); (6) an export attempt during a flagged state returns 409 with the blocking sentence indices; (7) each exported letter carries the criteria version, fingerprint and the placeholder label; (8) harness hallucination rate on final versions = 0 unflagged (target from the plan) and the report names the residual risk measure.

**M7 — Physician sign-off, Playwright end-to-end, README, COMPLIANCE.md.** *Buildable/testable: the full loop on a synthetic case in under 10 minutes, with the physician signing and the tracker closing out.*
- Deliverables: physician review view (diff since last review, flag list, page-image citations), step-up auth, typed attestation sign-off with hash and `verification_run_id`, sign-off revocation, `ReadyForReview → Submitted → Approved/Denied → Appealed` flows with `submission_ref` capture, due-date/turnaround dashboard, Playwright suite for the key flows (login+2FA, case creation, upload+OCR, evaluation, edit a flagged letter, export, sign-off, status transitions), README (clean-clone quickstart, synthetic-data policy, env var table, architecture diagram), COMPLIANCE.md, `EVAL.md` final, backup/restore notes for Postgres and blob store.
- Acceptance: (1) Playwright suite green from `docker compose up` in CI; (2) a timed run of the coordinator's loop on a synthetic case completes in under 10 minutes by a person not on the team (demonstrated live); (3) a physician cannot sign a letter that has a blocking flag, and cannot sign without step-up re-auth (both demonstrated); (4) an illegal status transition returns 409 naming the unmet precondition; (5) README quickstart works on a machine that has never run the project; (6) `COMPLIANCE.md` lists, as a checklist with a status per item: encryption in transit/at rest, RBAC, session policy, audit log coverage + tamper evidence, storage abstraction and its production counterpart, LLM provider/BAA status, OCR provider/BAA status, database BAA status, backups and retention, breach-notification readiness, minimum-necessary review, BAA paperwork pending, staff training, risk analysis (Security Rule §164.308(a)(1)) **not done**, penetration test **not done**, SOC 2 **not done**, and the explicit statement that the current build must not hold real PHI.

**Order and rationale.** M3's harness skeleton lands *before* extraction deliberately: the harness defines the labels the AI work will be judged against, so M4/M5/M6 are measured from the first line of their code. The criteria library lands before letter generation so that the letter can cite a version that already exists. Sign-off last, because it gates output that must already be verifiable.

---

## 10. Risks and mitigations

| # | Risk | Likelihood × impact | Mitigation in this design | Residual |
|---|---|---|---|---|
| R1 | **Extraction quality on messy scans.** Faxed, skewed, hand-annotated reports; low OCR confidence; tables losing structure | High × High | Text-layer-first; per-page confidence with an explicit 0.60 floor below which no extraction happens; span-bound facts so wrong OCR is visible at the source; "type the relevant text" paste escape hatch; fuzzy span recovery reported, not hidden; per-field accuracy measured every milestone | Real-world scans will still lose items — which is why the missing-documentation verdict exists and the letter never asserts an absent fact. Accepted, measured, surfaced. |
| R2 | **Criteria-version churn.** Payer criteria change; a case evaluated last month may not match today's policy; license text must not be paraphrased | High × High | Effective-dated, immutable published versions; case pins the version at creation; re-pin is explicit and audited and invalidates evaluations; letters carry version + fingerprint + source citation; criteria quote check (stage 1) requires near-verbatim text | A payer changing policy mid-case is handled by the coordinator re-pinning, not silently. Licensing the text is an owner dependency (§11 Q1/Q10). |
| R3 | **False confidence in generated letters.** A fluid letter reads as authoritative; staff may skim; models are fluent liars about specifics | Medium × Critical | Every clinical sentence bound to a real span (schema-enforced); numeric/date/code/negation checks; entailment stage with uncertainty → blocked; no override path; visible provenance; the UI never says "verified correct"; exports record the verification run; harness measures unflagged unsupported against human labels | The "plausible but semantically off" residual (§8.3) — targeted by stage 4 and caught by the human click-through. This is the single most important thing for the owner to watch in the M6 demo. |
| R4 | **Compliance gap to real PHI.** The MVP is not a covered-entity-compliant system; no BAA, no risk analysis, no pen test, no BAAs for providers | Certain × Critical (if used with real PHI) | Dev/test are synthetic-only; production startup guards; COMPLIANCE.md with an explicit "must not hold real PHI" statement; storage/DB/LLM/OCR seams ready for BAA-covered counterparts; PHI-out-of-logs by construction; data minimisation (no patient name in indexed columns) | Not closable by engineering alone. Owner must choose hosting, sign BAAs, and commission a risk analysis/pen test. **Do not take real patient data into this build.** |
| R5 | **Hallucinated facts in extraction** (model reports an EF that no document contains) | Medium × High | Span requirement means an unsourced fact cannot be stored; fuzzy recovery is flagged; `invented_fact_count` is a harness metric; "view in document" makes verification a one-click act | Model may pick a *plausible neighbouring* span (wrong value, real quote) — mitigated by numeric checks and human review of flagged low-confidence facts. |
| R6 | **LLM provider/cost/vendor lock-in.** The owner has not chosen a provider; unavailability breaks the pipeline | Medium × Medium | Provider-agnostic protocol; mock/recording providers for dev; per-task model override; token accounting per run; harness reports cost per case; no vendor-specific feature in the pipeline | Cost per case is unknown until a real provider is wired in — hence Q10's proposed default (a mid-tier model for extraction, a strong one for verification) and measurement before scaling. |
| R7 | **OCR/extraction latency making the "under 10 minutes" goal fail** | Medium × Medium | Async jobs with progress UI; extraction runs per document set in one call; verification batched; documented page limits; harness records per-case wall-clock | Long denial letters and 100-page records will be slow; the limit policy (§11 Q8) is the lever. |
| R8 | **Scope creep into payer submission / EHR integration** | Medium × Medium | Explicitly out of scope; FHIR import is a stub interface only; the system has no outbound payer integration by design (INV-4) | Requests will come. The design makes them additions, not rework: a submission module would be a new adapter, and it would need its own compliance review. |
| R9 | **Audit log or session compromise** | Low × High | Append-only grants + hash chain + separate schema owner; hashed session tokens; step-up auth; audited denials; no PHI in audit detail | Application-level compromise can still read PHI within the app's role — hence least privilege + the production re-architecture of secrets/network (§1.3). |
| R10 | **Placeholder criteria mistaken for policy** | Medium × High | `is_placeholder` on every version; mandatory banner in UI, gap report and *exported letters*; seed loader refuses to load into production; ADMIN UI cannot clear the flag without recording a clinical reviewer identity and a citation | Requires the owner to actually supply reviewed criteria (§11 Q1). Until then the tool's own output says it is unverified. |
| R11 | **Missing-documentation cases scored as "does not meet"** — clinically misleading | Medium × Medium | Verdict enum separates `insufficient_documentation`; the interpreter returns it whenever a required field is absent; the harness reports the three-way confusion matrix so systematic bias is visible | A tail of ambiguous cases will remain; measured and reviewed at M5. |

---

## 11. Open questions — each with a proposed default

Approve the defaults or change them; each default is buildable as written.

**Q1. Criteria source and clinical reviewer.** *Default:* ship the PLACEHOLDER seed pack as data (clearly banner-labelled, `is_placeholder=true`), build the admin UI so the owner's own criteria document can be entered or imported (YAML/CSV import in M5), and record `clinical_reviewer` (name + NPI + date) on a version when `is_placeholder` is set to false. **No criterion text is authored by the model.** Ties to the plan's own open item (criteria source + named reviewer).
**Q2. Extracted-text storage and re-OCR.** *Default:* append-only `page_text_version` per page; facts pin the version they were read from; re-OCR never mutates existing text; old-version spans become `stale`; re-anchor by exact quote → fuzzy ≥0.95 → quarantine as a gap; signed letters whose evidence becomes stale are flagged `evidence_invalidated` for human re-review (never silently altered). *Alternative if the owner prefers simplicity:* re-OCR overwrites the page text and forces re-extraction of the whole case (simpler, loses the audit link between a signed letter and the text it cited). Default chosen: versioned.
**Q3. Letter representation and export mechanism.** *Default:* structured AST (JSON blocks) as the source of truth; HTML/Markdown as renders/interchange; **DOCX via python-docx, PDF via WeasyPrint from the same AST**; one shared style map; automated block-text fidelity test for both formats. *Rejected alternatives:* storing HTML (whitespace ambiguity, provenance loss), storing Markdown (loses `claim_type`/`fact_ids`), browser-print PDF (heavy worker dependency, header/footer fidelity).
**Q4. Session timeout and re-auth.** *Default:* 15 min idle, 8 h absolute, server-authoritative, 60-second warning modal with autosaved drafts; step-up (password + TOTP) required for sign-off, export, criteria edits, user changes, audit-log viewing, gap waivers, and valid for 5 minutes. TOTP enforced at first login for physician/admin, and for coordinators enforced at first login too (with an admin-visible "not yet enrolled" flag rather than a block). Password reset is admin-initiated (no email dependency in the MVP).
**Q5. Physician e-signature form.** *Default:* **typed attestation** — the physician re-authenticates (step-up), sees the exact attestation text, clicks "Sign", and the system stores signer id, NPI, attestation text verbatim, timestamp, the verification run seen, and a `signature_hash` over `(user_id, letter_version.ast_sha256, attestation_text, signed_at)`. The exported letter prints a signature block with name, credentials, NPI, date and the hash-prefix, plus "electronically signed via CardioAuth". *Rejected for MVP:* uploaded signature images (weak provenance, easy to reuse, no better legal standing than a typed attestation for internal use) and third-party e-signature services (extra BAA, extra cost, out of scope). If the owner requires a legally-binding external signature (DocuSign-class), that becomes an M8 feature with its own BAA.
**Q6. Capturing "submitted" for real.** *Default:* the coordinator records it explicitly with a `submission_ref` (portal name + confirmation number + timestamp; or fax/mail with date and tracking). The UI allows back-dating `submitted_at` up to 30 days and audits the difference. The system has no outbound payer connection and never infers submission. Tracker buckets and turnaround metrics derive from this record. *Consequence to accept:* turnaround metrics are as accurate as the coordinator's data entry.
**Q7. Audit-log tamper protection.** *Default:* append-only DB grants, hash chain per entry, separate schema owner the app cannot assume, nightly chain verification, and a **weekly export of the tail hash to a second location** (owner-provided object store or a signed file committed to an off-site backup) so that total database compromise still leaves external evidence. *Simpler alternative:* skip the external anchor and rely on grants + chain (protects against application-level tampering but not against someone with DB superuser rights deleting the tail). Default chosen: external anchor, cheap and meaningful. Append-only DB user + no root access on the DB host is a deployment requirement to list in COMPLIANCE.md.
**Q8. Document volume limits per case.** *Default:* 25 documents, 2 000 pages, 2 GB per case; 100 MB / 500 pages per document; above 0.60 OCR confidence to extract; 0.60–0.80 accepted with an advisory warning. Rationale: extraction cost and latency scale with pages, and the MVP's premise is a curated packet, not a chart dump. Limits are configuration (env), audited when hit, and can be raised per practice without code changes. **Approve or state the number the practice actually needs.**
**Q9. Criteria library scope: global or per-practice.** *Default:* **global library with per-practice overlay.** Criteria sets are global (platform-maintained, seeds are global); a practice may create `scope='practice'` override sets, which win in resolution (§2.6). Rationale: most criteria are payer-wide, but independent practices negotiate/handle different plans and one practice's reviewer may want to tighten a rule; per-practice-only would duplicate every set, global-only would block a legitimate local policy. *Also decide:* whether practices can see other practices' criteria (default: no — global sets are read-only, practice sets are private to the practice).
**Q10. Cost/model choice for extraction, evaluation and verification.** *Default:* per-task model configuration — a mid-tier structured-output model for extraction and criteria evaluation (bulk of tokens), a stronger model for the letter generator, and a strong, low-temperature model for the verification stage (accuracy matters most there; it must be BAA-capable in production). Env vars per task (`CARDIOAUTH_LLM_TASK_MODEL_*`) with the ability to point all three at one provider. **Production requires a provider that signs a BAA** — the concrete recommendation is AWS Bedrock or Azure OpenAI within a BAA-covered account; the design deliberately keeps this a configuration choice. Measure cost per case in the M6 harness report before committing to a price. The owner must also confirm whether prompts/outputs may leave the practice's network at all; if not, the same interface supports a self-hosted model on a GPU instance (higher infra cost, no BAA needed because no third party receives PHI).
**Q11. Evaluation targets (numbers to approve).** *Default targets at M6:* extraction — per-field recall ≥ 0.90 and precision ≥ 0.95 on synthetic cases with `invented_fact_count = 0` for facts with dates/numbers/codes; criteria classification accuracy ≥ 0.90 per case with **no `met` predicted where ground truth is `not_met`** (asymmetric: a false "met" is worse than a false "not met" because it invites a denial); gap-detection recall ≥ 0.90 (must catch every deliberately missing item in the missing-documentation cases); hallucination rate on exported versions = **0 unflagged unsupported claims** (hard gate), with the residual semantic-mismatch rate reported separately and reviewed by a human. *Rationale for asymmetry:* the tool's job is to help staff chase documentation and avoid denials, so precision on "met" matters more than recall.
**Q12. Who may edit criteria, and is there a second pair of eyes?** *Default:* admin edits drafts; publishing requires a second confirmation step (admin re-authentication + typing the set name) and records `published_by`; a version whose `is_placeholder=false` additionally requires `clinical_reviewer` name/NPI/date to be filled in. No four-eyes requirement in the MVP (single-practice reality), but the audit log makes every publish attributable. *If the owner wants more:* publish could require two distinct admin accounts.
**Q13. Retention and deletion.** *Default:* case documents and derived data are retained 7 years (typical payer/audit horizon) with soft-delete only; an admin "redact case" action removes document blobs and full audit detail while keeping audit skeleton entries (who/when/action) so history stays verifiable. Retention period is configurable. *Needs owner confirmation because it interacts with practice policy and any state record-retention requirement.*
**Q14. Email/notifications.** *Default:* none in the MVP (no email provider, no PHI leaving the system). The tracker's due-date view is the notification mechanism. If notifications are wanted later, they must be PHI-free ("a case has a due date tomorrow") and sent through a BAA-covered provider.
**Q15. Backup/DR expectations.** *Default:* nightly `pg_dump` + blob-store sync to a second location, restore documented and tested once at M7, RPO 24 h / RTO 8 h for the MVP. State in COMPLIANCE.md that this is not a production SLA until the hosting for the BAA path is chosen.
**Q16. ICD-10 / CPT / medication vocabularies.** *Default:* no external terminology licence in the MVP. Codes are *read from documents* and stored as text with a span, checked for format, and displayed as found; the system does not map codes to concepts or validate them against a licensed code set, and does not look up drug names apart from a small bundled list used for the medication checks in stage 2. *If the owner wants validated coding, that is a licensed vocabulary purchase* and a later milestone.
**Q17. Multi-practice or single practice at launch.** *Default:* the schema is multi-practice from day one (`practice_id` everywhere, RBAC scoped) but the MVP is operated as one practice; a `platform_admin` role exists for support and criteria seeding. No cross-practice reporting. This avoids a painful migration later at the cost of one column now.

---

## 12. Deviations and additions to the owner-specified stack

*No functional deviation.* Everything the owner specified is used as specified: Python 3.12, FastAPI, SQLAlchemy, PostgreSQL, Alembic, OCR behind a pluggable interface (Tesseract as the default implementation), React + TypeScript with Next.js and Tailwind, email/password + TOTP 2FA, Docker Compose for local development, pytest and Playwright. Two clarifications and four additive choices:

1. **Clarification — the public site vs the application.** The team's placeholder marketing site is a TanStack Start app on port 3000. That stays the public marketing surface; the CardioAuth application described here is the Next.js + FastAPI stack, served on its own origin in production (and on a private port behind the proxy in dev so that only one public surface exists). No conflict, but the owner should know the marketing site is a separate codebase.
2. **Clarification — OCR default.** Tesseract is the dev/test backend; production should move to a BAA-covered managed OCR service through the same `OcrBackend` interface. Tesseract is kept for local work because it sends nothing off the machine.
3. **Addition — WeasyPrint and python-docx for export** (not in the owner's list, which did not name an export tool). Chosen over headless-Chrome PDF and over a document-generation service: no browser in the worker image, no third party receiving letter content, one AST renderer for both formats.
4. **Addition — MinIO** as the dev S3-compatible store so the production storage code path is exercised locally instead of being a code path that only exists in production.
5. **Addition — a Postgres-backed job queue** instead of adding Redis/RabbitMQ in the MVP. Fewer moving parts; the `worker` container preserves the async model so swapping in a broker later is contained in `workers/`.
6. **Addition — Tiptap** (ProseMirror) for the rich-text editor because it supports node-level attributes, which is what carries `block_id`/`claim_type`/`fact_ids` through human editing. A plain contenteditable or a Markdown editor cannot hold provenance and would make §8.4 unimplementable.

**Stack risks acknowledged:** pinning Next.js and Tailwind to known-good versions in the repo (no `latest`), and keeping the Pydantic JSON Schemas as the only definition of model I/O so a provider swap cannot silently change the contract.

---

## 13. What must be true before this design is built

1. The owner approves this document (or returns it with changes) — no code before approval.
2. M1 is unambiguous and can start the day approval lands: repo layout, schema-as-written, Compose stack, auth/audit, and the six M1 acceptance tests.
3. The owner's answers that unblock later milestones: **Q1** (criteria source + reviewer) before M5 can be meaningful, **Q10** (provider/BAA + whether PHI may leave the network) before M4 can use a real model, **Q11** (evaluation targets) before M6's gate means anything, **Q4/Q5** (session and signature policy) before M7, **Q13/Q15** (retention/backup) before any production hosting.

*End of design document. All examples, criteria and notes in this document are synthetic or placeholder; no real patient information appears anywhere in it.*
