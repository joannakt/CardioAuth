-- CardioAuth — authoritative schema DDL (DESIGN.md §2).
-- Applied by Alembic revision 0001. Every statement here is idempotent at the
-- object level because the migration runs exactly once against an empty schema.
--
-- Invariants enforced in this file (see DESIGN.md §2.11):
--   INV-1  fact_span must literally match the stored immutable page text (trigger)
--   INV-1  a fact with no span is unrepresentable (deferred constraint trigger)
--   INV-1  page_text_version is append-only (UPDATE/DELETE rejected)
--   INV-2  published criteria versions and their criteria are immutable (triggers)
--   INV-3  letter_version is insert-only; verification rows are insert-only
--   INV-4  signoff needs a verification_run, a fresh re-auth and is revoke-once
--   audit  cardioauth_audit.audit_log is append-only and hash-chained
-- There is no medical-necessity content in this file. Criteria arrive as data.

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS btree_gist;   -- needed by the criteria exclusion constraint

CREATE SCHEMA IF NOT EXISTS cardioauth;
CREATE SCHEMA IF NOT EXISTS cardioauth_audit;

-- ---------------------------------------------------------------------------
-- 0. Invariant helpers. Every rejection raises P0001 with a stable token so
--    tests and operators can identify exactly which rule refused the write.
-- ---------------------------------------------------------------------------
CREATE FUNCTION cardioauth.invariant_violation(p_token text, p_detail text DEFAULT '')
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'cardioauth:% %', p_token, p_detail
        USING ERRCODE = 'P0001',
              HINT = 'CardioAuth invariant ' || p_token || ' refused this operation';
END $$;

-- Generic append-only guard. Token is passed as a trigger argument.
CREATE FUNCTION cardioauth.reject_write() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM cardioauth.invariant_violation(
        coalesce(TG_ARGV[0], 'append_only'),
        format('table=%s op=%s id=%s', TG_TABLE_NAME, TG_OP, coalesce(OLD.id::text, '?')));
    RETURN NULL;
END $$;

-- ---------------------------------------------------------------------------
-- 2.1 Tenancy and identity
-- ---------------------------------------------------------------------------
CREATE TABLE cardioauth.practice (
    id          uuid PRIMARY KEY,
    name        text NOT NULL,
    npi         text,
    timezone    text NOT NULL DEFAULT 'America/New_York',
    settings    jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_practice_npi CHECK (npi IS NULL OR npi ~ '^[0-9]{10}$')
);

CREATE TABLE cardioauth.app_user (
    id                 uuid PRIMARY KEY,
    practice_id        uuid REFERENCES cardioauth.practice(id),
    email              citext NOT NULL,
    password_hash      text NOT NULL,
    full_name          text NOT NULL,
    role               text NOT NULL CHECK (role IN ('coordinator','physician','admin','platform_admin')),
    npi                text,
    totp_secret_enc    bytea,
    totp_enrolled_at   timestamptz,
    is_active          boolean NOT NULL DEFAULT true,
    failed_login_count integer NOT NULL DEFAULT 0,
    locked_until       timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_app_user_practice_email UNIQUE (practice_id, email),
    -- platform_admin is the only role allowed to live outside a practice
    CONSTRAINT ck_app_user_practice_scope CHECK (role = 'platform_admin' OR practice_id IS NOT NULL)
);
CREATE UNIQUE INDEX uq_app_user_platform_email ON cardioauth.app_user (email)
    WHERE practice_id IS NULL;

CREATE TABLE cardioauth.user_session (
    id                  uuid PRIMARY KEY,
    user_id             uuid NOT NULL REFERENCES cardioauth.app_user(id) ON DELETE CASCADE,
    token_hash          bytea NOT NULL UNIQUE,
    issued_at           timestamptz NOT NULL,
    last_seen_at        timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    idle_expires_at     timestamptz NOT NULL,
    ip_hash             bytea,
    user_agent_hash     bytea,
    revoked_at          timestamptz,
    reauth_at           timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_session_absolute_after_issue CHECK (absolute_expires_at > issued_at),
    CONSTRAINT ck_session_idle_before_absolute CHECK (idle_expires_at <= absolute_expires_at)
);
CREATE INDEX ix_user_session_user ON cardioauth.user_session (user_id, issued_at DESC);

CREATE TABLE cardioauth.user_invitation (
    id           uuid PRIMARY KEY,
    practice_id  uuid NOT NULL REFERENCES cardioauth.practice(id),
    email        citext NOT NULL,
    role         text NOT NULL CHECK (role IN ('coordinator','physician','admin')),
    token_hash   bytea NOT NULL UNIQUE,
    invited_by   uuid NOT NULL REFERENCES cardioauth.app_user(id),
    expires_at   timestamptz NOT NULL,
    accepted_at  timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- 2.3 Reference data: procedures and payers
-- ---------------------------------------------------------------------------
CREATE TABLE cardioauth.procedure (
    id                           uuid PRIMARY KEY,
    code                         text NOT NULL UNIQUE,
    display_name                 text NOT NULL,
    cpt_codes                    text[] NOT NULL DEFAULT '{}',
    modality                     text NOT NULL,
    default_criterion_categories text[] NOT NULL DEFAULT '{}',
    fact_fields                  jsonb NOT NULL,
    booster_letter_kind          text,
    is_active                    boolean NOT NULL DEFAULT true,
    display_order                integer NOT NULL DEFAULT 100,
    created_at                   timestamptz NOT NULL DEFAULT now(),
    updated_at                   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE cardioauth.payer (
    id              uuid PRIMARY KEY,
    name            text NOT NULL,
    payer_type      text NOT NULL CHECK (payer_type IN ('commercial','medicare_advantage','medicaid','other')),
    state           text,
    plan_hint       text,
    turnaround_days integer NOT NULL DEFAULT 14,
    is_active       boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- uq_payer_identity is created as an expression index below the table, not as a
    -- UNIQUE constraint: PostgreSQL treats NULLs as distinct, so a plain UNIQUE
    -- (name, state, plan_hint) would let duplicate payers in whenever a plan hint is
    -- absent. The index coalesces the nullable columns to a sentinel instead.
    CONSTRAINT ck_payer_turnaround CHECK (turnaround_days > 0)
);

-- ---------------------------------------------------------------------------
-- 2.2 Cases and status
-- ---------------------------------------------------------------------------
CREATE TABLE cardioauth.case_record (
    id                      uuid PRIMARY KEY,
    practice_id             uuid NOT NULL REFERENCES cardioauth.practice(id),
    case_number             text NOT NULL,
    patient_ref             text NOT NULL,
    patient_display         jsonb NOT NULL DEFAULT '{}'::jsonb,
    procedure_code_id       uuid NOT NULL REFERENCES cardioauth.procedure(id),
    payer_id                uuid NOT NULL REFERENCES cardioauth.payer(id),
    cpt_code                text NOT NULL,
    date_of_service         date,
    ordering_provider       text,
    urgency                 text NOT NULL DEFAULT 'routine' CHECK (urgency IN ('routine','urgent','emergent')),
    criteria_set_version_id uuid,   -- FK added after criteria_set_version exists
    status                  text NOT NULL DEFAULT 'draft' CHECK (status IN
                              ('draft','ready_for_review','submitted','approved','denied','appealed',
                               'withdrawn','cancelled','closed')),
    priority_rank           integer NOT NULL DEFAULT 100,
    submitted_at            timestamptz,
    submission_ref          jsonb,
    due_date                date,
    closed_at               timestamptz,
    close_reason            text CHECK (close_reason IS NULL OR close_reason IN ('approved','denied','withdrawn','duplicate')),
    created_by              uuid NOT NULL REFERENCES cardioauth.app_user(id),
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_case_number UNIQUE (practice_id, case_number),
    -- deliberate data minimisation (§2.2): no name, address, phone or full DOB
    CONSTRAINT ck_case_patient_display_keys CHECK (
        patient_display - 'initials' - 'dob_year' = '{}'::jsonb)
);
CREATE INDEX ix_case_tracker ON cardioauth.case_record (practice_id, status, due_date);
CREATE INDEX ix_case_procedure_payer ON cardioauth.case_record (practice_id, procedure_code_id, payer_id);

CREATE TABLE cardioauth.case_status_history (
    id         uuid PRIMARY KEY,
    case_id    uuid NOT NULL REFERENCES cardioauth.case_record(id) ON DELETE CASCADE,
    from_status text,
    to_status  text NOT NULL,
    reason     text,
    changed_by uuid NOT NULL REFERENCES cardioauth.app_user(id),
    changed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_case_status_history_case ON cardioauth.case_status_history (case_id, changed_at DESC);

CREATE TABLE cardioauth.case_party (
    id          uuid PRIMARY KEY,
    case_id     uuid NOT NULL REFERENCES cardioauth.case_record(id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES cardioauth.app_user(id),
    case_role   text NOT NULL CHECK (case_role IN ('coordinator','physician','reviewer','admin')),
    assigned_at timestamptz NOT NULL DEFAULT now(),
    removed_at  timestamptz,
    CONSTRAINT uq_case_party UNIQUE (case_id, user_id, case_role)
);

-- ---------------------------------------------------------------------------
-- 2.4 Documents, pages and page text
-- ---------------------------------------------------------------------------
CREATE TABLE cardioauth.document (
    id                uuid PRIMARY KEY,
    case_id           uuid NOT NULL REFERENCES cardioauth.case_record(id),
    kind              text NOT NULL CHECK (kind IN (
                        'clinic_note','echo_report','stress_report','cath_report','ecg','med_list','labs',
                        'imaging_report','denial_letter','prior_auth_form','insurance_card','other','pasted_text')),
    original_filename text,
    mime_type         text NOT NULL,
    byte_size         bigint NOT NULL CHECK (byte_size >= 0),
    sha256            bytea NOT NULL,
    blob_key          text NOT NULL,
    page_count        integer NOT NULL CHECK (page_count >= 0),
    ingest_status     text NOT NULL CHECK (ingest_status IN ('uploaded','processing','ready','failed','needs_review')),
    ingest_error      text,
    source            text NOT NULL CHECK (source IN ('upload','paste')),
    uploaded_by       uuid NOT NULL REFERENCES cardioauth.app_user(id),
    uploaded_at       timestamptz NOT NULL DEFAULT now(),
    deleted_at        timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_document_case_sha UNIQUE (case_id, sha256)
);
CREATE INDEX ix_document_case_kind ON cardioauth.document (case_id, kind);

CREATE TABLE cardioauth.document_page (
    id                      uuid PRIMARY KEY,
    document_id             uuid NOT NULL REFERENCES cardioauth.document(id) ON DELETE RESTRICT,
    page_number             integer NOT NULL CHECK (page_number >= 1),
    width_px                integer,
    height_px               integer,
    render_dpi              integer,
    image_blob_key          text,
    ocr_method              text NOT NULL,
    ocr_confidence          numeric(5,4) CHECK (ocr_confidence IS NULL OR ocr_confidence BETWEEN 0 AND 1),
    current_text_version_id uuid,   -- deferred FK, added after page_text_version exists
    created_at              timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_document_page_number UNIQUE (document_id, page_number)
);

-- Append-only. Re-OCR creates a NEW row; history is never rewritten.
CREATE TABLE cardioauth.page_text_version (
    id                uuid PRIMARY KEY,
    page_id           uuid NOT NULL REFERENCES cardioauth.document_page(id) ON DELETE RESTRICT,
    version_no        integer NOT NULL CHECK (version_no >= 1),
    text_normalized   text NOT NULL,
    char_count        integer NOT NULL CHECK (char_count = length(text_normalized)),
    ocr_method        text NOT NULL,
    ocr_confidence    numeric(5,4) CHECK (ocr_confidence IS NULL OR ocr_confidence BETWEEN 0 AND 1),
    normalization_notes jsonb NOT NULL DEFAULT '{}'::jsonb,
    produced_by_job   uuid,
    created_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_page_text_version UNIQUE (page_id, version_no)
);
CREATE INDEX ix_page_text_version_page ON cardioauth.page_text_version (page_id, version_no DESC);

CREATE FUNCTION cardioauth.guard_page_current_text_version() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE v_page uuid;
BEGIN
    IF NEW.current_text_version_id IS NOT NULL THEN
        SELECT page_id INTO v_page FROM cardioauth.page_text_version WHERE id = NEW.current_text_version_id;
        IF NOT FOUND THEN
            PERFORM cardioauth.invariant_violation('page_current_text_unknown',
                format('document_page=%s text_version=%s', NEW.id, NEW.current_text_version_id));
        END IF;
        IF v_page IS DISTINCT FROM NEW.id THEN
            PERFORM cardioauth.invariant_violation('page_current_text_foreign_page',
                format('document_page=%s text_version=%s', NEW.id, NEW.current_text_version_id));
        END IF;
    END IF;
    RETURN NEW;
END $$;

-- ---------------------------------------------------------------------------
-- 2.5 Facts and their source spans
-- ---------------------------------------------------------------------------
CREATE TABLE cardioauth.extraction_run (
    id                     uuid PRIMARY KEY,
    case_id                uuid NOT NULL REFERENCES cardioauth.case_record(id),
    procedure_code_id      uuid NOT NULL REFERENCES cardioauth.procedure(id),
    status                 text NOT NULL CHECK (status IN ('queued','running','succeeded','partially_failed','failed')),
    llm_provider           text NOT NULL,
    llm_model              text NOT NULL,
    prompt_version         text NOT NULL,
    input_document_ids     uuid[] NOT NULL DEFAULT '{}',
    page_text_version_ids  uuid[] NOT NULL DEFAULT '{}',
    token_input            integer,
    token_output           integer,
    error                  text,
    started_at             timestamptz,
    finished_at            timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_extraction_run_case ON cardioauth.extraction_run (case_id, created_at DESC);

CREATE TABLE cardioauth.fact (
    id                uuid PRIMARY KEY,
    case_id           uuid NOT NULL REFERENCES cardioauth.case_record(id),
    extraction_run_id uuid NOT NULL REFERENCES cardioauth.extraction_run(id),
    field_key         text NOT NULL,
    value_text        text,
    value_typed       jsonb,
    value_date        date,
    polarity          text NOT NULL DEFAULT 'present' CHECK (polarity IN ('present','absent','negated','unknown')),
    confidence        numeric(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    is_current        boolean NOT NULL DEFAULT true,
    superseded_by     uuid REFERENCES cardioauth.fact(id),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_fact_superseded_not_self CHECK (superseded_by IS DISTINCT FROM id),
    CONSTRAINT ck_fact_has_value CHECK (value_text IS NOT NULL OR value_typed IS NOT NULL OR value_date IS NOT NULL
                                        OR polarity IN ('absent','negated','unknown'))
);
CREATE INDEX ix_fact_current ON cardioauth.fact (case_id, field_key) WHERE is_current;
CREATE INDEX ix_fact_run ON cardioauth.fact (extraction_run_id);

CREATE TABLE cardioauth.fact_span (
    id                   uuid PRIMARY KEY,
    fact_id              uuid NOT NULL REFERENCES cardioauth.fact(id) ON DELETE CASCADE,
    page_text_version_id uuid NOT NULL REFERENCES cardioauth.page_text_version(id),
    page_id              uuid NOT NULL REFERENCES cardioauth.document_page(id),
    document_id          uuid NOT NULL REFERENCES cardioauth.document(id),
    start_offset         integer NOT NULL CHECK (start_offset >= 0),
    end_offset           integer NOT NULL CHECK (end_offset > start_offset),
    quote_text           text NOT NULL,
    span_role            text NOT NULL DEFAULT 'support' CHECK (span_role IN ('support','contradict','context')),
    verified_at          timestamptz NOT NULL DEFAULT now(),
    created_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_fact_span UNIQUE (fact_id, page_text_version_id, start_offset, end_offset)
);
CREATE INDEX ix_fact_span_fact ON cardioauth.fact_span (fact_id);
CREATE INDEX ix_fact_span_text_version ON cardioauth.fact_span (page_text_version_id);

-- ---------------------------------------------------------------------------
-- 2.6 Criteria library (data, never code — INV-2)
-- ---------------------------------------------------------------------------
CREATE TABLE cardioauth.criteria_set (
    id                uuid PRIMARY KEY,
    key               text NOT NULL,
    name              text NOT NULL,
    procedure_code_id uuid REFERENCES cardioauth.procedure(id),
    payer_id          uuid REFERENCES cardioauth.payer(id),
    scope             text NOT NULL DEFAULT 'global' CHECK (scope IN ('global','practice')),
    practice_id       uuid REFERENCES cardioauth.practice(id),
    created_by        uuid NOT NULL REFERENCES cardioauth.app_user(id),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_criteria_set_scope CHECK ((scope = 'practice') = (practice_id IS NOT NULL))
);
CREATE UNIQUE INDEX uq_payer_identity ON cardioauth.payer
    (name, coalesce(state, ''), coalesce(plan_hint, ''));

CREATE UNIQUE INDEX uq_criteria_set_identity ON cardioauth.criteria_set
    (key, scope, coalesce(practice_id, '00000000-0000-0000-0000-000000000000'::uuid));

CREATE TABLE cardioauth.criteria_set_version (
    id                 uuid PRIMARY KEY,
    criteria_set_id    uuid NOT NULL REFERENCES cardioauth.criteria_set(id) ON DELETE RESTRICT,
    version_no         integer NOT NULL CHECK (version_no >= 1),
    status             text NOT NULL CHECK (status IN ('draft','published','retired')),
    is_placeholder     boolean NOT NULL DEFAULT true,
    verification_label text NOT NULL DEFAULT 'UNVERIFIED — requires clinical review before use',
    source_citation    jsonb NOT NULL,
    effective_from     date NOT NULL,
    effective_to       date,
    published_at       timestamptz,
    published_by       uuid REFERENCES cardioauth.app_user(id),
    fingerprint        text NOT NULL,
    notes              text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_criteria_set_version UNIQUE (criteria_set_id, version_no),
    CONSTRAINT ck_criteria_effective_range CHECK (effective_to IS NULL OR effective_to >= effective_from),
    CONSTRAINT ck_criteria_published_fields CHECK (
        status = 'draft' OR (published_at IS NOT NULL AND published_by IS NOT NULL))
);
CREATE INDEX ix_criteria_version_effective ON cardioauth.criteria_set_version (effective_from, effective_to);
CREATE INDEX ix_criteria_version_status ON cardioauth.criteria_set_version (status);

CREATE TABLE cardioauth.criterion (
    id                 uuid PRIMARY KEY,
    version_id         uuid NOT NULL REFERENCES cardioauth.criteria_set_version(id) ON DELETE RESTRICT,
    code               text NOT NULL,
    ordinal            integer NOT NULL,
    category           text NOT NULL CHECK (category IN (
                         'indication','symptom','prior_testing','conservative_therapy','risk_stratification',
                         'contraindication','technical_eligibility','documentation','other')),
    plain_text         text NOT NULL,
    logic              jsonb NOT NULL,
    required_fields    text[] NOT NULL DEFAULT '{}',
    met_rationale_hint text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_criterion_code UNIQUE (version_id, code)
);
CREATE INDEX ix_criterion_version ON cardioauth.criterion (version_id, ordinal);

CREATE TABLE cardioauth.criteria_set_version_selection (
    id                      uuid PRIMARY KEY,
    case_id                 uuid NOT NULL REFERENCES cardioauth.case_record(id) ON DELETE CASCADE,
    criteria_set_version_id uuid NOT NULL REFERENCES cardioauth.criteria_set_version(id),
    resolved_at             timestamptz NOT NULL DEFAULT now(),
    resolver_reason         text NOT NULL CHECK (resolver_reason IN
                              ('payer+specific','payer-general','practice-overlay','fallback-latest')),
    CONSTRAINT uq_criteria_selection UNIQUE (case_id)
);
CREATE INDEX ix_criteria_selection_version ON cardioauth.criteria_set_version_selection (criteria_set_version_id);

-- ---------------------------------------------------------------------------
-- 2.7 Evaluations and gap items
-- ---------------------------------------------------------------------------
CREATE TABLE cardioauth.criteria_evaluation (
    id                      uuid PRIMARY KEY,
    case_id                 uuid NOT NULL REFERENCES cardioauth.case_record(id),
    criteria_set_version_id uuid NOT NULL REFERENCES cardioauth.criteria_set_version(id) ON DELETE RESTRICT,
    extraction_run_id       uuid NOT NULL REFERENCES cardioauth.extraction_run(id),
    status                  text NOT NULL CHECK (status IN ('queued','running','succeeded','failed','superseded')),
    llm_provider            text NOT NULL,
    llm_model               text NOT NULL,
    prompt_version          text NOT NULL,
    summary                 jsonb NOT NULL,
    created_at              timestamptz NOT NULL DEFAULT now(),
    finished_at             timestamptz
);
CREATE INDEX ix_criteria_evaluation_case ON cardioauth.criteria_evaluation (case_id, created_at DESC);

CREATE TABLE cardioauth.criterion_verdict (
    id               uuid PRIMARY KEY,
    evaluation_id    uuid NOT NULL REFERENCES cardioauth.criteria_evaluation(id) ON DELETE CASCADE,
    criterion_id     uuid NOT NULL REFERENCES cardioauth.criterion(id) ON DELETE RESTRICT,
    verdict          text NOT NULL CHECK (verdict IN ('met','not_met','insufficient_documentation','not_applicable')),
    confidence       numeric(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    rationale        text NOT NULL,
    is_deterministic boolean NOT NULL DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_criterion_verdict UNIQUE (evaluation_id, criterion_id)
);

CREATE TABLE cardioauth.criterion_verdict_fact (
    id           uuid PRIMARY KEY,
    verdict_id   uuid NOT NULL REFERENCES cardioauth.criterion_verdict(id) ON DELETE CASCADE,
    fact_id      uuid NOT NULL REFERENCES cardioauth.fact(id),
    fact_span_id uuid NOT NULL REFERENCES cardioauth.fact_span(id),
    role         text NOT NULL CHECK (role IN ('supports','contradicts','missing_for')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_criterion_verdict_fact UNIQUE (verdict_id, fact_span_id, role)
);

CREATE TABLE cardioauth.gap_item (
    id               uuid PRIMARY KEY,
    case_id          uuid NOT NULL REFERENCES cardioauth.case_record(id) ON DELETE CASCADE,
    evaluation_id    uuid REFERENCES cardioauth.criteria_evaluation(id) ON DELETE SET NULL,
    kind             text NOT NULL CHECK (kind IN ('missing_field','unsourced_mention','unreadable_document',
                                                  'expired_prior_test','contradictory_evidence',
                                                  'criteria_missing','low_ocr_confidence')),
    field_key        text,
    criterion_code   text,
    description      text NOT NULL,
    suggested_source text,
    severity         text NOT NULL DEFAULT 'blocking' CHECK (severity IN ('blocking','advisory')),
    status           text NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','resolved','waived')),
    resolved_by      uuid REFERENCES cardioauth.app_user(id),
    resolution_note  text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    -- acknowledging or waiving a gap always records who and why
    CONSTRAINT ck_gap_resolution CHECK (
        status = 'open' OR (resolved_by IS NOT NULL AND resolution_note IS NOT NULL))
);
CREATE INDEX ix_gap_item_case ON cardioauth.gap_item (case_id, status, severity);

-- ---------------------------------------------------------------------------
-- 2.8 Letters, versions, verification, sign-offs
-- ---------------------------------------------------------------------------
CREATE TABLE cardioauth.letter (
    id                 uuid PRIMARY KEY,
    case_id            uuid NOT NULL REFERENCES cardioauth.case_record(id),
    kind               text NOT NULL CHECK (kind IN ('lmn','appeal','p2p_summary')),
    status             text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','in_review','signed','exported','superseded')),
    current_version_no integer NOT NULL DEFAULT 0 CHECK (current_version_no >= 0),
    created_by         uuid NOT NULL REFERENCES cardioauth.app_user(id),
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_letter_kind UNIQUE (case_id, kind)
);

-- Insert-only: an edit creates a new version (§2.8, §8.4)
CREATE TABLE cardioauth.letter_version (
    id                      uuid PRIMARY KEY,
    letter_id               uuid NOT NULL REFERENCES cardioauth.letter(id) ON DELETE RESTRICT,
    version_no              integer NOT NULL CHECK (version_no >= 1),
    source                  text NOT NULL CHECK (source IN ('generated','edited','imported')),
    ast                     jsonb NOT NULL,
    ast_sha256              bytea NOT NULL,
    criteria_set_version_id uuid REFERENCES cardioauth.criteria_set_version(id) ON DELETE RESTRICT,
    extraction_run_id       uuid REFERENCES cardioauth.extraction_run(id),
    denial_input            jsonb,
    created_by              uuid NOT NULL REFERENCES cardioauth.app_user(id),
    created_at              timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_letter_version UNIQUE (letter_id, version_no)
);
CREATE INDEX ix_letter_version_letter ON cardioauth.letter_version (letter_id, version_no DESC);

CREATE TABLE cardioauth.verification_run (
    id                uuid PRIMARY KEY,
    letter_version_id uuid NOT NULL REFERENCES cardioauth.letter_version(id) ON DELETE RESTRICT,
    status            text NOT NULL CHECK (status IN ('queued','running','succeeded','failed')),
    verifier_provider text NOT NULL,
    verifier_model    text NOT NULL,
    method_version    text NOT NULL,
    counts            jsonb NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    finished_at       timestamptz
);
CREATE INDEX ix_verification_run_letter_version ON cardioauth.verification_run (letter_version_id, created_at DESC);

CREATE TABLE cardioauth.claim_verdict (
    id                  uuid PRIMARY KEY,
    verification_run_id uuid NOT NULL REFERENCES cardioauth.verification_run(id) ON DELETE RESTRICT,
    sentence_index      integer NOT NULL CHECK (sentence_index >= 0),
    block_id            text NOT NULL,
    sentence_text       text NOT NULL,
    claim_type          text NOT NULL CHECK (claim_type IN
                          ('clinical_fact','criteria_reference','administrative','attestation','quoted_denial')),
    verdict             text NOT NULL CHECK (verdict IN ('supported','unsupported','unverified','exempt')),
    confidence          numeric(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    reason              text NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_claim_verdict_sentence UNIQUE (verification_run_id, sentence_index)
);

CREATE TABLE cardioauth.claim_verdict_fact (
    id                uuid PRIMARY KEY,
    claim_verdict_id  uuid NOT NULL REFERENCES cardioauth.claim_verdict(id) ON DELETE RESTRICT,
    fact_id           uuid NOT NULL REFERENCES cardioauth.fact(id),
    fact_span_id      uuid NOT NULL REFERENCES cardioauth.fact_span(id),
    match_kind        text NOT NULL CHECK (match_kind IN ('bound','entailed','lexical','numeric')),
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE cardioauth.signoff (
    id                  uuid PRIMARY KEY,
    case_id             uuid NOT NULL REFERENCES cardioauth.case_record(id),
    letter_id           uuid NOT NULL REFERENCES cardioauth.letter(id),
    letter_version_id   uuid NOT NULL REFERENCES cardioauth.letter_version(id) ON DELETE RESTRICT,
    signer_id           uuid NOT NULL REFERENCES cardioauth.app_user(id),
    signer_npi          text,
    method              text NOT NULL CHECK (method IN ('typed_attestation')),
    attestation_text    text NOT NULL,
    signature_hash      bytea NOT NULL,
    signed_at           timestamptz NOT NULL DEFAULT now(),
    reauth_at           timestamptz NOT NULL,
    verification_run_id uuid NOT NULL REFERENCES cardioauth.verification_run(id) ON DELETE RESTRICT,
    revoked_at          timestamptz,
    revoke_reason       text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    -- step-up auth: the signer re-authenticated within 5 minutes of signing
    CONSTRAINT ck_signoff_reauth_fresh CHECK (reauth_at <= signed_at AND reauth_at >= signed_at - interval '5 minutes'),
    CONSTRAINT ck_signoff_revoke_reason CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);
CREATE UNIQUE INDEX uq_signoff_active ON cardioauth.signoff (letter_version_id) WHERE revoked_at IS NULL;
CREATE INDEX ix_signoff_case ON cardioauth.signoff (case_id, signed_at DESC);

-- ---------------------------------------------------------------------------
-- 2.9 Audit log — append-only, hash-chained, separate schema
-- ---------------------------------------------------------------------------
CREATE TABLE cardioauth_audit.audit_log (
    id            bigserial PRIMARY KEY,
    occurred_at   timestamptz NOT NULL DEFAULT now(),
    practice_id   uuid,
    actor_user_id uuid,
    actor_role    text,
    action        text NOT NULL,
    object_type   text NOT NULL,
    object_id     uuid,
    case_id       uuid,
    outcome       text NOT NULL DEFAULT 'success' CHECK (outcome IN ('success','denied','error')),
    detail        jsonb NOT NULL DEFAULT '{}'::jsonb,
    request_id    text,
    session_id    uuid,
    prev_hash     bytea NOT NULL,
    entry_hash    bytea NOT NULL,
    CONSTRAINT ck_audit_hash_width CHECK (length(prev_hash) = 32 AND length(entry_hash) = 32)
);
CREATE INDEX ix_audit_case ON cardioauth_audit.audit_log (case_id, occurred_at DESC);
CREATE INDEX ix_audit_actor ON cardioauth_audit.audit_log (actor_user_id, occurred_at DESC);
CREATE INDEX ix_audit_action ON cardioauth_audit.audit_log (action, occurred_at DESC);

-- ---------------------------------------------------------------------------
-- Deferred / cross-table constraints
-- ---------------------------------------------------------------------------
ALTER TABLE cardioauth.document_page
    ADD CONSTRAINT fk_page_current_text_version
    FOREIGN KEY (current_text_version_id) REFERENCES cardioauth.page_text_version(id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE cardioauth.case_record
    ADD CONSTRAINT fk_case_criteria_version
    FOREIGN KEY (criteria_set_version_id) REFERENCES cardioauth.criteria_set_version(id);

-- One published criteria version effective on any given date, per set (§2.6)
ALTER TABLE cardioauth.criteria_set_version
    ADD CONSTRAINT ex_criteria_version_effective
    EXCLUDE USING gist (
        criteria_set_id WITH =,
        daterange(effective_from, effective_to, '[]') WITH &&
    ) WHERE (status = 'published');

-- ---------------------------------------------------------------------------
-- INV-1: a fact span must literally match the stored immutable page text,
--       and its page/document must agree with the text version it indexes.
-- ---------------------------------------------------------------------------
CREATE FUNCTION cardioauth.validate_fact_span() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    v_text   text;
    v_page   uuid;
    v_doc    uuid;
    v_len    integer;
    v_actual text;
BEGIN
    SELECT t.text_normalized, t.page_id, p.document_id, length(t.text_normalized)
      INTO v_text, v_page, v_doc, v_len
      FROM cardioauth.page_text_version t
      JOIN cardioauth.document_page p ON p.id = t.page_id
     WHERE t.id = NEW.page_text_version_id;

    IF NOT FOUND THEN
        PERFORM cardioauth.invariant_violation('fact_span_unknown_text_version',
            format('page_text_version=%s', NEW.page_text_version_id));
    END IF;

    IF NEW.page_id IS DISTINCT FROM v_page THEN
        PERFORM cardioauth.invariant_violation('fact_span_page_mismatch',
            format('span.page_id=%s text_version.page_id=%s', NEW.page_id, v_page));
    END IF;

    IF NEW.document_id IS DISTINCT FROM v_doc THEN
        PERFORM cardioauth.invariant_violation('fact_span_document_mismatch',
            format('span.document_id=%s page.document_id=%s', NEW.document_id, v_doc));
    END IF;

    IF NEW.end_offset > v_len THEN
        PERFORM cardioauth.invariant_violation('fact_span_out_of_range',
            format('end_offset=%s text_length=%s', NEW.end_offset, v_len));
    END IF;

    -- 0-based half-open offsets over 1-based substring()
    v_actual := substring(v_text FROM NEW.start_offset + 1 FOR (NEW.end_offset - NEW.start_offset));
    IF v_actual IS DISTINCT FROM NEW.quote_text THEN
        PERFORM cardioauth.invariant_violation('fact_span_quote_mismatch',
            format('page_text_version=%s offsets=[%s,%s)', NEW.page_text_version_id, NEW.start_offset, NEW.end_offset));
    END IF;

    NEW.verified_at := now();
    RETURN NEW;
END $$;

CREATE TRIGGER trg_fact_span_validate
    BEFORE INSERT OR UPDATE ON cardioauth.fact_span
    FOR EACH ROW EXECUTE FUNCTION cardioauth.validate_fact_span();

-- INV-1: a fact with no span cannot be committed (checked at COMMIT time so that
-- fact and its spans may be inserted in any order inside one transaction).
CREATE FUNCTION cardioauth.fact_requires_span() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM cardioauth.fact_span s WHERE s.fact_id = NEW.id) THEN
        PERFORM cardioauth.invariant_violation('fact_without_span',
            format('fact=%s field_key=%s', NEW.id, NEW.field_key));
    END IF;
    RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER trg_fact_requires_span
    AFTER INSERT ON cardioauth.fact
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION cardioauth.fact_requires_span();

-- Deleting the last span of a surviving fact is equally unrepresentable.
CREATE FUNCTION cardioauth.fact_span_delete_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM cardioauth.fact f WHERE f.id = OLD.fact_id)
       AND NOT EXISTS (SELECT 1 FROM cardioauth.fact_span s WHERE s.fact_id = OLD.fact_id) THEN
        PERFORM cardioauth.invariant_violation('fact_without_span',
            format('fact=%s lost its last fact_span', OLD.fact_id));
    END IF;
    RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER trg_fact_span_delete_guard
    AFTER DELETE ON cardioauth.fact_span
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION cardioauth.fact_span_delete_guard();

-- ---------------------------------------------------------------------------
-- Append-only tables
-- ---------------------------------------------------------------------------
CREATE TRIGGER trg_page_text_version_append_only
    BEFORE UPDATE OR DELETE ON cardioauth.page_text_version
    FOR EACH ROW EXECUTE FUNCTION cardioauth.reject_write('page_text_version_append_only');

CREATE TRIGGER trg_letter_version_append_only
    BEFORE UPDATE OR DELETE ON cardioauth.letter_version
    FOR EACH ROW EXECUTE FUNCTION cardioauth.reject_write('letter_version_append_only');

CREATE TRIGGER trg_case_status_history_append_only
    BEFORE UPDATE OR DELETE ON cardioauth.case_status_history
    FOR EACH ROW EXECUTE FUNCTION cardioauth.reject_write('case_status_history_append_only');

CREATE TRIGGER trg_verification_run_append_only
    BEFORE UPDATE OR DELETE ON cardioauth.verification_run
    FOR EACH ROW EXECUTE FUNCTION cardioauth.reject_write('verification_run_append_only');

CREATE TRIGGER trg_claim_verdict_append_only
    BEFORE UPDATE OR DELETE ON cardioauth.claim_verdict
    FOR EACH ROW EXECUTE FUNCTION cardioauth.reject_write('claim_verdict_append_only');

CREATE TRIGGER trg_claim_verdict_fact_append_only
    BEFORE UPDATE OR DELETE ON cardioauth.claim_verdict_fact
    FOR EACH ROW EXECUTE FUNCTION cardioauth.reject_write('claim_verdict_fact_append_only');

CREATE TRIGGER trg_audit_log_append_only
    BEFORE UPDATE OR DELETE ON cardioauth_audit.audit_log
    FOR EACH ROW EXECUTE FUNCTION cardioauth.reject_write('audit_log_append_only');

-- ---------------------------------------------------------------------------
-- INV-4: a sign-off is permanent except for a single revocation.
-- ---------------------------------------------------------------------------
CREATE FUNCTION cardioauth.guard_signoff() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM cardioauth.invariant_violation('signoff_immutable', format('signoff=%s delete refused', OLD.id));
    END IF;

    IF OLD.revoked_at IS NOT NULL THEN
        PERFORM cardioauth.invariant_violation('signoff_immutable', format('signoff=%s already revoked', OLD.id));
    END IF;
    IF NEW.revoked_at IS NULL THEN
        PERFORM cardioauth.invariant_violation('signoff_needs_revoke_reason', format('signoff=%s', OLD.id));
    END IF;

    -- only the revocation columns may change, ever
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.case_id IS DISTINCT FROM OLD.case_id
       OR NEW.letter_id IS DISTINCT FROM OLD.letter_id
       OR NEW.letter_version_id IS DISTINCT FROM OLD.letter_version_id
       OR NEW.signer_id IS DISTINCT FROM OLD.signer_id
       OR NEW.signer_npi IS DISTINCT FROM OLD.signer_npi
       OR NEW.method IS DISTINCT FROM OLD.method
       OR NEW.attestation_text IS DISTINCT FROM OLD.attestation_text
       OR NEW.signature_hash IS DISTINCT FROM OLD.signature_hash
       OR NEW.signed_at IS DISTINCT FROM OLD.signed_at
       OR NEW.reauth_at IS DISTINCT FROM OLD.reauth_at
       OR NEW.verification_run_id IS DISTINCT FROM OLD.verification_run_id THEN
        PERFORM cardioauth.invariant_violation('signoff_immutable',
            format('signoff=%s only revoked_at/revoke_reason may be set once', OLD.id));
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER trg_signoff_guard
    BEFORE UPDATE OR DELETE ON cardioauth.signoff
    FOR EACH ROW EXECUTE FUNCTION cardioauth.guard_signoff();

-- ---------------------------------------------------------------------------
-- INV-2: published criteria (and their criterion rows) are immutable.
-- ---------------------------------------------------------------------------
CREATE FUNCTION cardioauth.guard_criteria_set_version() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.status <> 'draft' THEN
            PERFORM cardioauth.invariant_violation('criteria_version_immutable',
                format('version=%s status=%s delete refused', OLD.id, OLD.status));
        END IF;
        RETURN OLD;
    END IF;

    -- one-way lifecycle: draft -> published -> retired
    IF OLD.status = 'draft' AND NEW.status NOT IN ('draft','published') THEN
        PERFORM cardioauth.invariant_violation('criteria_version_status_transition',
            format('version=%s %s -> %s', OLD.id, OLD.status, NEW.status));
    END IF;
    IF OLD.status = 'published' AND NEW.status NOT IN ('published','retired') THEN
        PERFORM cardioauth.invariant_violation('criteria_version_status_transition',
            format('version=%s %s -> %s', OLD.id, OLD.status, NEW.status));
    END IF;
    IF OLD.status = 'retired' AND NEW.status <> 'retired' THEN
        PERFORM cardioauth.invariant_violation('criteria_version_status_transition',
            format('version=%s %s -> %s', OLD.id, OLD.status, NEW.status));
    END IF;
    IF OLD.status = 'draft' AND NEW.status = 'published'
       AND (NEW.published_at IS NULL OR NEW.published_by IS NULL) THEN
        PERFORM cardioauth.invariant_violation('criteria_version_publish_incomplete',
            format('version=%s published_at/published_by required', OLD.id));
    END IF;

    IF OLD.status <> 'draft' THEN
        IF NEW.criteria_set_id IS DISTINCT FROM OLD.criteria_set_id
           OR NEW.version_no IS DISTINCT FROM OLD.version_no
           OR NEW.is_placeholder IS DISTINCT FROM OLD.is_placeholder
           OR NEW.verification_label IS DISTINCT FROM OLD.verification_label
           OR NEW.source_citation IS DISTINCT FROM OLD.source_citation
           OR NEW.effective_from IS DISTINCT FROM OLD.effective_from
           OR NEW.fingerprint IS DISTINCT FROM OLD.fingerprint
           OR NEW.notes IS DISTINCT FROM OLD.notes
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            PERFORM cardioauth.invariant_violation('criteria_version_immutable',
                format('version=%s status=%s: only status, effective_to and publication columns may change',
                       OLD.id, OLD.status));
        END IF;
        -- publication stamps themselves are write-once
        IF OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at THEN
            PERFORM cardioauth.invariant_violation('criteria_version_immutable',
                format('version=%s published_at is write-once', OLD.id));
        END IF;
        IF OLD.published_by IS NOT NULL AND NEW.published_by IS DISTINCT FROM OLD.published_by THEN
            PERFORM cardioauth.invariant_violation('criteria_version_immutable',
                format('version=%s published_by is write-once', OLD.id));
        END IF;
    END IF;

    NEW.updated_at := now();
    RETURN NEW;
END $$;

CREATE TRIGGER trg_criteria_set_version_guard
    BEFORE UPDATE OR DELETE ON cardioauth.criteria_set_version
    FOR EACH ROW EXECUTE FUNCTION cardioauth.guard_criteria_set_version();

CREATE FUNCTION cardioauth.guard_criterion() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_status text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        SELECT status INTO v_status FROM cardioauth.criteria_set_version WHERE id = OLD.version_id;
    ELSE
        SELECT status INTO v_status FROM cardioauth.criteria_set_version WHERE id = NEW.version_id;
    END IF;

    IF v_status IS DISTINCT FROM 'draft' THEN
        PERFORM cardioauth.invariant_violation('criterion_immutable',
            format('criterion version status=%s op=%s', coalesce(v_status,'unknown'), TG_OP));
    END IF;

    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER trg_criterion_guard
    BEFORE INSERT OR UPDATE OR DELETE ON cardioauth.criterion
    FOR EACH ROW EXECUTE FUNCTION cardioauth.guard_criterion();

-- A published version must actually contain criteria (published = reviewable).
CREATE FUNCTION cardioauth.require_published_criteria() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status = 'published' AND NOT EXISTS (
        SELECT 1 FROM cardioauth.criterion c WHERE c.version_id = NEW.id) THEN
        PERFORM cardioauth.invariant_violation('criteria_version_publish_empty',
            format('version=%s has no criteria', NEW.id));
    END IF;
    RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER trg_require_published_criteria
    AFTER UPDATE ON cardioauth.criteria_set_version
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION cardioauth.require_published_criteria();

-- ---------------------------------------------------------------------------
-- INV-3: a case may only become ready for review when nothing blocks it
--        (the full precondition matrix lives in tracker_service, §6.2)
-- ---------------------------------------------------------------------------
COMMENT ON TABLE cardioauth.fact IS 'Extracted clinical facts. Every row has >=1 cardioauth.fact_span (INV-1, deferred constraint trigger).';
COMMENT ON TABLE cardioauth.fact_span IS 'Source spans. quote_text is validated against the immutable page text by trigger (INV-1).';
COMMENT ON TABLE cardioauth.page_text_version IS 'Append-only page text (INV-1). Offsets in fact_span index into text_normalized.';
COMMENT ON TABLE cardioauth.criteria_set_version IS 'Versioned criteria. Immutable once published (INV-2). Placeholder seed is UNVERIFIED.';
COMMENT ON TABLE cardioauth.letter_version IS 'Insert-only letter AST (INV-3). Edits create a new version; export_blocked is derived from verification_run.';
COMMENT ON TABLE cardioauth.signoff IS 'Typed physician attestation (INV-4). Revocable once; every other column is immutable.';
COMMENT ON TABLE cardioauth_audit.audit_log IS 'Append-only hash-chained audit (INV-5). No PHI values in detail; ids and field names only.';
