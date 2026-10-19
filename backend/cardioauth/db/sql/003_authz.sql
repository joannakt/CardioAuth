-- ---------------------------------------------------------------------------
-- 003 — authorisation support for the §7.3 RBAC matrix (M1b-2)
--
-- The matrix itself is code (cardioauth/authz/permissions.py), deliberately: it is reviewed
-- against DESIGN.md §7.3 line by line, and a permission must not be grantable by editing a
-- row in a database that an application compromise could reach. What the database owes the
-- matrix is the storage the matrix's *decisions* need:
--
--   1. a denial must explain itself (CHECK on audit_log),
--   2. a denial must be findable by actor (index for the "privilege probing" review §7.3
--      asks for),
--   3. the "soft-redact a case" cell needs somewhere to record who redacted, when and why,
--   4. user management within a practice needs an index that does not scan the table.
--
-- Additive only: revisions 0001 and 0002 are never amended.
-- ---------------------------------------------------------------------------

-- 1. A refused authorisation is only useful if the row says why. The application always
--    writes a reason code into ``detail`` (cardioauth.authz.deps.audit_denial); this makes a
--    silent denial impossible to store, whoever the writer is.
ALTER TABLE cardioauth_audit.audit_log
    ADD CONSTRAINT ck_audit_denied_has_detail
    CHECK (outcome <> 'denied' OR detail <> '{}'::jsonb);

-- 2. §7.3: "Every denial is audited with outcome='denied', which makes privilege probing
--    visible." Answering "which refusals did this actor collect, most recent first" is a
--    per-actor scan without this index.
CREATE INDEX ix_audit_outcome_actor
    ON cardioauth_audit.audit_log (outcome, actor_user_id, occurred_at DESC);

-- 3. §7.3 "Delete/redact a case — admin, soft-redact with mandatory reason; audit entry
--    retained". The case row survives (it is soft), the clinical payload is cleared by the
--    endpoint that arrives with the case milestone, and these columns keep the redaction
--    itself on the record. All three are set together or not at all.
ALTER TABLE cardioauth.case_record
    ADD COLUMN redacted_at      timestamptz,
    ADD COLUMN redacted_by      uuid REFERENCES cardioauth.app_user(id),
    ADD COLUMN redaction_reason text;

ALTER TABLE cardioauth.case_record
    ADD CONSTRAINT ck_case_redaction_complete CHECK (
        (redacted_at IS NULL AND redacted_by IS NULL AND redaction_reason IS NULL)
        OR (redacted_at IS NOT NULL AND redacted_by IS NOT NULL
            AND redaction_reason IS NOT NULL AND length(btrim(redaction_reason)) > 0)
    );

-- Redacted cases stay in the table but must drop out of the working board cheaply.
CREATE INDEX ix_case_redacted ON cardioauth.case_record (practice_id, redacted_at)
    WHERE redacted_at IS NOT NULL;

-- 4. User management is practice-scoped (§7.3 "within practice"); listing a practice's users
--    by role is the only access pattern it has.
CREATE INDEX ix_app_user_practice_role ON cardioauth.app_user (practice_id, role);
