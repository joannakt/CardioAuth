-- CardioAuth — M1b-1 identity and session core (DESIGN.md §2.1, §7.1, §7.2, §11 Q4).
-- Applied by Alembic revision 0002 on top of 0001; 001_schema.sql is never amended.
--
-- What this adds and why:
--   app_user.lockout_stage        the "exponential thereafter" part of the lockout rule
--                                 (§7.1) needs a counter that survives a lockout, so the
--                                 Nth lockout can be longer than the first.
--   user_session.two_factor_verified_at
--                                 a session created by a password check that still owes a
--                                 second factor is a *pending* session. It must not be
--                                 usable for protected routes, and it is rotated into a
--                                 fully authenticated session when the factor is verified
--                                 (fixation defence, §7.1).
--   totp_used_code                single-use enforcement: (user, code, time step) can be
--                                 consumed exactly once, so a replayed code fails. The
--                                 code is stored as a keyed hash, never in the clear.
--   user_recovery_code            10 single-use recovery codes per user, stored as keyed
--                                 hashes (§7.1); only the hash is ever persisted.
--
-- No clinical content and no medical-necessity rule lives in this file.
--
-- INV-5 note: none of these columns store a secret in the clear. `totp_secret_enc` (0001)
-- holds AES-GCM ciphertext keyed by APP_KEY; session tokens are SHA-256 digests; TOTP
-- codes and recovery codes are keyed HMAC-SHA256 digests.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Lockout escalation counter (per user, per §7.1 "exponential thereafter")
-- ---------------------------------------------------------------------------
ALTER TABLE cardioauth.app_user
    ADD COLUMN lockout_stage integer NOT NULL DEFAULT 0;
ALTER TABLE cardioauth.app_user
    ADD CONSTRAINT ck_app_user_lockout_stage_non_negative CHECK (lockout_stage >= 0);

-- ---------------------------------------------------------------------------
-- Pending-2FA sessions (login step 1) vs fully authenticated sessions
-- ---------------------------------------------------------------------------
ALTER TABLE cardioauth.user_session
    ADD COLUMN two_factor_verified_at timestamptz;
-- A session can never claim a second factor before it was issued.
ALTER TABLE cardioauth.user_session
    ADD CONSTRAINT ck_session_totp_after_issue
    CHECK (two_factor_verified_at IS NULL OR two_factor_verified_at >= issued_at);

-- ---------------------------------------------------------------------------
-- TOTP replay ledger: one row per consumed code/step pair
-- ---------------------------------------------------------------------------
CREATE TABLE cardioauth.totp_used_code (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES cardioauth.app_user(id) ON DELETE CASCADE,
    code_hash  bytea NOT NULL,          -- HMAC-SHA256(key=derived APP_KEY, normalised code)
    time_step  bigint NOT NULL,         -- RFC 6238 step the code matched
    used_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_totp_used_code_hash_width CHECK (length(code_hash) = 32),
    CONSTRAINT uq_totp_used_code_user_code_step UNIQUE (user_id, code_hash, time_step)
);
CREATE INDEX ix_totp_used_code_user ON cardioauth.totp_used_code (user_id, used_at DESC);

-- ---------------------------------------------------------------------------
-- Recovery codes: keyed hashes, single use, revocable
-- ---------------------------------------------------------------------------
CREATE TABLE cardioauth.user_recovery_code (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES cardioauth.app_user(id) ON DELETE CASCADE,
    code_hash  bytea NOT NULL UNIQUE,   -- HMAC-SHA256(key=derived APP_KEY, normalised code)
    used_at    timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_recovery_code_hash_width CHECK (length(code_hash) = 32),
    CONSTRAINT ck_recovery_code_used_before_revoked
        CHECK (used_at IS NULL OR revoked_at IS NULL)
);
CREATE INDEX ix_recovery_code_user ON cardioauth.user_recovery_code (user_id, used_at);

COMMENT ON COLUMN cardioauth.app_user.lockout_stage IS
    'Number of completed lockouts; drives the exponential lockout backoff (DESIGN.md §7.1).';
COMMENT ON COLUMN cardioauth.user_session.two_factor_verified_at IS
    'NULL on a session that owes a second factor (password accepted, TOTP pending). '
    'Rotated into a new session on successful 2FA (DESIGN.md §7.1).';
COMMENT ON TABLE cardioauth.totp_used_code IS
    'Single-use ledger for TOTP codes; a replayed (code, step) pair is refused. Keyed hash only.';
COMMENT ON TABLE cardioauth.user_recovery_code IS
    'Single-use recovery codes, keyed-hash at rest. Plaintext is shown exactly once, at issue.';
