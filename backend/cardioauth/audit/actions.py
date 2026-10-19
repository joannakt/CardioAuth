"""The closed audit-action vocabulary (DESIGN.md §7.4).

One module so the vocabulary "cannot drift". The names listed in §7.4 are present verbatim;
the auth names this milestone needed and the design did not enumerate are marked
``ADDED IN M1b-1`` with the reason, so a reviewer can see exactly what grew and why.

Every value is ``<object>.<past_tense_verb>`` and is written to
``cardioauth_audit.audit_log.action`` as free text (the column has no CHECK constraint, so
a new action never needs a migration — but it *does* need to be added here, and
``tests/test_auth_audit.py`` asserts the auth code path emits nothing outside this set).
"""

from __future__ import annotations

from typing import Final

# --- §7.4 "View" -----------------------------------------------------------
VIEW_ACTIONS: Final[frozenset[str]] = frozenset(
    {
        "case.viewed",
        "document.viewed",
        "letter.version_viewed",
        "criteria.version_viewed",
        "audit_log.viewed",
        "gap.report_viewed",
        "document.exported",
        "letter.exported",
    }
)

# --- §7.4 "Edit" -----------------------------------------------------------
EDIT_ACTIONS: Final[frozenset[str]] = frozenset(
    {
        "case.created",
        "case.updated",
        "document.uploaded",
        "document.text_pasted",
        "document.deleted",
        "page.reocr_requested",
        "extraction.started",
        "extraction.completed",
        "evaluation.completed",
        "criterion_verdict.overridden",
        "gap.waived",
        "gap.resolved",
        "letter.generated",
        "letter.edited",
        "letter.version_created",
        "verification.completed",
        "criteria.set_created",
        "criteria.version_published",
        "criteria.criterion_updated",
        "case.criteria_repinned",
        # --- ADDED IN M1b-2 (RBAC) ------------------------------------------
        # §7.3 "Delete/redact a case": a soft redaction keeps the case row and the audit
        # trail and clears the clinical payload, so it is an edit the log must show.
        "case.redacted",
    }
)

# --- §7.4 "Export/sign" ----------------------------------------------------
EXPORT_SIGN_ACTIONS: Final[frozenset[str]] = frozenset(
    {
        "letter.submitted_for_review",
        "letter.signed",
        "letter.signoff_revoked",
    }
)

# --- §7.4 "Auth" -----------------------------------------------------------
AUTH_ACTIONS: Final[frozenset[str]] = frozenset(
    {
        "auth.login_succeeded",
        "auth.login_failed",
        "auth.totp_failed",
        "auth.logout",
        "auth.session_expired",
        "auth.step_up_succeeded",
        "auth.step_up_failed",
        "auth.password_changed",
        "user.created",
        "user.deactivated",
        "user.role_changed",
        # --- ADDED IN M1b-1 (identity & session core) ----------------------
        # §7.4 names the auth events but not these; each is an event the milestone's scope
        # requires to be recorded (task item 6), so the vocabulary grows deliberately.
        "auth.account_locked",  # lockout threshold reached; detail carries stage and minutes
        "auth.totp_succeeded",  # a second factor was accepted (login step-up) — audit has no PHI
        "auth.totp_enrolled",  # enrolment completed; detail carries recovery_code_count
        "auth.totp_disabled",  # second factor removed after a fresh password check
        "auth.recovery_codes_issued",  # codes (re)generated; plaintext is never audited
        "auth.recovery_code_used",  # a recovery code was consumed (single use)
        "auth.session_revoked",  # one session revoked (self or admin, by id)
        "auth.sessions_revoked_all",  # every session of one user revoked
    }
)

# --- §7.4 "Status" ---------------------------------------------------------
STATUS_ACTIONS: Final[frozenset[str]] = frozenset({"case.status_changed"})

# --- ADDED IN M1b-2: authorisation decisions (§7.3 "every denial is audited") ----------
# One action for every refused authorisation decision: a role that does not hold the
# permission, a sensitive permission without a fresh step-up, a constraint or precondition
# that was not met, an object outside the practice, and an endpoint that declared no
# policy at all. The reason code and the required permission travel in ``detail``; the
# actor, the object type and the object id are columns. Successful decisions are
# deliberately NOT logged here: the domain action they permit (case.viewed,
# letter.exported, ...) is the record, and a row per allowed request would bury it.
AUTHZ_ACTIONS: Final[frozenset[str]] = frozenset({"authz.denied"})

# --- ADDED IN M1b-3: blob-store events (§1.3, INV-5) -----------------------------------
# The storage layer is where clinical documents actually live, so create/read/export/delete
# are recorded at the store boundary and not only at the API boundary. Four verbs, one extra
# for corruption: a read that fails its integrity check is an event a compliance reviewer
# needs (it means stored evidence changed under a citation), and it must not be silent.
# ``detail`` carries the PHI-free projection in
# :func:`cardioauth.blobs.base.describe_metadata` — backend, encryption mode, namespace kind,
# blob id, content type, sizes and digests. Never a filename, never a byte of the object.
STORAGE_ACTIONS: Final[frozenset[str]] = frozenset(
    {
        "blob.created",
        "blob.read",
        "blob.exported",
        "blob.deleted",
        "blob.integrity_failed",
    }
)

#: The complete vocabulary. An audit write whose action is not here is a bug.
ALL_ACTIONS: Final[frozenset[str]] = (
    VIEW_ACTIONS
    | EDIT_ACTIONS
    | EXPORT_SIGN_ACTIONS
    | AUTH_ACTIONS
    | STATUS_ACTIONS
    | AUTHZ_ACTIONS
    | STORAGE_ACTIONS
)

__all__ = [
    "ALL_ACTIONS",
    "AUTH_ACTIONS",
    "AUTHZ_ACTIONS",
    "EDIT_ACTIONS",
    "EXPORT_SIGN_ACTIONS",
    "STATUS_ACTIONS",
    "STORAGE_ACTIONS",
    "VIEW_ACTIONS",
]
