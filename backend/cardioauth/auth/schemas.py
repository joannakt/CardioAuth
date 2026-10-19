"""Authentication schemas — request and response bodies for /api/auth.

Response bodies never contain a password, a session token, a TOTP secret or a recovery code,
with exactly two exceptions that are *documented and deliberate*:

* ``otpauth`` on ``POST /totp/enrol`` returns the shared secret and provisioning URI — the
  user has to see it once to put it in their authenticator app;
* ``recovery_codes`` on ``POST /totp/activate`` and ``POST /totp/recovery-codes`` returns the
  10 plaintext codes once. The server keeps only keyed hashes; there is no "show them again".
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=512)


class CodeRequest(BaseModel):
    """A 6-digit TOTP code or a recovery code on the same field.

    One field for both is intentional: the UI should not have to tell the server which kind
    of code it holds, and the server decides from the shape (``security.totp``).
    """

    code: str = Field(min_length=1, max_length=64)


class StepUpRequest(BaseModel):
    password: str = Field(min_length=1, max_length=512)
    code: str | None = Field(default=None, max_length=64)


class DisableTotpRequest(BaseModel):
    password: str = Field(min_length=1, max_length=512)
    code: str | None = Field(default=None, max_length=64)


class RevokeAllRequest(BaseModel):
    """``include_current=False`` keeps the calling session alive (the usual self-service case)."""

    include_current: bool = False


class SessionOut(BaseModel):
    id: uuid.UUID
    issued_at: datetime
    last_seen_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    two_factor_verified: bool
    reauth_at: datetime | None
    current: bool
    #: First 12 hex characters of the keyed fingerprint: lets a user recognise "that is my
    #: other browser" without the server ever storing or returning the address itself.
    request_fingerprint: str | None = None


class SessionListView(BaseModel):
    sessions: list[SessionOut]
    count: int


class AuthStateOut(BaseModel):
    """The client's view of its own authentication state. No secrets."""

    status: str
    user_id: uuid.UUID | None = None
    role: str | None = None
    practice_id: uuid.UUID | None = None
    totp_enrolled: bool = False
    two_factor_verified: bool = False
    totp_enrolment_required: bool = False
    recovery_codes_remaining: int | None = None
    reauth_at: datetime | None = None
    reauth_required: bool = False


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]


class MessageOut(BaseModel):
    status: str
    detail: str | None = None


class RevokeAllOut(BaseModel):
    sessions_revoked: int
    kept_current: bool


class ErrorOut(BaseModel):
    """Error body. ``code`` is a stable machine-readable reason; never contains user input."""

    code: str
    message: str


__all__ = [
    "AuthStateOut",
    "CodeRequest",
    "DisableTotpRequest",
    "ErrorOut",
    "LoginRequest",
    "MessageOut",
    "RecoveryCodesOut",
    "RevokeAllOut",
    "RevokeAllRequest",
    "SessionListView",
    "SessionOut",
    "StepUpRequest",
]
