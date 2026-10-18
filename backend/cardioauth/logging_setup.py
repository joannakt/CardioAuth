"""Structured logging with the PHI filter (§7.5).

Rule for the whole codebase: **log identifiers, never values.** Document text, quotes,
patient identifiers and LLM prompt/completion bodies must never reach a log handler.

Enforcement is mechanical, not disciplinary:

* :class:`PhiLogFilter` is installed on the root logger and on every handler. It raises
  (so the offending log call fails loudly at the call site) when a record from a module
  that handles document text carries a denylisted marker.
* ``record.phi_body`` is only ever set by the LLM adapter when
  ``CARDIOAUTH_PHI_LOGGING=dev``; in any other mode it is refused here.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Final

# Modules that touch document text, spans, prompts or completions.
SENSITIVE_LOGGER_PREFIXES: Final[tuple[str, ...]] = (
    "cardioauth.services.ingest_service",
    "cardioauth.services.extraction_service",
    "cardioauth.services.letter_service",
    "cardioauth.services.verification_service",
    "cardioauth.ocr",
    "cardioauth.llm",
    "cardioauth.blobs",
)

# Substrings that must not appear in a log message, argument or extra from those modules.
PHI_DENYLIST: Final[tuple[str, ...]] = (
    "text_normalized",
    "quote_text",
    "document_text",
    "page_text",
    "prompt_body",
    "completion_body",
    "patient_name",
    "attestation_text",
    "raw_text",
)

PHI_EXTRA_KEYS: Final[frozenset[str]] = frozenset(
    {"text", "quote", "document_text", "page_text", "patient", "patient_name", "phi_body", "prompt", "completion"}
)


class PhiInLogsError(RuntimeError):
    """Raised when a log call would have written PHI."""


def _is_sensitive(logger_name: str) -> bool:
    return logger_name.startswith(SENSITIVE_LOGGER_PREFIXES)


class PhiLogFilter(logging.Filter):
    """Refuses PHI-shaped log records. Never returns False — it raises, so the bug is
    visible in tests and in development instead of silently dropping evidence."""

    def __init__(self, *, allow_phi_body: bool = False) -> None:
        super().__init__(name="cardioauth.phi_filter")
        self.allow_phi_body = allow_phi_body

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003 - logging API
        # A PHI-shaped value can arrive either as a conventional `extra=` key
        # (PHI_EXTRA_KEYS) or under one of the denylisted names (PHI_DENYLIST), so both
        # sets are checked against the record's attributes. Without the union,
        # `logger.info("msg", extra={"quote_text": ...})` would sail through.
        for key in PHI_EXTRA_KEYS | frozenset(PHI_DENYLIST):
            if key in record.__dict__:
                if key == "phi_body" and self.allow_phi_body:
                    continue
                raise PhiInLogsError(
                    f"log record from {record.name} carries a PHI-shaped attribute '{key}'; "
                    "log identifiers, never values (§7.5)"
                )
        if not _is_sensitive(record.name):
            return True
        try:
            rendered = record.getMessage()
        except Exception:  # pragma: no cover - defensive: never mask the original bug
            rendered = str(record.msg)
        haystack = f"{record.name} {rendered}"
        for token in PHI_DENYLIST:
            if token in haystack:
                raise PhiInLogsError(
                    f"log record from {record.name} contains denylisted marker '{token}' (§7.5)"
                )
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line; no free-form message text beyond what the caller passed."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in ("request_id", "case_id", "actor_user_id", "action", "object_type", "object_id", "duration_ms"):
            if (value := record.__dict__.get(key)) is not None:
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return f"{self.formatTime(record, '%H:%M:%S')} {record.levelname:<5} {record.name} :: {record.getMessage()}"


def configure_logging(*, level: str = "INFO", fmt: str = "json", env: str = "dev") -> None:
    """Install handlers, formatters and the PHI filter. Idempotent."""
    allow_phi_body = env == "dev"
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if fmt == "json" else ConsoleFormatter())
    handler.addFilter(PhiLogFilter(allow_phi_body=allow_phi_body))
    root.addHandler(handler)
    root.setLevel(level.upper())

    for filt in list(root.filters):
        root.removeFilter(filt)
    root.addFilter(PhiLogFilter(allow_phi_body=allow_phi_body))

    # uvicorn's loggers propagate; keep their noise out of application logs.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
