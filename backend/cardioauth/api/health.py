"""``/api/health`` — liveness, database connectivity and the applied migration revision.

This is the endpoint the Compose healthchecks and the smoke test use. It reports the
revision so that "the app is up" can never be confused with "the schema is current".
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from cardioauth import __version__
from cardioauth.authz.policy import PolicyRoute
from cardioauth.db import get_engine
from cardioauth.settings import get_settings

logger = logging.getLogger(__name__)

# PolicyRoute: the route refuses to run unless ROUTE_POLICIES declares it (deny by default).
router = APIRouter(tags=["health"], route_class=PolicyRoute)

BACKEND_ROOT = Path(__file__).resolve().parents[2]


def expected_head_revision() -> str | None:
    """The revision this build expects to find applied."""
    cfg = Config(str(BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_ROOT / "migrations"))
    try:
        return ScriptDirectory.from_config(cfg).get_current_head()
    except Exception:  # pragma: no cover - packaging accident
        return None


@router.get("/health")
def health() -> JSONResponse:
    settings = get_settings()
    head = expected_head_revision()
    database = {"connected": False, "revision": None, "expected_revision": head, "latency_ms": None, "error": None}
    started = time.perf_counter()
    try:
        with get_engine().connect() as conn:
            database["connected"] = conn.execute(text("SELECT 1")).scalar_one() == 1
            row = conn.execute(
                text("SELECT to_regclass('public.alembic_version') IS NOT NULL")
            ).scalar_one()
            database["revision"] = (
                conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none() if row else None
            )
    except Exception as exc:
        # Exception class only: a driver message can echo a DSN fragment.
        database["error"] = type(exc).__name__
        logger.warning("health.database_unavailable: %s", type(exc).__name__)
    database["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)

    migrated = database["revision"] is not None and database["revision"] == head
    status = "ok" if (database["connected"] and migrated) else "degraded"
    body = {
        "status": status,
        "service": "cardioauth-api",
        "version": __version__,
        "env": settings.cardioauth_env.value,
        "checks": {"liveness": "ok", "database": "ok" if database["connected"] else "fail", "schema": "ok" if migrated else "stale"},
        "database": database,
    }
    return JSONResponse(status_code=200 if status == "ok" else 503, content=body)
