"""FastAPI application factory. M1a serves the health endpoint; M1b-1 adds ``/api/auth``
(login, second factor, sessions, step-up). Case, document, criteria, letter and verification
routers arrive with their milestones."""

from __future__ import annotations

import logging
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from cardioauth import __version__
from cardioauth.api.health import router as health_router
from cardioauth.auth.router import router as auth_router
from cardioauth.logging_setup import configure_logging
from cardioauth.settings import get_settings

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    settings = get_settings()
    # Production guards run before the app can serve a request (§4.2).
    settings.assert_runtime_safe()
    configure_logging(level=settings.log_level, fmt=settings.log_format, env=settings.cardioauth_env.value)

    app = FastAPI(
        title="CardioAuth API",
        version=__version__,
        docs_url="/api/docs" if not settings.is_production else None,
        openapi_url="/api/openapi.json" if not settings.is_production else None,
    )
    app.include_router(health_router, prefix="/api")
    app.include_router(auth_router)

    @app.middleware("http")
    async def request_context(request: Request, call_next):  # type: ignore[no-untyped-def]
        started = time.perf_counter()
        response = await call_next(request)
        # Identifiers only — never request bodies or document text (§7.5).
        logger.info(
            "http.request",
            extra={
                "request_id": request.headers.get("x-request-id", "-"),
                "action": f"{request.method} {request.url.path}",
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            },
        )
        response.headers["x-cardioauth-version"] = __version__
        return response

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:  # noqa: ARG001
        logger.exception("unhandled_error")
        return JSONResponse(status_code=500, content={"detail": "internal error"})

    return app


app = create_app()
