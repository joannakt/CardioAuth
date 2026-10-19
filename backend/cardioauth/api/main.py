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
from cardioauth.authz.policy import assert_routes_declared
from cardioauth.logging_setup import configure_logging
from cardioauth.security.identifiers import request_id_for, route_template
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
    # Deny by default, fail closed at import time: an endpoint that declares no policy is
    # unreachable, so it is a startup error rather than a silent hole (M1b-2, §7.3).
    assert_routes_declared(app, health_router, auth_router)

    @app.middleware("http")
    async def request_context(request: Request, call_next):  # type: ignore[no-untyped-def]
        started = time.perf_counter()
        # The correlation id is ours, not the caller's: a header value is not an identifier just
        # because it sits in an identifier's place, and this one is logged and audited
        # (cardioauth.security.identifiers). Generated before the route runs so the dependency
        # that puts it on an audit row names the same id as this log line.
        request_id = request_id_for(request)
        response = await call_next(request)
        # Identifiers only — never request bodies, query strings or document text (§7.5). The
        # path is logged as the *route template* it matched, so a free-text path segment cannot
        # reach a log line; a request that matched no route is recorded as <unmatched>.
        logger.info(
            "http.request",
            extra={
                "request_id": request_id,
                "action": f"{request.method} {route_template(request)}",
                "status": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            },
        )
        response.headers["x-cardioauth-version"] = __version__
        response.headers["x-request-id"] = request_id
        return response

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:  # noqa: ARG001
        logger.exception("unhandled_error")
        return JSONResponse(status_code=500, content={"detail": "internal error"})

    return app


app = create_app()
