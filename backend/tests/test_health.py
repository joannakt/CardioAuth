"""/api/health smoke test: liveness, database connectivity and the migration revision."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.db


@pytest.fixture
def client(test_database_url: str) -> TestClient:
    from cardioauth.api.main import create_app

    return TestClient(create_app())


def test_health_reports_ok_with_the_current_revision(client: TestClient, test_database_url: str) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "ok"
    assert body["checks"] == {"liveness": "ok", "database": "ok", "schema": "ok"}
    assert body["database"]["connected"] is True
    assert body["database"]["revision"] == "0001"
    assert body["database"]["expected_revision"] == "0001"
    assert body["database"]["latency_ms"] >= 0
    assert body["service"] == "cardioauth-api"
    assert response.headers["x-cardioauth-version"]


def test_health_is_503_and_degraded_when_the_schema_is_behind(test_database_url: str, monkeypatch) -> None:  # noqa: ANN001
    """A reachable database with no baseline applied must not look healthy."""
    from sqlalchemy import create_engine, text

    from cardioauth.api import health as health_module
    from cardioauth.db import reset_engine
    from cardioauth.settings import get_settings

    monkeypatch.setenv("DATABASE_URL", test_database_url.replace("/cardioauth_test", "/postgres"))
    get_settings.cache_clear()
    reset_engine()
    engine = create_engine(test_database_url.replace("/cardioauth_test", "/postgres"))
    with engine.connect() as conn:
        has_version_table = conn.execute(
            text("SELECT to_regclass('public.alembic_version') IS NOT NULL")
        ).scalar_one()
    engine.dispose()
    if has_version_table:
        pytest.skip("the admin database happens to carry an alembic_version table")

    from cardioauth.audit.chain import verify_chain  # noqa: F401  (import sanity)

    health_module.expected_head_revision()  # unchanged: the build still expects 0001
    try:
        response = TestClient(health_module.router and __import__("cardioauth.api.main", fromlist=["create_app"]).create_app()).get("/api/health")
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()
        reset_engine()
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["database"] == "ok"
    assert body["checks"]["schema"] == "stale"
