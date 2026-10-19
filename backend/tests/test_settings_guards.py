"""Settings guards and the PHI log filter (the two mechanisms §4.2 and §7.5 require)."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from cardioauth.logging_setup import PhiInLogsError, PhiLogFilter, configure_logging
from cardioauth.settings import DEV_APP_KEY, Environment, Settings, SettingsError

BACKEND_ROOT = Path(__file__).resolve().parents[1]


def _production_settings(**overrides: object) -> Settings:
    base = {
        "cardioauth_env": Environment.production,
        "cardioauth_phi_logging": "off",
        "llm_provider": "bedrock",
        "llm_model": "some-baa-model",
        "blob_backend": "s3",
        "s3_bucket": "cardioauth-prod",
        "s3_region": "us-east-1",
        "s3_server_side_encryption": "aws:kms",
        "app_key": "not-the-dev-key-but-long-enough-for-real-use-ok",
        "database_require_tls": True,
        "session_cookie_secure": True,
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


def test_safe_production_configuration_is_accepted() -> None:
    _production_settings().assert_runtime_safe()


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"llm_provider": "mock"}, "LLM_PROVIDER=mock"),
        ({"cardioauth_phi_logging": "dev"}, "CARDIOAUTH_PHI_LOGGING=dev"),
        ({"blob_backend": "local"}, "BLOB_BACKEND=local"),
        ({"app_key": DEV_APP_KEY}, "APP_KEY is still the development default"),
        ({"app_key": "too-short-key"}, "at least 32"),
        ({"database_require_tls": False}, "DATABASE_REQUIRE_TLS=false"),
        ({"session_cookie_secure": False}, "SESSION_COOKIE_SECURE=false"),
        ({"s3_server_side_encryption": None}, "server-side encryption"),
    ],
)
def test_production_refuses_unsafe_configuration(overrides: dict, expected: str) -> None:
    with pytest.raises(SettingsError) as excinfo:
        _production_settings(**overrides).assert_runtime_safe()
    assert expected in str(excinfo.value)
    assert "refusing to start" in str(excinfo.value)


def test_dev_defaults_are_allowed_and_flagged() -> None:
    settings = Settings(_env_file=None, cardioauth_env=Environment.dev)
    settings.assert_runtime_safe()  # dev may use the mock provider and local blobs
    assert settings.is_production is False
    assert settings.cookie_secure is False


def test_synthetic_fixtures_are_refused_in_production() -> None:
    with pytest.raises(SettingsError):
        _production_settings().assert_lab_role()
    Settings(_env_file=None, cardioauth_env=Environment.test).assert_lab_role()


def _reads_environment(source: str) -> bool:
    """True when *source* reads the process environment.

    Parsed as an AST rather than matched with a regex, so a comment or docstring that
    merely *mentions* ``os.environ`` — e.g. explaining why it is deliberately not used —
    is not an offender. Only real accesses count: ``os.environ[...]``,
    ``os.environ.get(...)`` and ``os.getenv(...)``.
    """
    import ast

    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Attribute) and node.attr == "environ":
            return True
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "getenv":
                return True
            if isinstance(func, ast.Attribute) and func.attr == "getenv":
                return True
    return False


def test_environment_guard_detects_real_reads_but_not_mentions() -> None:
    """Negative control: the guard must still catch a genuine environment read, so that
    making it AST-based did not quietly turn it into a no-op."""
    assert _reads_environment("import os\nX = os.environ['CARDIOAUTH_ENV']\n") is True
    assert _reads_environment("import os\nX = os.environ.get('CARDIOAUTH_ENV')\n") is True
    assert _reads_environment("import os\nX = os.getenv('CARDIOAUTH_ENV')\n") is True
    # A comment/docstring that merely names the mechanism is not a read.
    assert _reads_environment("# no os.environ here: use Settings\n") is False
    assert _reads_environment('"""Never read os.environ directly."""\n') is False


def test_every_env_var_is_declared_in_one_place() -> None:
    """Nothing outside cardioauth/settings.py may read the process environment, and the docs
    must list every variable the settings object accepts."""
    offenders = []
    for path in (BACKEND_ROOT / "cardioauth").rglob("*.py"):
        if path.name == "settings.py":
            continue
        if _reads_environment(path.read_text(encoding="utf-8")):
            offenders.append(str(path.relative_to(BACKEND_ROOT)))
    assert offenders == [], f"read environment through Settings instead: {offenders}"

    env_example = (BACKEND_ROOT.parent / ".env.example").read_text(encoding="utf-8")
    declared = {name.upper() for name in Settings.model_fields}
    missing = {name for name in declared if f"{name}=" not in env_example and f"#{name}" not in env_example}
    assert missing == set(), f".env.example does not document: {sorted(missing)}"


def test_phi_filter_refuses_document_text_from_a_sensitive_module(caplog) -> None:  # noqa: ANN001
    configure_logging(level="INFO", fmt="json", env="test")
    filter_ = PhiLogFilter(allow_phi_body=False)
    record = logging.LogRecord(
        name="cardioauth.services.ingest_service", level=logging.INFO, pathname=__file__, lineno=1,
        msg="stored %s", args=("page_text",), exc_info=None,
    )
    with pytest.raises(PhiInLogsError):
        filter_.filter(record)


def test_phi_filter_refuses_phi_shaped_extras(caplog) -> None:  # noqa: ANN001
    filter_ = PhiLogFilter(allow_phi_body=False)
    record = logging.LogRecord(
        name="cardioauth.services.letter_service", level=logging.INFO, pathname=__file__, lineno=1,
        msg="generated sentence", args=(), exc_info=None,
    )
    record.quote_text = "LVEF 55 percent"
    with pytest.raises(PhiInLogsError):
        filter_.filter(record)


def test_phi_filter_allows_identifiers_and_counts() -> None:
    filter_ = PhiLogFilter(allow_phi_body=False)
    record = logging.LogRecord(
        name="cardioauth.services.extraction_service", level=logging.INFO, pathname=__file__, lineno=1,
        msg="extraction.completed facts=%d rejected=%d", args=(12, 2), exc_info=None,
    )
    assert filter_.filter(record) is True


def test_log_filter_is_installed_on_the_root_logger() -> None:
    configure_logging(level="INFO", fmt="json", env="test")
    names = [f.name for f in logging.getLogger().filters]
    assert "cardioauth.phi_filter" in names
    assert any(isinstance(h.filters[0], PhiLogFilter) for h in logging.getLogger().handlers if h.filters)


def test_sensitive_modules_do_not_format_document_text_into_log_calls() -> None:
    """The lint rule in §7.5, implemented as an AST check: no f-string log arguments in
    the modules that handle document text."""
    import ast

    sensitive = [
        BACKEND_ROOT / "cardioauth" / "services",
        BACKEND_ROOT / "cardioauth" / "llm",
        BACKEND_ROOT / "cardioauth" / "ocr",
        BACKEND_ROOT / "cardioauth" / "blobs",
    ]
    violations: list[str] = []
    for directory in sensitive:
        for path in Path(directory).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "logger"
                    and node.func.attr in {"debug", "info", "warning", "error", "exception", "critical"}
                ):
                    for arg in node.args:
                        if isinstance(arg, ast.JoinedStr):
                            violations.append(f"{path.name}:{node.lineno}")
    assert violations == [], f"f-string logging of values is forbidden here: {violations}"
