"""The application's log stream must survive whatever other tests do to global logging.

``tests/test_no_phi_in_denials.py`` opens with a positive control: *the application really did
log these requests*, so that its "no sentinel in any log record" assertions are not vacuous.
That control is only worth having if it cannot be disarmed by ambient logging state — and it
was disarmed, which is why this module exists.

The polluter, reproduced and named:

* ``tests/conftest.py``'s session-scoped ``test_database_url`` fixture runs Alembic
  (``alembic.command.upgrade``), whose ``migrations/env.py`` called
  ``fileConfig(Alembic's alembic.ini)``;
* ``fileConfig`` defaults to ``disable_existing_loggers=True``, so it set ``disabled = True`` on
  **every logger that already existed** and was not named in ``alembic.ini``. In a full-suite
  run that was 52 loggers: ``cardioauth.api.main``, ``cardioauth.api.health``,
  ``cardioauth.auth.*``, ``cardioauth.authz.deps``, ``cardioauth.settings`` — and ``httpx``;
* from that moment ``Logger.isEnabledFor`` returned ``False`` for all of them, so the
  application's records were dropped before any handler could see them. The sentinel test's
  capture then collected nothing (``captured=0 app_records=0``) and its positive control failed.

Because the database fixture runs lazily and only once, whether a given test module was hit
depended on import order: a module that imported ``cardioauth.api.main`` before the first
database test lost its application logs for the rest of the session. Running
``tests/test_no_phi_in_denials.py`` alone hid the bug completely.

Two guards, cheapest first: the capture itself must be indifferent to the state it is handed
(``tests/logging_capture.py``), and the migration environment must not disable loggers it does
not own.
"""

from __future__ import annotations

import ast
import io
import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from alembic import command
from alembic.config import Config

BACKEND_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_ROOT / "alembic.ini"
ENV_PY = BACKEND_ROOT / "migrations" / "env.py"

#: Loggers this module asserts stay enabled. All of them are created by importing the
#: application, so each one is exactly the kind of logger the polluter used to switch off.
APPLICATION_LOGGERS = (
    "cardioauth.api.main",
    "cardioauth.auth.service",
    "cardioauth.settings",
)

#: The subset that this module logs through, so the capture must contain exactly these names.
PROBED_LOGGERS = frozenset({"cardioauth.api.main", "cardioauth.auth.service"})


@contextmanager
def _logging_state_restored() -> Iterator[None]:
    """Snapshot the whole global logging state and put it back afterwards.

    This module deliberately does to the process exactly what the polluter did, so it has to
    leave no trace of it: a test that silences loggers would otherwise break the tests that
    follow it — the same bug it is here to prevent.
    """
    root = logging.getLogger()
    previous_disable = logging.Logger.manager.disable
    previous_root = (root.disabled, root.level, list(root.handlers), list(root.filters))
    previous_loggers = [
        (name, logger.disabled, logger.level, logger.propagate)
        for name, logger in logging.Logger.manager.loggerDict.items()
        if isinstance(logger, logging.Logger)
    ]
    try:
        yield
    finally:
        root.disabled, root.level, handlers, filters = previous_root
        root.handlers = handlers
        root.filters = filters
        for name, disabled, level, propagate in previous_loggers:
            logger = logging.getLogger(name)
            logger.disabled = disabled
            logger.setLevel(level)
            logger.propagate = propagate
        logging.disable(previous_disable)


def test_the_capture_collects_application_records_after_loggers_are_disabled() -> None:
    """The sentinel capture, run against the exact state the polluter left behind.

    A dependency calls ``fileConfig`` with its defaults — what ``migrations/env.py`` used to do,
    and what any library may do — and the capture must still see the application's records.
    """
    import cardioauth.api.main  # noqa: F401 - importing is what creates the loggers
    import cardioauth.auth.service  # noqa: F401

    from tests.logging_capture import capture_application_logs

    with _logging_state_restored():
        # The polluter, replayed verbatim: the stdlib default is disable_existing_loggers=True.
        from logging.config import fileConfig

        fileConfig(str(ALEMBIC_INI))

        # Positive control: if this stops holding, the test below is no longer testing anything.
        disabled = {name: logging.getLogger(name).disabled for name in APPLICATION_LOGGERS}
        assert disabled == dict.fromkeys(APPLICATION_LOGGERS, True), (
            "the polluter did not reproduce; this test would otherwise pass vacuously: "
            f"{disabled}"
        )

        with capture_application_logs() as captured:
            cardioauth.api.main.logger.info("http.request", extra={"action": "TEST-ONLY pollution probe"})
            cardioauth.auth.service.logger.info("auth.probe")

    assert captured, "the capture collected nothing at all"
    names = {record.name for record in captured}
    assert names >= PROBED_LOGGERS, f"the application's own loggers were not captured: {names}"
    actions = {
        record.__dict__.get("action") for record in captured if record.name == "cardioauth.api.main"
    }
    assert "TEST-ONLY pollution probe" in actions, "the record's extras did not survive the capture"


def test_the_capture_is_indifferent_to_the_ambient_logger_configuration() -> None:
    """Capturing must not be a matter of luck: same records, with and without interference."""
    import cardioauth.api.main  # noqa: F401

    from tests.logging_capture import capture_application_logs

    def captured_actions() -> list[str]:
        with capture_application_logs() as captured:
            cardioauth.api.main.logger.info("http.request", extra={"action": "TEST-ONLY even split"})
        return [
            record.__dict__["action"] for record in captured if record.name == "cardioauth.api.main"
        ]

    clean = captured_actions()

    with _logging_state_restored():
        logger = logging.getLogger("cardioauth.api.main")
        logger.disabled = True  # a dependency switched the logger off
        logger.setLevel(logging.CRITICAL)  # and pinned its level above the record
        logger.propagate = False  # and stopped it propagating to the root handler
        logging.disable(logging.CRITICAL)  # and disabled logging process-wide
        polluted = captured_actions()
        # ...and the same three levers are handed back untouched.
        assert logger.disabled is True
        assert logger.level == logging.CRITICAL
        assert logger.propagate is False
        assert logging.Logger.manager.disable == logging.CRITICAL

    assert clean == ["TEST-ONLY even split"]
    assert polluted == clean, "the ambient logging configuration changed what the capture saw"


def test_the_migration_environment_does_not_disable_application_loggers() -> None:
    """Alembic's environment configures its own loggers and nobody else's.

    Runs the real ``migrations/env.py`` through Alembic in offline mode (``--sql``), so the
    ``fileConfig`` call under test actually executes, and asserts the application's loggers are
    still enabled afterwards — the state the whole test suite (and any in-process migration)
    depends on.
    """
    import cardioauth.api.main  # noqa: F401

    with _logging_state_restored():
        config = Config(str(ALEMBIC_INI), output_buffer=io.StringIO())
        config.set_main_option("script_location", str(BACKEND_ROOT / "migrations"))
        command.upgrade(config, "head", sql=True)
        # Alembic really did configure logging in this process (positively: if env.py ever stops
        # calling fileConfig, this test should be revisited rather than pass for the wrong reason).
        assert config.output_buffer.getvalue(), "the offline upgrade produced no SQL; env.py did not run"
        still_disabled = {
            name: logging.getLogger(name).disabled
            for name in APPLICATION_LOGGERS
            if logging.getLogger(name).disabled
        }

    assert still_disabled == {}, f"migrations/env.py disabled application loggers: {still_disabled}"


def test_the_migration_environment_passes_disable_existing_loggers_false() -> None:
    """The source-level half of the guard above, which cannot be fooled by import timing."""
    calls = [
        node
        for node in ast.walk(ast.parse(ENV_PY.read_text(encoding="utf-8")))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "fileConfig"
    ]
    assert calls, "migrations/env.py no longer calls fileConfig; revisit this guard"
    for call in calls:
        kwargs = {keyword.arg: keyword.value for keyword in call.keywords}
        passed = kwargs.get("disable_existing_loggers")
        assert isinstance(passed, ast.Constant) and passed.value is False, (
            "migrations/env.py must call fileConfig(..., disable_existing_loggers=False): the "
            "default silences every logger the host process already created, which is how the "
            f"application's log stream disappeared (line {call.lineno})"
        )
