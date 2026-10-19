"""Capturing the application's own log records, independent of ambient logging state.

A test that reads "what the application logged" must not be at the mercy of whatever global
logging configuration an earlier test left behind. In this suite it was, and it broke:

* ``tests/conftest.py``'s session ``test_database_url`` fixture runs Alembic through
  ``alembic.command.upgrade``;
* ``migrations/env.py`` then calls the stdlib's ``fileConfig(Alembic's alembic.ini)``;
* ``fileConfig`` defaults to ``disable_existing_loggers=True``, which sets
  ``disabled = True`` on **every logger that already exists** and is not named in
  ``alembic.ini`` — 52 loggers in a full-suite run, including ``cardioauth.api.main``,
  ``cardioauth.auth.*``, ``cardioauth.settings`` and ``httpx``;
* ``Logger.isEnabledFor`` therefore returns ``False`` for those loggers from then on, so
  their records are dropped before *any* handler — on any logger — can see them.

Whether it bites depends on import order, which is exactly what makes it a flaky-looking
failure: a module that imports ``cardioauth.api.main`` (and, via
``starlette.testclient``, ``httpx``) before the first database fixture runs loses its
application logs for the rest of the session; a module that imports them afterwards does not.

:func:`capture_application_logs` removes that dependency. Instead of trusting whatever the
global configuration currently says, it puts the application's own loggers into a known state
for the duration of the ``with`` block and restores precisely what it found:

* ``disabled`` — cleared, so a logger some dependency switched off still emits;
* ``level`` — ``cardioauth`` is pinned to ``DEBUG`` and its children to ``NOTSET`` (inherit),
  so a logger pinned above the level under test cannot silently drop the record;
* ``propagate`` — forced on, so a record always reaches the handler below regardless of where
  the ambient configuration put it;
* ``logging.Logger.manager.disable`` — set to ``NOTSET``, so a global ``logging.disable()``
  cannot swallow the block either.

The handler is attached to the ``cardioauth`` namespace *and* to the root logger (where a
deployed handler sits) and collects each record once, so neither attachment point can be
removed from under the test nor duplicate a record.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator

#: The application's logger namespace: every module logs through
#: ``logging.getLogger(__name__)``, so all application records travel under this prefix.
APPLICATION_LOGGER = "cardioauth"


class _CollectRecords(logging.Handler):
    """Collects every record once, whichever attachment point it arrives by."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []
        self._seen: set[int] = set()

    def emit(self, record: logging.LogRecord) -> None:
        marker = id(record)
        if marker in self._seen:
            return
        self._seen.add(marker)
        self.records.append(record)


def application_loggers() -> list[logging.Logger]:
    """The ``cardioauth`` namespace logger and every application logger that exists now.

    Loggers created *during* the capture need no forcing: a new logger is enabled, inherits
    its level from ``cardioauth`` and propagates, so it is collected too.
    """
    namespace = logging.getLogger(APPLICATION_LOGGER)
    children = [
        logger
        for name, logger in logging.Logger.manager.loggerDict.items()
        if name.startswith(f"{APPLICATION_LOGGER}.") and isinstance(logger, logging.Logger)
    ]
    return [namespace, *children]


@contextmanager
def capture_application_logs() -> Iterator[list[logging.LogRecord]]:
    """Collect the application's log records for the duration of the ``with`` block."""
    handler = _CollectRecords()
    namespace = logging.getLogger(APPLICATION_LOGGER)
    root = logging.getLogger()

    previous = [(logger, logger.disabled, logger.level, logger.propagate) for logger in application_loggers()]
    previous_root_disabled = root.disabled
    previous_disable = logging.Logger.manager.disable

    for logger, *_ in previous:
        logger.disabled = False
        logger.setLevel(logging.NOTSET)
        logger.propagate = True
    namespace.setLevel(logging.DEBUG)
    root.disabled = False
    logging.disable(logging.NOTSET)

    namespace.addHandler(handler)
    root.addHandler(handler)
    try:
        yield handler.records
    finally:
        namespace.removeHandler(handler)
        root.removeHandler(handler)
        for logger, disabled, level, propagate in previous:
            logger.disabled = disabled
            logger.setLevel(level)
            logger.propagate = propagate
        root.disabled = previous_root_disabled
        logging.disable(previous_disable)
