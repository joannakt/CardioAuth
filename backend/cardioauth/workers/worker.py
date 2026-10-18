"""Worker entrypoint.

Dev runs jobs inline (``CARDIOAUTH_JOBS_INLINE=true``) so the stack stays small; the
``worker`` Compose service exists so that the production topology (§1.3) is reproduced
locally and so that OCR/extraction/verification have somewhere to run from M2 onward.

M1a registers no job handlers — there is no job table yet (it arrives with M2's ingest
pipeline, backed by Postgres). Rather than pretend to work, the worker states plainly
that it has nothing to do and idles, so ``docker compose up`` can start it and show a
truthful log line.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time

from cardioauth import __version__
from cardioauth.logging_setup import configure_logging
from cardioauth.settings import get_settings

logger = logging.getLogger("cardioauth.worker")

JOB_HANDLERS: dict[str, object] = {}  # populated in M2 (ingest) and later milestones

_stop = False


def _handle_signal(signum: int, _frame: object) -> None:
    global _stop
    _stop = True
    logger.info("worker.signal received=%s shutting down", signal.Signals(signum).name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CardioAuth worker")
    parser.add_argument("--once", action="store_true", help="check configuration and exit (no idle loop)")
    args = parser.parse_args(argv)

    settings = get_settings()
    settings.assert_runtime_safe()
    configure_logging(level=settings.log_level, fmt=settings.log_format, env=settings.cardioauth_env.value)

    logger.info(
        "worker.start version=%s env=%s handlers=%d jobs_inline=%s",
        __version__,
        settings.cardioauth_env.value,
        len(JOB_HANDLERS),
        settings.jobs_inline,
    )
    if not JOB_HANDLERS:
        logger.warning(
            "worker.idle no job handlers are registered in M1a: the Postgres-backed job table "
            "and the ingest/OCR/extraction/verification handlers arrive in M2 and later milestones"
        )

    if args.once:
        return 0

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    while not _stop:
        time.sleep(settings.worker_poll_interval_s)
    logger.info("worker.stop")
    return 0


if __name__ == "__main__":
    sys.exit(main())
