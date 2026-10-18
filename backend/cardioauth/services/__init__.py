"""Service layer boundaries (§1.1).

M1a ships the schema and the seams; the services below arrive with their milestones and
none of them exist yet, so nothing is stubbed into a shape that would let a caller believe
work happened:

* ``case_service``, ``ingest_service``          — M2
* ``extraction_service``                        — M4
* ``criteria_service``                          — M5 (the anti-hardcoding interpreter, INV-2)
* ``letter_service``, ``verification_service``  — M6
* ``tracker_service``                           — M2
* ``audit_service``                             — M1b (see :mod:`cardioauth.audit.service`)
* ``stats_service`` (eval/telemetry)            — M3
"""

from __future__ import annotations

PLANNED_SERVICES: tuple[str, ...] = (
    "case_service",
    "ingest_service",
    "extraction_service",
    "criteria_service",
    "letter_service",
    "verification_service",
    "tracker_service",
)
