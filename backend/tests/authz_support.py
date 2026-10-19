"""Shared fixtures and helpers for the M1b-2 authorisation tests.

Synthetic data only: two practices, three accounts each, obviously fake addresses and
passwords, and no clinical content anywhere. Every account, case and criteria set created
here is deleted at the end of the test; audit rows are append-only by design and are queried
by actor instead.

The helpers exist so a test can say "sign in as the physician of practice B, step up, ask for
practice A's case" in one line, which is the shape every §7.3 test needs.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import pyotp
import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from cardioauth.settings import get_settings

PRACTICES = ("a", "b")
ROLES = ("coordinator", "physician", "admin")

#: Values a constrained grant needs. The matrix test passes these so that a denial it observes
#: is about the *role*, never about a missing fact.
SATISFYING_FACTS: dict[str, Any] = {
    "letter_kind": "p2p_summary",  # the one kind every role may generate (§7.3)
    "signer_npi_present": True,
    "covering_physician_attestation": True,
    "reason_present": True,
}

PASSWORDS = {
    "coordinator": "authz-c00rdinator-Passphrase-01",
    "physician": "authz-physician-Passphrase-02",
    "admin": "authz-adm1n-Passphrase-03",
}


def totp_code(secret: str, *, offset: int = 0) -> str:
    settings = get_settings()
    step = settings.totp_period_seconds
    moment = int(time.time() // step + offset) * step
    return pyotp.TOTP(secret, digits=settings.totp_digits, interval=step).at(moment)


@dataclass
class Account:
    practice: str
    role: str
    user_id: uuid.UUID
    email: str
    password: str
    secret: str | None = None


class TotpClock:
    """A controllable clock for the TOTP verifier.

    The verifier accepts +-1 step (``settings.totp_drift_steps``) and refuses a code it has
    already seen for that step, so a test that needs a second code has to move the clock
    rather than reuse a step. Advancing whole steps keeps every code inside the drift window.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cardioauth.security import totp as totp_module

        self._period = get_settings().totp_period_seconds
        self._base = time.time()
        self._steps = 0
        monkeypatch.setattr(totp_module.time, "time", self._now)

    def _now(self) -> float:
        return self._base + self._steps * self._period

    def advance(self, steps: int = 1) -> None:
        self._steps += steps

    def code(self, secret: str) -> str:
        settings = get_settings()
        moment = int(self._now() // self._period) * self._period
        return pyotp.TOTP(secret, digits=settings.totp_digits, interval=self._period).at(moment)


def make_totp_clock(monkeypatch: pytest.MonkeyPatch) -> TotpClock:
    return TotpClock(monkeypatch)


@dataclass
class World:
    practices: dict[str, uuid.UUID]
    accounts: dict[tuple[str, str], Account]
    cases: dict[str, uuid.UUID]
    criteria_versions: dict[str, uuid.UUID]
    procedure_id: uuid.UUID
    payer_id: uuid.UUID
    extra: dict[str, Any] = field(default_factory=dict)

    def account(self, practice: str, role: str) -> Account:
        return self.accounts[(practice, role)]

    @property
    def practice_ids(self) -> tuple[uuid.UUID, ...]:
        return tuple(self.practices.values())


def _insert_world(engine, suffix: str) -> World:  # noqa: ANN001
    from cardioauth.security import passwords

    settings = get_settings()
    practices = {name: uuid.uuid4() for name in PRACTICES}
    procedure_id, payer_id = uuid.uuid4(), uuid.uuid4()
    accounts: dict[tuple[str, str], Account] = {}
    cases: dict[str, uuid.UUID] = {}
    criteria_versions: dict[str, uuid.UUID] = {}

    with Session(engine) as session:
        for name, practice_id in practices.items():
            session.execute(
                text("INSERT INTO cardioauth.practice (id, name) VALUES (:id, :name)"),
                {"id": practice_id, "name": f"TEST-ONLY Practice {name.upper()} {suffix}"},
            )
        session.execute(
            text(
                "INSERT INTO cardioauth.procedure (id, code, display_name, cpt_codes, modality, fact_fields) "
                "VALUES (:id, :code, :name, :cpt, :modality, '{}')"
            ),
            {
                "id": procedure_id,
                "code": f"test-only-authz-{suffix}",
                "name": "TEST-ONLY Procedure",
                "cpt": ["0000T"],
                "modality": "echo",
            },
        )
        session.execute(
            text("INSERT INTO cardioauth.payer (id, name, payer_type) VALUES (:id, :name, 'commercial')"),
            {"id": payer_id, "name": f"TEST-ONLY-PAYER-{suffix}"},
        )

        for name, practice_id in practices.items():
            for role in ROLES:
                user_id = uuid.uuid4()
                email = f"authz-{name}-{role}-{suffix}@test-only.invalid"
                session.execute(
                    text(
                        "INSERT INTO cardioauth.app_user "
                        "(id, practice_id, email, password_hash, full_name, role, npi) "
                        "VALUES (:id, :practice_id, :email, :password_hash, :full_name, :role, :npi)"
                    ),
                    {
                        "id": user_id,
                        "practice_id": practice_id,
                        "email": email,
                        "password_hash": passwords.hash_password(PASSWORDS[role], settings=settings),
                        "full_name": f"TEST-ONLY {role} {name}",
                        "role": role,
                        # The physician NPI precondition (§7.3 "physician NPI required") is
                        # satisfied by this synthetic value; the precondition *fact* is what
                        # the authoriser checks, not this column.
                        "npi": "0000000000" if role == "physician" else None,
                    },
                )
                accounts[(name, role)] = Account(
                    practice=name, role=role, user_id=user_id, email=email, password=PASSWORDS[role]
                )

            coordinator_id = accounts[(name, "coordinator")].user_id
            case_id = uuid.uuid4()
            session.execute(
                text(
                    "INSERT INTO cardioauth.case_record (id, practice_id, case_number, patient_ref, "
                    "patient_display, procedure_code_id, payer_id, cpt_code, created_by) "
                    "VALUES (:id, :practice_id, :number, :ref, '{}'::jsonb, :procedure, :payer, '0000T', "
                    ":created_by)"
                ),
                {
                    "id": case_id,
                    "practice_id": practice_id,
                    "number": f"AUTHZ-{name.upper()}-0001",
                    "ref": f"SYNTH-{name.upper()}-0001",
                    "procedure": procedure_id,
                    "payer": payer_id,
                    "created_by": coordinator_id,
                },
            )
            cases[name] = case_id

            set_id, version_id = uuid.uuid4(), uuid.uuid4()
            session.execute(
                text(
                    "INSERT INTO cardioauth.criteria_set "
                    "(id, key, name, procedure_code_id, payer_id, scope, practice_id, created_by) "
                    "VALUES (:id, :key, :name, :procedure, :payer, 'practice', :practice_id, :created_by)"
                ),
                {
                    "id": set_id,
                    "key": f"test-only-authz-{name}-{suffix}",
                    "name": f"TEST-ONLY criteria set {name}",
                    "procedure": procedure_id,
                    "payer": payer_id,
                    "practice_id": practice_id,
                    "created_by": accounts[(name, "admin")].user_id,
                },
            )
            session.execute(
                text(
                    "INSERT INTO cardioauth.criteria_set_version "
                    "(id, criteria_set_id, version_no, status, source_citation, effective_from, fingerprint) "
                    "VALUES (:id, :set_id, 1, 'draft', '{\"doc_name\":\"TEST-ONLY\"}', DATE '2026-01-01', "
                    ":fingerprint)"
                ),
                {"id": version_id, "set_id": set_id, "fingerprint": f"test-only-{suffix}-{name}"},
            )
            criteria_versions[name] = version_id

        # A shared-library set (no owning practice): readable by everyone, writable by nobody.
        global_set_id, global_version_id = uuid.uuid4(), uuid.uuid4()
        session.execute(
            text(
                "INSERT INTO cardioauth.criteria_set "
                "(id, key, name, procedure_code_id, payer_id, scope, created_by) "
                "VALUES (:id, :key, :name, :procedure, :payer, 'global', :created_by)"
            ),
            {
                "id": global_set_id,
                "key": f"test-only-authz-global-{suffix}",
                "name": "TEST-ONLY global criteria set",
                "procedure": procedure_id,
                "payer": payer_id,
                "created_by": accounts[("a", "admin")].user_id,
            },
        )
        session.execute(
            text(
                "INSERT INTO cardioauth.criteria_set_version "
                "(id, criteria_set_id, version_no, status, source_citation, effective_from, fingerprint) "
                "VALUES (:id, :set_id, 1, 'draft', '{\"doc_name\":\"TEST-ONLY\"}', DATE '2026-01-01', "
                ":fingerprint)"
            ),
            {"id": global_version_id, "set_id": global_set_id, "fingerprint": f"test-only-{suffix}-global"},
        )
        criteria_versions["global"] = global_version_id
        session.commit()

    return World(
        practices=practices,
        accounts=accounts,
        cases=cases,
        criteria_versions=criteria_versions,
        procedure_id=procedure_id,
        payer_id=payer_id,
        extra={"suffix": suffix, "global_set_id": global_set_id},
    )


def _delete_world(engine, world: World) -> None:  # noqa: ANN001
    practice_ids = list(world.practice_ids)
    with Session(engine) as session:
        session.execute(
            text("DELETE FROM cardioauth.user_session WHERE user_id IN "
                 "(SELECT id FROM cardioauth.app_user WHERE practice_id = ANY(:ids))"),
            {"ids": practice_ids},
        )
        session.execute(
            text("DELETE FROM cardioauth.case_record WHERE practice_id = ANY(:ids)"),
            {"ids": practice_ids},
        )
        session.execute(
            text(
                "DELETE FROM cardioauth.criteria_set_version WHERE criteria_set_id IN "
                "(SELECT id FROM cardioauth.criteria_set WHERE practice_id = ANY(:ids) "
                " OR key LIKE :pattern)"
            ),
            {"ids": practice_ids, "pattern": f"test-only-authz-global-{world.extra['suffix']}"},
        )
        session.execute(
            text(
                "DELETE FROM cardioauth.criteria_set WHERE practice_id = ANY(:ids) OR key LIKE :pattern"
            ),
            {"ids": practice_ids, "pattern": f"test-only-authz-global-{world.extra['suffix']}"},
        )
        session.execute(
            text("DELETE FROM cardioauth.app_user WHERE practice_id = ANY(:ids)"), {"ids": practice_ids}
        )
        session.execute(
            text("DELETE FROM cardioauth.practice WHERE id = ANY(:ids)"), {"ids": practice_ids}
        )
        session.execute(
            text("DELETE FROM cardioauth.procedure WHERE id = :id"), {"id": world.procedure_id}
        )
        session.execute(text("DELETE FROM cardioauth.payer WHERE id = :id"), {"id": world.payer_id})
        session.commit()


def create_world(engine) -> World:  # noqa: ANN001
    """Two practices, three accounts each, one case and one criteria version per practice."""
    return _insert_world(engine, uuid.uuid4().hex[:10])


def destroy_world(engine, world: World) -> None:  # noqa: ANN001
    _delete_world(engine, world)


def build_probe_app():  # noqa: ANN201
    """The real application plus the test-only probe routes, built fresh per test."""
    from cardioauth.api.main import create_app
    from tests.authz_probe import build_probe_router

    app = create_app()
    app.include_router(build_probe_router())
    return app


# ---------------------------------------------------------------------------
# Signing in
# ---------------------------------------------------------------------------
def sign_in(client, account: Account, clock: TotpClock):  # noqa: ANN001, ANN201
    """Log in as ``account`` and leave the client holding a fully authenticated session.

    A role that must have a second factor (physician, admin) enrols one here, because §7.1
    will not let it reach a protected route without it — which is itself part of what these
    tests exercise.
    """
    response = client.post("/api/auth/login", json={"email": account.email, "password": account.password})
    assert response.status_code == 200, response.text
    state = response.json()
    if state.get("totp_enrolment_required"):
        enrolment = client.post("/api/auth/totp/enrol")
        assert enrolment.status_code == 200, enrolment.text
        account.secret = str(enrolment.json()["otpauth"]["secret"])
        activated = client.post("/api/auth/totp/activate", json={"code": clock.code(account.secret)})
        assert activated.status_code == 200, activated.text
        clock.advance()  # activation spent this step; the next code must be a different one
    elif state.get("totp_enrolled") and not state.get("two_factor_verified"):
        assert account.secret is not None
        clock.advance()
        verified = client.post("/api/auth/2fa/verify", json={"code": clock.code(account.secret)})
        assert verified.status_code == 200, verified.text
    me = client.get("/api/auth/me")
    assert me.status_code == 200, me.text
    return client


def step_up(client, account: Account, clock: TotpClock) -> None:
    """Perform the §7.2 step-up through the real endpoint (no test-only back door)."""
    payload: dict[str, Any] = {"password": account.password}
    if account.secret is not None:
        clock.advance()
        payload["code"] = clock.code(account.secret)
    response = client.post("/api/auth/step-up", json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["reauth_required"] is False


# ---------------------------------------------------------------------------
# Audit assertions
# ---------------------------------------------------------------------------
def audit_rows(engine, *, actor_user_id: uuid.UUID, action: str = "authz.denied") -> list[dict[str, Any]]:  # noqa: ANN001
    with engine.connect() as conn:
        result = conn.execute(
            text(
                "SELECT action, object_type, object_id, case_id, outcome, detail, actor_role, practice_id, "
                "session_id FROM cardioauth_audit.audit_log "
                "WHERE actor_user_id = :actor AND action = :action ORDER BY id"
            ),
            {"actor": actor_user_id, "action": action},
        )
        return [dict(row._mapping) for row in result]


def chain_verifies(engine) -> tuple[int, int]:  # noqa: ANN001
    """Verify the whole audit hash chain after a denial (a denial must not break the chain)."""
    from cardioauth.audit.chain import verify_chain

    with engine.connect() as conn:
        return verify_chain(conn)


__all__ = [
    "PASSWORDS",
    "PRACTICES",
    "ROLES",
    "SATISFYING_FACTS",
    "Account",
    "TotpClock",
    "World",
    "audit_rows",
    "build_probe_app",
    "chain_verifies",
    "create_world",
    "destroy_world",
    "make_totp_clock",
    "sign_in",
    "step_up",
    "totp_code",
]
