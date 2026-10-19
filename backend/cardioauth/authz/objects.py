"""Object resolvers — authorising *that* case / criteria version / user, not just the verb.

§7.3 is a role matrix, but a role that may "view a case" may only view cases of its own
practice. A global "does this role have this verb" check is therefore not enough: the
decision has to be made against a loaded row. :data:`OBJECT_SPECS` registers the object
types this milestone can authorise and, for each, how to find the practice that owns the row
and the user that produced it (for the ``own_actions`` scope). The dependency that uses them
lives in :mod:`cardioauth.authz.deps`.

Every loader returns the row or ``None``; it never raises "forbidden" by itself. The caller
decides the response, and the reason it chose is what gets audited.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final

from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from cardioauth.authz.permissions import Scope
from cardioauth.db.models import AppUser, AuditLog, CaseRecord, CriteriaSet, CriteriaSetVersion


def _load_case(session: Session, object_id: uuid.UUID) -> Any | None:
    return session.get(CaseRecord, object_id)


def _load_criteria_set_version(session: Session, object_id: uuid.UUID) -> Any | None:
    return session.get(CriteriaSetVersion, object_id)


def _load_app_user(session: Session, object_id: uuid.UUID) -> Any | None:
    return session.get(AppUser, object_id)


def _practice_of_row(_session: Session, row: Any) -> uuid.UUID | None:
    return getattr(row, "practice_id", None)


def _practice_of_criteria_version(session: Session, row: Any) -> uuid.UUID | None:
    """A version has no practice of its own; its set does. ``None`` means a shared library
    row (``criteria_set.scope = 'global'``), which is readable but never writable."""
    criteria_set = session.get(CriteriaSet, row.criteria_set_id)
    return None if criteria_set is None else criteria_set.practice_id


@dataclass(frozen=True, slots=True)
class ObjectSpec:
    """How to load an object type and find the practice (and actor) it belongs to."""

    object_type: str
    loader: Callable[[Session, uuid.UUID], Any | None]
    practice_id_of: Callable[[Session, Any], uuid.UUID | None]
    #: Who produced the row, for the ``own_actions`` scope. ``None`` means that scope cannot
    #: be satisfied for this object type, and therefore denies.
    owner_id_of: Callable[[Any], uuid.UUID | None] | None = None


OBJECT_SPECS: Final[Mapping[str, ObjectSpec]] = MappingProxyType(
    {
        "case": ObjectSpec("case", _load_case, _practice_of_row),
        "criteria_set_version": ObjectSpec(
            "criteria_set_version", _load_criteria_set_version, _practice_of_criteria_version
        ),
        "app_user": ObjectSpec(
            "app_user", _load_app_user, _practice_of_row, owner_id_of=lambda row: row.id
        ),
    }
)


def spec_for_object_type(object_type: str) -> ObjectSpec:
    try:
        return OBJECT_SPECS[object_type]
    except KeyError:
        raise KeyError(
            f"no authorisation spec for object type {object_type!r}; register one in "
            "cardioauth.authz.objects.OBJECT_SPECS before naming it in a permission"
        ) from None


def load_object(session: Session, object_type: str, object_id: uuid.UUID) -> Any | None:
    """Load the row, or ``None`` if it does not exist."""
    return spec_for_object_type(object_type).loader(session, object_id)


def practice_of(session: Session, object_type: str, row: Any) -> uuid.UUID | None:
    """The practice that owns this row (``None`` for a shared-library row)."""
    return spec_for_object_type(object_type).practice_id_of(session, row)


def scope_allows(*, scope: Scope, actor_user_id: uuid.UUID, spec: ObjectSpec, row: Any) -> bool:
    """The extra reach rules a grant can carry beyond "same practice".

    ``own_actions`` requires the row to have been produced by the actor. Everything else is
    decided by the caller, which is the only place that knows both practices.
    """
    if scope is Scope.OWN_ACTIONS:
        owner = spec.owner_id_of(row) if spec.owner_id_of is not None else None
        return owner is not None and owner == actor_user_id
    return True


def unscoped_object_allowed(*, practice_id: uuid.UUID | None, read_only: bool) -> bool:
    """A row with no owning practice is a shared-library row: readable, never writable."""
    return practice_id is None and read_only


def audit_scope_filter(
    *, scope: Scope, actor_user_id: uuid.UUID, practice_id: uuid.UUID | None
) -> ColumnElement[bool]:
    """The WHERE clause for listing audit rows under an ``audit.read`` grant (§7.3).

    A practice admin sees its own practice's log; a physician sees only rows it produced.
    Applied as a query filter rather than per-row, so a listing cannot leak a neighbouring
    practice's rows by accident.
    """
    if scope is Scope.OWN_ACTIONS:
        return AuditLog.actor_user_id == actor_user_id
    return AuditLog.practice_id == practice_id


__all__ = [
    "OBJECT_SPECS",
    "ObjectSpec",
    "audit_scope_filter",
    "load_object",
    "practice_of",
    "scope_allows",
    "spec_for_object_type",
    "unscoped_object_allowed",
]
