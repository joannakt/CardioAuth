"""Database access: engine, session factory, declarative base and migration revision.

The authoritative schema is SQL (``cardioauth/db/sql/001_schema.sql``), applied by
Alembic. The ORM declares the tables the application reads and writes today;
``tests/test_schema_sync.py`` fails if the ORM and the migrated database ever disagree,
so the two cannot drift silently.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import MetaData, create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from cardioauth.settings import Settings, get_settings

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION, schema="cardioauth")


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine(settings: Settings | None = None) -> Engine:
    global _engine, _session_factory
    settings = settings or get_settings()
    if _engine is None:
        _engine = create_engine(
            settings.database_url,
            echo=settings.database_echo,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            connect_args={"connect_timeout": settings.database_connect_timeout_s},
            pool_pre_ping=True,
        )
        _session_factory = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def reset_engine() -> None:
    """Drop the cached engine (tests switching databases)."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None


def get_session_factory(settings: Settings | None = None) -> sessionmaker[Session]:
    get_engine(settings)
    assert _session_factory is not None
    return _session_factory


@contextmanager
def session_scope(settings: Settings | None = None) -> Iterator[Session]:
    session = get_session_factory(settings)()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def database_revision(engine: Engine | None = None) -> str | None:
    """Current Alembic revision, or None when the database has no baseline yet."""
    engine = engine or get_engine()
    with engine.connect() as conn:
        exists = conn.execute(
            text("SELECT to_regclass('public.alembic_version') IS NOT NULL")
        ).scalar_one()
        if not exists:
            return None
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()


def ping(engine: Engine | None = None) -> bool:
    engine = engine or get_engine()
    with engine.connect() as conn:
        return conn.execute(text("SELECT 1")).scalar_one() == 1
