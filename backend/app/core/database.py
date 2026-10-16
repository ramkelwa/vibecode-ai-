"""SQLAlchemy engine/session setup.

Runs on SQLite for local development and PostgreSQL in Docker, selected purely
by the DATABASE_URL environment variable - the same models work on both.
"""

from __future__ import annotations

from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def _build_engine():
    url = settings.DATABASE_URL
    if settings.is_sqlite:
        engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            future=True,
        )

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, _record):  # pragma: no cover
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

        return engine

    # PostgreSQL / other server backends use a pooled connection.
    return create_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=20, future=True)


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables. Import models so they register on the metadata."""
    from app import models  # noqa: F401  (ensures mappers are configured)

    Base.metadata.create_all(bind=engine)
