"""SQLAlchemy engine/session setup.

Runs on SQLite for local development and PostgreSQL in Docker, selected purely
by the DATABASE_URL environment variable - the same models work on both.
"""

from __future__ import annotations

from typing import Generator

from sqlalchemy import DateTime, JSON, Text, create_engine, event, inspect, text
from sqlalchemy.engine import Engine
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
    _upgrade_schema(engine)


def _upgrade_schema(bind: Engine) -> None:
    """Add columns introduced after the initial SQLite schema was created."""
    additions = {
        "scans": {
            "artifacts": (JSON(), "NOT NULL DEFAULT '{}'"),
        },
        "findings": {
            "ai_explanation": (Text(), ""),
            "ai_error": (Text(), ""),
            "ai_provider": (Text(), ""),
            "ai_generated_at": (DateTime(timezone=True), ""),
        },
    }
    with bind.begin() as connection:
        schema = inspect(connection)
        for table, columns in additions.items():
            existing = {column["name"] for column in schema.get_columns(table)}
            for name, (column_type, constraints) in columns.items():
                if name not in existing:
                    sql_type = column_type.compile(dialect=bind.dialect)
                    connection.execute(
                        text(
                            f'ALTER TABLE "{table}" ADD COLUMN "{name}" '
                            f"{sql_type} {constraints}"
                        )
                    )
