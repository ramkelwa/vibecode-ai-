"""Health check helpers: real database connectivity probe (no guessing)."""

from __future__ import annotations

from typing import Any, Dict, Literal

from fastapi import APIRouter
from sqlalchemy import text

from app.core.config import settings
from app.core.database import engine

HealthState = Literal["ok", "unavailable"]

router = APIRouter()


def database_health() -> Dict[str, Any]:
    """Return {'state': 'ok'|'unavailable', 'detail': ...} based on a real probe."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"state": "ok", "detail": "database responded to SELECT 1"}
    except Exception as exc:
        # Any failure class (SQLAlchemyError, OSError, connection refused, ...)
        # must be reported honestly - never fabricate success.
        return {"state": "unavailable", "detail": type(exc).__name__}


@router.get("/health")
def health() -> Dict[str, Any]:
    db = database_health()
    return {
        "status": "ok",  # the API itself is up if this handler responds
        "app": settings.APP_NAME,
        "environment": settings.ENVIRONMENT,
        "database": db,
        "features": {
            "scans": db["state"] == "ok",
            "findings": db["state"] == "ok",
        },
    }
