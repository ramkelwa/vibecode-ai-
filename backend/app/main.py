"""VibeShield AI FastAPI application shell (Phase 1).

Phase 1 is intentionally minimal: health, persistence wiring, and an auth-ready
foundation. No scanner endpoints exist yet - scanner modules arrive in Phase 2.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import ai_provider, health, scan_artifacts, scan_risk, scans, virustotal
from app.core.config import settings
from app.core.database import init_db
from app.core.logging import get_logger
from app.report_routes import router as report_routes

logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Create tables on startup; a failed DB keeps the API up for health checks.
    try:
        init_db()
        logger.info("Database schema initialized")
    except Exception as exc:  # pragma: no cover - depends on environment
        logger.warning("Database initialization failed: %s", type(exc).__name__)
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix=settings.API_V1_PREFIX)
app.include_router(scans.router, prefix=settings.API_V1_PREFIX)
app.include_router(scan_artifacts.router, prefix=settings.API_V1_PREFIX)
app.include_router(scan_risk.router, prefix=settings.API_V1_PREFIX)
app.include_router(ai_provider.router, prefix=settings.API_V1_PREFIX)
app.include_router(virustotal.router, prefix=settings.API_V1_PREFIX)
app.mount("/api/reports", report_routes)
