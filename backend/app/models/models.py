"""SQLAlchemy ORM models for VibeShield AI.

Phase 1 scope: users (auth-ready), scans, findings, endpoints, technologies,
dependencies. All scanner findings are stored with full traceability fields so
that a finding can always be traced back to the raw evidence that produced it.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), default="Analyst")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Project(Base):
    """A grouping of scans under one assessment engagement."""

    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    scans: Mapped[List[Scan]] = relationship(back_populates="project")


class Target(Base):
    """Registered scan target with explicit authorization record.

    A scan may only run against a Target whose authorization was confirmed.
    This is the persistence side of the allowlist control.
    """

    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    url: Mapped[str] = mapped_column(String(2048), unique=True)
    label: Mapped[str] = mapped_column(String(255), default="")
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    authorization_note: Mapped[str] = mapped_column(Text, default="")
    authorized_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[Optional[str]] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    project_id: Mapped[Optional[str]] = mapped_column(
        String(32), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True
    )
    target_url: Mapped[str] = mapped_column(String(2048))
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    # pending | running | completed | failed | cancelled
    modules_requested: Mapped[List[str]] = mapped_column(JSON, default=list)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    # Real module artifacts (inventories, parsed HTML summary, etc.).
    artifacts: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    findings: Mapped[List["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    project: Mapped[Optional[Project]] = relationship(back_populates="scans")
    stages: Mapped[List[ScanStage]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ScanStage(Base):
    """Per-module execution record for a scan (status per pipeline stage)."""

    __tablename__ = "scan_stages"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    module: Mapped[str] = mapped_column(String(64))
    # pending | running | completed | failed | skipped
    status: Mapped[str] = mapped_column(String(32), default="pending")
    detail: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="stages")


class Finding(Base):
    """Normalized finding record produced exclusively by real scanner modules."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(16), default="low")
    affected_asset: Mapped[str] = mapped_column(String(2048), default="")
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    source_module: Mapped[str] = mapped_column(String(64))
    cwe: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    cve: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    impact: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    verification_status: Mapped[str] = mapped_column(
        String(32), default="potential"
    )  # confirmed | potential | unverified | false_positive | informational
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    # Phase 7: optional AI-assisted explanation, grounded in stored evidence.
    # Stored separately from the raw finding so the UI can distinguish
    # scanner evidence from AI-generated interpretation.
    ai_explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_provider: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ai_generated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class Endpoint(Base):
    """API endpoint discovered by a scan (URL + method inventory)."""

    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    url: Mapped[str] = mapped_column(String(2048))
    method: Mapped[str] = mapped_column(String(10), default="GET")
    source: Mapped[str] = mapped_column(String(64), default="http_headers")
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Technology(Base):
    """Technology fingerprint detected from real response headers/body."""

    __tablename__ = "technologies"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    category: Mapped[str] = mapped_column(String(64), default="server")
    source: Mapped[str] = mapped_column(String(64), default="http_headers")
    confidence: Mapped[str] = mapped_column(String(16), default="medium")


class Dependency(Base):
    """A dependency entry parsed from a manifest/lockfile provided by the user."""

    __tablename__ = "dependencies"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(64), default="")
    ecosystem: Mapped[str] = mapped_column(String(32), default="npm")
    # CVE fields are only populated by a real advisory source, never guessed.
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    raw_advisories: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list)
