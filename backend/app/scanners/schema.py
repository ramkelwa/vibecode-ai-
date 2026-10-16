"""Shared finding schema for all scanner modules.

Every module emits ``FindingData`` objects - the single normalized format
described in the project spec. Findings are produced ONLY from observed
evidence; a module must never invent a severity or an exploitation claim.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

SEVERITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCES = ("uncertain", "firm", "certain")
STATUSES = ("confirmed", "potential", "unverified", "false_positive", "informational")


def finding_id(*parts: Any) -> str:
    """Deterministic identifier from stable parts (module + asset + check)."""
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


@dataclass
class FindingData:
    title: str
    description: str
    category: str
    severity: str  # info|low|medium|high|critical
    confidence: str  # uncertain|firm|certain
    affected_asset: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    source_module: str = ""
    cwe: Optional[str] = None
    cve: Optional[str] = None
    impact: str = ""
    remediation: str = ""
    verification_status: str = "potential"
    scan_id: Optional[str] = None  # set by the orchestrator when persisted

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"invalid confidence: {self.confidence}")
        if self.verification_status not in STATUSES:
            raise ValueError(f"invalid verification_status: {self.verification_status}")
        if not self.source_module:
            raise ValueError("source_module is required")

    @property
    def id(self) -> str:
        return finding_id(self.source_module, self.affected_asset, self.title)

    def with_scan(self, scan_id: str) -> "FindingData":
        """Return a copy of this finding bound to a scan id."""
        import dataclasses

        return dataclasses.replace(self, scan_id=scan_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "affected_asset": self.affected_asset,
            "evidence": self.evidence,
            "source_module": self.source_module,
            "cwe": self.cwe,
            "cve": self.cve,
            "impact": self.impact,
            "remediation": self.remediation,
            "verification_status": self.verification_status,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
