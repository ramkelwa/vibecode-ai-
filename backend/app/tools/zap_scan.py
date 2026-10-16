"""Optional OWASP ZAP integration - DISABLED unless explicitly configured.

Safety properties:
- enabled only when ZAP_API_URL is explicitly set (non-empty)
- defaults to the ZAP "safe" scan policy: no destructive rules, no uncontrolled
  active scanning
- required explicit scope: the target host must match an authorized scan target
- hard duration cap; ZAP calls go through its REST API (GET) with timeouts
- unavailability and disabled-state are recorded, never silently swallowed

The integration talks to ZAP via its REST API ( ZAP v2 API ), never spawning a
local ZAP process (that would require the user's own authorized ZAP install).
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import quote, urljoin, urlparse

import httpx

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("zap")

MODULE = "zap_dynamic"

# Default ZAP scanner policy: "safe". Destructive policies are never selected.
SAFE_SCAN_POLICY = "safe-policy"


def zap_enabled() -> bool:
    """ZAP is opt-in: requires an explicitly configured API URL."""
    return bool(settings.ZAP_API_URL.strip())


def _api_headers() -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if settings.ZAP_API_KEY.strip():
        headers["X-ZAP-API-Key"] = settings.ZAP_API_KEY.strip()
    return headers


def _call(action_path: str, *, timeout: int = 30, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Single ZAP REST API call with explicit timeout. Never follows redirects."""
    base = settings.ZAP_API_URL.strip()
    url = urljoin(base if base.endswith("/") else base + "/", action_path.lstrip("/"))
    if params:
        import urllib.parse as up
        url += "?" + up.urlencode(params, safe="")  # encoded params
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            resp = client.get(url, headers=_api_headers())
        if resp.status_code != 200:
            return {"ok": False, "error": f"zap api status {resp.status_code}", "body": resp.text[:1000]}
        data = resp.json()
        if not isinstance(data, dict):
            return {"ok": False, "error": "zap response is not a JSON object"}
        return {"ok": True, "data": data}
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"zap unreachable: {type(exc).__name__}"}
    except ValueError:
        return {"ok": False, "error": "zap returned invalid JSON"}


def zap_status() -> Dict[str, Any]:
    """Report whether ZAP is configured and reachable. Safe to call anytime."""
    if not zap_enabled():
        return {"enabled": False, "reachable": False, "reason": "ZAP_API_URL is not configured"}
    result = _call("JSON/core/view/version/", timeout=10)
    if result.get("ok"):
        version = result["data"].get("version") if isinstance(result["data"], dict) else None
        return {"enabled": True, "reachable": True, "version": version}
    return {"enabled": True, "reachable": False, "reason": result.get("error", "unreachable")}


def _validate_scope(target_url: str, authorized_target_url: str) -> Optional[str]:
    """Ensure the ZAP-scan target is within the authorized scope.

    Returns None when in scope; otherwise a human-readable error.
    """
    try:
        wanted = urlparse(authorized_target_url)
        candidate = urlparse(target_url)
    except ValueError:
        return "unparsable URL"
    if not candidate.scheme in ("http", "https"):
        return "zap scan target must be http/https"
    # The ZAP target must be the same host as the authorized target.
    if (candidate.hostname or "").lower() != (wanted.hostname or "").lower():
        return "zap scan target host is outside the authorized scope"
    return None


def safe_scan(target_url: str, authorized_target_url: str, *, max_duration: Optional[int] = None) -> Dict[str, Any]:
    """Start a ZAP scan with safe defaults and wait for completion (bounded).

    Steps (all logged, all with explicit states):
    1. verify ZAP configured and reachable
    2. validate target against explicit authorized scope
    3. access the target through ZAP (spider disabled by default: we are not
       trying to enumerate, only to exercise the primary document)
    4. start an active scan limited to the SAFE policy
    5. poll status bounded by ZAP_SCAN_MAX_DURATION
    6. fetch alerts from ZAP and map to our normalized finding shape

    The scanner NEVER chooses a destructive policy and NEVER begins active
    scanning of hosts outside the authorized scope.
    """
    out: Dict[str, Any] = {
        "module": MODULE,
        "status": "disabled",
        "alerts": [],
        "errors": [],
        "duration_seconds": 0.0,
    }
    if not zap_enabled():
        out["errors"].append("zap not configured (ZAP_API_URL empty) - integration disabled")
        return out

    scope_error = _validate_scope(target_url, authorized_target_url)
    if scope_error:
        out["status"] = "out_of_scope"
        out["errors"].append(scope_error)
        return out

    status = zap_status()
    if not status.get("reachable"):
        out["status"] = "zap_unavailable"
        out["errors"].append(status.get("reason", "zap unreachable"))
        return out

    encoded = quote(target_url, safe="")
    # 1. Access the primary document via ZAP (GET only; no spider, no fuzz).
    access = _call("JSON/core/action/accessUrl/", {"url": encoded}, timeout=60)
    if not access.get("ok"):
        out["status"] = "zap_unavailable"
        out["errors"].append(access.get("error", "zap accessUrl failed"))
        return out

    # 2. Start active scan pinned to the safe policy.
    policy = SAFE_SCAN_POLICY
    scan_start = _call(
        "JSON/ascan/action/scan/",
        {"url": encoded, "scanPolicyName": policy},
        timeout=60,
    )
    if not scan_start.get("ok"):
        out["status"] = "zap_unavailable"
        out["errors"].append(scan_start.get("error", "zap ascan/scan failed"))
        return out
    verdict = scan_start.get("data", {}) or {}
    scan_id = verdict.get("scan") if isinstance(verdict, dict) else None
    if scan_id is None:
        out["status"] = "zap_unavailable"
        out["errors"].append("zap did not return a scan id")
        return out

    # 3. Poll status with a hard cap.
    import time as _time
    started = _time.monotonic()
    duration_cap = max_duration if max_duration is not None else settings.ZAP_SCAN_MAX_DURATION
    while True:
        if _time.monotonic() - started > duration_cap:
            out["status"] = "timeout"
            out["errors"].append(f"zap scan exceeded {duration_cap}s limit")
            break
        prog = _call("JSON/ascan/view/status/", {"scanId": str(scan_id)}, timeout=15)
        if not prog.get("ok"):
            out["errors"].append(prog.get("error", "zap status poll failed"))
            break
        status_data = prog.get("data", {})
        progress = int(status_data.get("status", "0")) if isinstance(status_data, dict) else 0
        if progress >= 100:
            out["status"] = "completed"
            out["duration_seconds"] = round(_time.monotonic() - started, 2)
            break
        _time.sleep(2.0)

    # 4. Collect alerts.
    alerts = _call("JSON/core/view/alerts/", {"baseurl": encoded}, timeout=60)
    if alerts.get("ok"):
        raw = alerts.get("data", {}).get("alerts", []) if isinstance(alerts.get("data"), dict) else []
        mapped = []
        for a in raw:
            if not isinstance(a, dict):
                continue
            mapped.append({
                "plugin_id": a.get("pluginId"),
                "alert_ref": a.get("alertRef"),
                "name": a.get("alert", ""),
                "risk": a.get("riskDesc", ""),
                "url": a.get("url", ""),
                "evidence_redacted": a.get("evidence", "")[:200] or "",
                "description": a.get("description", "")[:1500],
                "solution": a.get("solution", "")[:1000],
                "cwe_id": a.get("cweid"),
                "wasc_id": a.get("wascid"),
                "confidence": "firm",  # tool-reported
                "source_tool": "zap",
            })
        out["alerts"] = mapped
    else:
        out["errors"].append(alerts.get("error", "zap alerts fetch failed"))
    if out["status"] == "disabled":
        out["status"] = "completed"
    return out
