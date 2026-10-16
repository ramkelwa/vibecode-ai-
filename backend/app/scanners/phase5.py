"""Phase 5: finding normalization, evidence-preserving deduplication,
cautious correlation, and deterministic risk prioritization.

This module is a pure post-processing engine. It consumes finding records
(the same dicts produced by ``FindingData.to_dict()`` or stored on the
``Finding`` ORM rows) and never talks to the network, executes anything, or
re DERIVES evidence that the Phase 1-4 modules did not observe.

Core rules honored here:
- severity and confidence are separate fields and never re-derived from each
  other; unknown/missing values are marked ``unknown`` instead of guessed
- no CVSS or any other score is invented
- deduplication merges only identical observations and keeps ALL contributing
  source modules; findings are never merged merely for sharing a title
- correlation adds context links between findings; it never upgrades weak
  evidence to a stronger verification status
- the risk priority formula is a documented, deterministic heuristic - a
  review-ordering aid, not a probability, not a CVSS, and never presented as
  a single opaque score (the formula travels with every summary)
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from app.scanners.schema import finding_id

# ---------------------------------------------------------------------------
# Normalization tables
# ---------------------------------------------------------------------------

# Canonical categories as produced by the Scan modules/Phase 4.
KNOWN_CATEGORIES = {
    "url_validation", "dns_analysis", "tls_analysis", "http_headers",
    "cookie_analysis", "html_analysis", "js_discovery", "js_analysis",
    "api_discovery", "dependency_audit", "source_analysis", "zap_dynamic",
}

# Aliases seen across tool ecosystems -> canonical category.
CATEGORY_ALIASES: Dict[str, str] = {
    "js": "js_analysis", "javascript": "js_analysis",
    "headers": "http_headers", "header": "http_headers",
    "tls": "tls_analysis", "ssl": "tls_analysis", "certificates": "tls_analysis",
    "cookies": "cookie_analysis", "cookie": "cookie_analysis",
    "dns": "dns_analysis",
    "urls": "url_validation", "url": "url_validation", "redirects": "url_validation",
    "html": "html_analysis",
    "assets": "js_discovery", "js_assets": "js_discovery", "scripts": "js_discovery",
    "apis": "api_discovery", "api": "api_discovery", "endpoints": "api_discovery",
    "dependencies": "dependency_audit", "deps": "dependency_audit", "dependency": "dependency_audit",
    "src": "source_analysis", "source": "source_analysis", "sast": "source_analysis",
    "zap": "zap_dynamic", "dynamic": "zap_dynamic",
}

KNOWN_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
SEVERITY_ALIASES: Dict[str, str] = {
    "informational": "info", "info": "info", "none": "info", "note": "info",
    "minor": "low", "low": "low", "negligible": "low",
    "moderate": "medium", "medium": "medium", "med": "medium", "mid": "medium",
    "important": "high", "major": "high", "high": "high", "severe": "high",
    "critical": "critical", "catastrophic": "critical",
    "unspecified": "unknown", "unknown": "unknown", "": "unknown", "n/a": "unknown",
}

KNOWN_CONFIDENCES = {"uncertain", "firm", "certain", "unknown"}
CONFIDENCE_ALIASES: Dict[str, str] = {
    "certain": "certain", "confirmed": "certain", "definite": "certain",
    "firm": "firm", "likely": "firm", "probable": "firm", "high": "firm", "medium": "firm",
    "uncertain": "uncertain", "possible": "uncertain", "low": "uncertain",
    "candidate": "uncertain", "guess": "uncertain",
    "unspecified": "unknown", "unknown": "unknown", "": "unknown", "n/a": "unknown",
}

# Verification-status tiering used when merging duplicates: the merged
# record keeps the MOST CONSERVATIVE (weakest claim) status observed,
# while both raw statuses are preserved in evidence.
_STATUS_VISIBLE_ORDER = {
    "confirmed": 5, "potential": 4, "unverified": 3,
    "informational": 2, "false_positive": 1, "unknown": 0,
}

def _normalize_asset(raw: Any) -> Tuple[str, bool, str]:
    """Standardize an asset identifier without losing path/query context.

    URL assets: scheme+host lowercased, default ports (80/443) dropped, and
    only the non-navigable fragment removed. Path and query case is
    preserved (signed/query URLs can be case-sensitive). Non-URL assets
    (project paths) keep their case; trailing whitespace is stripped.
    """
    asset = raw if isinstance(raw, str) else str(raw or "")
    original = asset
    asset = asset.strip()
    try:
        parts = urlsplit(asset)
    except ValueError:
        parts = None
    if parts is not None and parts.scheme.lower() in ("http", "https") and parts.netloc:
        scheme = parts.scheme.lower()
        host = parts.netloc.lower()
        try:
            port = parts.port
        except ValueError:
            port = None
        if port in (80, 443) and host.endswith(f":{port}"):
            host = host[: -len(f":{port}")]
        # path defaults to "/" so the site root stays comparable;
        # query kept verbatim; fragment dropped (client-only, server-invisible)
        asset = " ".join(urlunsplit((scheme, host, parts.path or "/", parts.query, "")).split())
    elif asset and ":" in asset and "\\" in asset:
        # local project paths: forward slashes for portability
        asset = asset.replace("\\", "/")
    return asset, asset != original, original


def normalize_asset(raw: str) -> Dict[str, Any]:
    """Public shape used by callers: canonical key + preserved original."""
    canonical, changed, original = _normalize_asset(raw)
    return {"asset": canonical, "original": original, "changed": changed}


def normalize_category(raw: Any) -> Tuple[str, str, bool]:
    """Return (normalized, original, recognized) for a category label."""
    original = raw if isinstance(raw, str) else str(raw or "")
    text = original.strip().lower()
    known = text in KNOWN_CATEGORIES
    if known:
        return text, original, True
    aliased = CATEGORY_ALIASES.get(text)
    if aliased:
        return aliased, original, True
    # Unknown category labels are kept verbatim, with a recognition flag -
    # normalization must not drop a finding nor invent a category for it.
    if not text:
        return "uncategorized", original, False
    return text, original, False


def normalize_severity(raw: Any) -> Tuple[str, str]:
    """Return (normalized, original); unknown/missing/unspecified -> 'unknown'."""
    original = raw if isinstance(raw, str) else ("" if raw is None else str(raw))
    text = original.strip().lower()
    return SEVERITY_ALIASES.get(text, "unknown"), original


def normalize_confidence(raw: Any) -> Tuple[str, str]:
    original = raw if isinstance(raw, str) else ("" if raw is None else str(raw))
    text = original.strip().lower()
    return CONFIDENCE_ALIASES.get(text, "unknown"), original


def normalize_title(raw: Any) -> str:
    title = raw if isinstance(raw, str) else str(raw or "")
    return " ".join(title.split()).strip()


# ---------------------------------------------------------------------------
# Normalization of finding structures
# ---------------------------------------------------------------------------

def normalize_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize ONE finding dict.

    Returns a normalized record with:
    - ``normalized_category`` / ``original_category`` / ``category_recognized``
    - ``severity`` / ``severity_raw`` and ``confidence`` / ``confidence_raw``
      (never cross-derived; ``unknown`` when the source gave nothing usable)
    - ``affected_asset`` canonicalized with the original preserved
    - the source module and every evidence key preserved
    Raises ``ValueError`` only when the structure is unusable; callers should
    route malformed records into an error list (see ``normalize_all``).
    """
    if not isinstance(raw, dict):
        raise ValueError("finding is not an object")
    title = normalize_title(raw.get("title"))
    if not title:
        raise ValueError("finding has no usable title")

    category, original_category, recognized = normalize_category(raw.get("category"))
    if not original_category:
        raise ValueError("finding has no category")
    severity, severity_raw = normalize_severity(raw.get("severity"))
    confidence, confidence_raw = normalize_confidence(raw.get("confidence"))
    asset = raw.get("affected_asset")
    if isinstance(asset, str) and asset.strip():
        canonical_asset, asset_changed, asset_original = _normalize_asset(asset)
    else:
        canonical_asset, asset_changed, asset_original = "", False, ""

    evidence = raw.get("evidence")
    evidence = dict(evidence) if isinstance(evidence, dict) else {}

    source_module = raw.get("source_module")
    source_module = source_module if isinstance(source_module, str) else str(source_module or "")

    status = raw.get("verification_status")
    status = status if isinstance(status, str) and status.strip() else "unverified"
    identity = str(finding_id(status, category, canonical_asset, title))
    identity = str(finding_id(status, category, canonical_asset, title))
    norm_record: Dict[str, Any] = {
        "id": identity,
        "title": title,
        "category": category,
        "original_category": original_category,
        "category_recognized": recognized,
        "severity": severity,
        "severity_raw": severity_raw if severity_raw else "",
        "confidence": confidence,
        "confidence_raw": confidence_raw if confidence_raw else "",
        "verification_status": status,
        "affected_asset": canonical_asset,
        "asset_original": asset_original,
        "asset_changed": asset_changed,
        "evidence": evidence,
        "source_module": source_module,
        "cwe": raw.get("cwe"),
        "cve": raw.get("cve"),
        "remediation": raw.get("remediation", ""),
        "impact": raw.get("impact", ""),
    }
    # Preserve every other original field under a guarded namespace so the
    # raw scanner payload is never lost.
    norm_record["originals"] = {
        str(k): v for k, v in raw.items()
        if isinstance(k, str) and k not in norm_record
    }
    return norm_record


def normalize_all(
    raws: Iterable[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Normalize many findings; malformed records come back as errors.

    Malformed tool output degrades to the ``errors`` list with a reason -
    it never crashes the engine and never silently disappears.
    """
    normalized: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    for index, raw in enumerate(raws):
        try:
            normalized.append(normalize_finding(raw))
        except (ValueError, TypeError) as exc:
            errors.append({
                "index": index,
                "reason": str(exc),
                "finding_preview": (
                    {k: (str(v)[:120] if isinstance(v, str) else v)
                     for k, v in list(raw.items())[:6]}
                    if isinstance(raw, dict) else str(raw)[:200]
                ),
            })
    return normalized, errors


# ---------------------------------------------------------------------------
# Deduplication (evidence-preserving)
# ---------------------------------------------------------------------------


def _merged_evidence(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two evidence maps field-by-field; collisions collapse to lists."""
    out = dict(a)
    for k, v in (b or {}).items():
        if k not in out:
            out[k] = v
        elif out[k] == v:
            continue
        else:
            merged = out[k]
            if isinstance(merged, list):
                if v not in merged:
                    merged = merged + [v]
            else:
                merged = [merged, v]
            out[k] = merged
    return out

def _dedup_key(f: Dict[str, Any]) -> Tuple[Any, ...]:
    """Identity key for merge decisions.

    Includes asset, title, cwe, and CVE (with helper for cve), keeping distinct
    assets and different titles SEPARATE. Two findings sharing only a title
    but differing in asset, category, cwe, or cve are NOT duplicates.
    """
    cve = f.get("cve")
    cve_key = str(cve) if cve else ""
    cwe = f.get("cwe")
    cwe_key = str(cwe) if cwe else ""
    # Merge cve into same key namespace...
    return (
        f["category"],
        f["affected_asset"],
        f["title"],
        cwe_key,
        cve_key,
    )


def _conservative_status(statuses: List[str]) -> str:
    seen = [s for s in statuses if s]
    # weakest claim wins for a merged record (never upgrades evidence)
    return min(seen, key=lambda s: _STATUS_VISIBLE_ORDER.get(s, -1)) if seen else "unverified"


def deduplicate_findings(
    findings: List[Dict[str, Any]],
    *,
    input_order: str = "normalized_key_sort",
) -> Dict[str, Any]:
    """Deterministically merge deduplicate identical observations.

    Ordering is fully deterministic: input is processed in the order given
    (caller may pre-sort; default helper sorts by identity key). Output has
    every contributing source module and every meaningful evidence field and
    original finding id preserved.

    Returns {"findings": [...], "duplicate_groups": n, "inputs": n}
    """
    prepped = sorted(findings, key=lambda f: (f["category"], f["affected_asset"], f["title"], f["id"]))
    groups: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = {}
    for f in prepped:
        groups.setdefault(_dedup_key(f), []).append(f)

    out: List[Dict[str, Any]] = []
    for members in groups.values():
        # Fully deterministic member order even when ids tie (identical
        # observations): canonical, order-independent tie-breaking on the
        # preserved non-schema originals.
        members.sort(
            key=lambda f: (
                f["id"],
                json.dumps(f.get("originals", {}), sort_keys=True, default=str),
            )
        )
        first, rest = members[0], members[1:]
        if not rest:
            out.append(_shaped(first, [], [], []))
            continue
        sources: List[str] = []
        original_ids: List[str] = []
        merged_evidence = dict(first["evidence"])
        severity_raws = [first["severity_raw"]] if first["severity_raw"] else []
        statuses = [first["verification_status"]]
        confidences = [first["confidence_raw"]] if first["confidence_raw"] else []
        for other in rest:
            if other["source_module"] and other["source_module"] not in sources:
                sources.append(other["source_module"])
            original_ids.append(other["id"])
            merged_evidence = _merged_evidence(merged_evidence, other["evidence"])
            if other["severity_raw"]:
                severity_raws.append(other["severity_raw"])
            statuses.append(other["verification_status"])
            if other["confidence_raw"]:
                confidences.append(other["confidence_raw"])
        if first["source_module"] and first["source_module"] not in sources:
            sources.insert(0, first["source_module"])
        merged = dict(first)
        merged["evidence"] = merged_evidence
        merged["source_modules"] = sources
        merged["contributing_original_ids"] = original_ids
        merged["verification_status"] = _conservative_status(statuses)
        if severity_raws:
            merged["evidence"]["observed_severity_labels"] = severity_raws
            # Conflicting severity labels on the SAME observation: the merged
            # record carries the most severe scanner-reported label, with
            # every raw label preserved in evidence (nothing invented).
            most_severe = max(
                members,
                key=lambda f: SEVERITY_WEIGHT.get(f["severity"], SEVERITY_WEIGHT["unknown"]),
            )
            merged["severity"] = most_severe["severity"]
            merged["evidence"]["severity_basis"] = (
                f"most severe of scanner-reported labels: {severity_raws}"
            )
        if len(confidences) > 1:
            merged["evidence"]["observed_confidence_labels"] = confidences
        out.append(_shaped(merged, sources, original_ids, statuses))

    duplicate_groups = sum(1 for m in out if len(m.get("contributing_original_ids", [])) > 0)
    # Deterministic output order regardless of caller input order.
    out.sort(key=lambda m: (m["category"], m["affected_asset"], m["title"], m["id"]))
    return {"findings": out, "inputs": len(findings), "duplicate_groups": duplicate_groups}


def _shaped(f: Dict[str, Any], sources: List[str], original_ids: List[str],
            statuses: List[str]) -> Dict[str, Any]:
    shaped = dict(f)
    shaped["source_modules"] = sources or ([f["source_module"]] if f["source_module"] else [])
    shaped["contributing_original_ids"] = original_ids
    return shaped


# ---------------------------------------------------------------------------
# Risk priority formula (documented heuristic)
# ---------------------------------------------------------------------------
#   priority = SEVERITY_WEIGHT[severity]
#            * CONFIDENCE_WEIGHT[confidence]
#            * VERIFICATION_WEIGHT[verification_status]     -> 0.0 .. 100
#
# Weights (documented here for the UI and README; stable by contract):
SEVERITY_WEIGHT = {"critical": 100, "high": 75, "medium": 50, "low": 25,
                   "info": 10, "unknown": 15}
CONFIDENCE_WEIGHT = {"certain": 1.0, "firm": 0.85, "uncertain": 0.6, "unknown": 0.5}
VERIFICATION_WEIGHT = {"confirmed": 1.0, "potential": 0.9, "unverified": 0.7,
                       "informational": 0.4, "false_positive": 0.05, "unknown": 0.3}

FORMULA_NAME = "vibeshield-phase5-priority-1"
FORMULA_EXPRESSION = (
    "priority = severity_weight(severity) * confidence_weight(confidence) "
    "* verification_weight(verification_status), severity_weight: critical=100 "
    "high=75 medium=50 low=25 info=10 unknown=15; confidence_weight: certain=1.0 "
    "firm=0.85 uncertain=0.6 unknown=0.5; verification_weight: confirmed=1.0 "
    "potential=0.9 unverified=0.7 informational=0.4 false_positive=0.05 unknown=0.3"
)
# known limitations, surfaced with every summary (not a probability, not CVSS)
FORMULA_LIMITATIONS = [
    "Linear heuristic over reported labels; it is a review-ordering aid, not a vulnerability score or an exploit probability.",
    "No CVSS, EPSS, exploit-feed, or business-context data is used; nothing is invented when the scanner did not report it.",
    "severity and confidence stay separate fields; 'unknown' values are dropped to conservative defaults instead of a guess.",
    "Cross-asset blast radius is not modeled: one high-severity finding on many assets counts once per asset.",
]


def finding_priority(f: Dict[str, Any]) -> float:
    sev = SEVERITY_WEIGHT.get(f["severity"], SEVERITY_WEIGHT["unknown"])
    conf = CONFIDENCE_WEIGHT.get(f["confidence"], CONFIDENCE_WEIGHT["unknown"])
    stat = VERIFICATION_WEIGHT.get(f.get("verification_status", ""), VERIFICATION_WEIGHT["unknown"])
    return round(float(sev) * float(conf) * float(stat), 1)


def _priority_sort_key(f: Dict[str, Any]) -> Tuple[Any, ...]:
    # deterministic: priority desc, then severity rank desc, then stable ties
    rank = SEVERITY_WEIGHT.get(f["severity"], SEVERITY_WEIGHT["unknown"])
    return (
        -finding_priority(f),
        -rank,
        f["title"],
        f["category"],
        f["affected_asset"],
        f["id"],
    )


# ---------------------------------------------------------------------------
# Correlation (cautious, reason-carrying, context only)
# ---------------------------------------------------------------------------

def _same_host(a: str, b: str) -> bool:
    try:
        ha = urlsplit(a)
        hA = (ha.netloc or "").lower()
        hB = (urlsplit(b).netloc or "").lower()
        return bool(hA) and hA == hB
    except ValueError:
        return False


def correlate_findings(
    findings: List[Dict[str, Any]],
    *,
    dedup_result: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Correlate causally related findings; every link carries its reason.

    Cautious by contract: a link NEVER changes a finding's severity,
    confidence, or verification status. It only links two stored findings and
    explains why the relation is plausible.

    Rules implemented (all context-only):
    1. insecure_transport_resource - an insecure http:// reference observed
       in JavaScript, linked to a plain-HTTP/weak-TLS transport finding on
       the same host.
    2. secret_and_endpoint_same_asset - a secret CANDIDATE linked to an API
       endpoint reference found in the same script asset.
    3. dangerous_sink_and_endpoint_same_asset - a dangerous DOM/sink usage
       linked to API endpoint references in the same script asset.
    """
    # Work on normalized findings; input may already be deduped output.
    normalized = [f for f in findings if "category" in f and isinstance(f.get("category"), str) and f.get("category") in KNOWN_CATEGORIES]

    links: List[Dict[str, Any]] = []

    def _link(a: Dict[str, Any], b: Dict[str, Any], relation: str, reason: str) -> None:
        id_a = str(a["id"]) if isinstance(a.get("id"), str) else str(finding_id(a["category"], a["affected_asset"], a["title"]))
        id_b = str(b["id"]) if isinstance(b.get("id"), str) else str(finding_id(b["category"], b["affected_asset"], b["title"]))
        # symmetric canonical id: sorted endpoint ids, a-role annotation below
        pair = tuple(sorted((("a", id_a), ("b", id_b)), key=lambda t: t[1]))
        cid = finding_id(relation, pair)
        links.append({
            "id": cid,
            "relation": relation,
            "finding": id_a,
            "related_to": id_b,
            "finding_title": a["title"],
            "related_title": b["title"],
            "related_finding": id_a,
            "reason": reason,
        })

    # pre-bucket rules per category to stay O(n^2) worst-case only within rule
    secret_candidates = [
        f for f in normalized
        if f["category"] == "js_analysis" and "hardcoded secret" in f["title"].lower()
    ]
    dangerous_sinks = [
        f for f in normalized
        if f["category"] == "js_analysis" and "dangerous api usage" in f["title"].lower()
    ]
    insecure_refs = [
        f for f in normalized
        if f["category"] == "js_analysis" and "insecure http://" in f["title"].lower()
    ]
    transport = [
        f for f in normalized
        if f["category"] == "tls_analysis"
        and (
            (f.get("evidence") or {}).get("scheme") == "http"
            or "plain http" in f["title"].lower()
            or "weak protocol" in f["title"].lower()
        )
    ]

    by_asset: Dict[str, List[Dict[str, Any]]] = {}
    for f in normalized:
        by_asset.setdefault(f["affected_asset"], []).append(f)

    # rule 2 & 3: same-asset link between JS observations and endpoint references
    for group_name, buckets in (
        ("secret_and_endpoint_same_asset", secret_candidates),
        ("dangerous_sink_and_endpoint_same_asset", dangerous_sinks),
    ):
        for f in buckets:
            for endpoint in by_asset.get(f["affected_asset"], []):
                if endpoint["category"] != "api_discovery":
                    continue
                if group_name.startswith("secret"):
                    reason = (
                        f"The same script asset '{_short(f['affected_asset'])}' contains a "
                        "secret-like value candidate and references the API endpoint "
                        f"'{_short(endpoint['title'])}'. This is positioning context only: "
                        "the secret-like value was redacted and never validated against "
                        "any service, and this correlation does not confirm any leak."
                    )
                else:
                    reason = (
                        f"The script asset '{_short(f['affected_asset'])}' contains a "
                        "dangerous-DOM/sink usage and references the API endpoint "
                        f"'{_short(endpoint['title'])}'. No data-flow/taint analysis was "
                        "performed, so this link explains exposure context but does not "
                        "assert that endpoint data reaches the sink."
                    )
                _link(f, endpoint, group_name, reason)

    # rule 1: insecure http:// reference <-> transport finding on the same host
    for ref in insecure_refs:
        ref_url = (ref.get("evidence") or {}).get("url", "")
        for t in transport:
            same_host = _same_host(ref["affected_asset"], t["affected_asset"]) or _same_host(ref_url, t["affected_asset"])
            if not same_host:
                continue
            reason = (
                f"Client-side JavaScript asset '{_short(ref['affected_asset'])}' references "
                f"an http:// URL, while transport-level analysis of the same host "
                f"('{_short(t['affected_asset'])}') reports a non-HTTPS/weak-transport condition "
                "(category: tls_analysis). The two observations are consistent "
                "(both describe cleartext transport) but neither confirms the other's "
                "impact; the http:// reference may also be a namespace or comment."
            )
            _link(ref, t, "insecure_transport_resource", reason)

    # de-duplicate symmetric rule hits and force deterministic order
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for l in sorted(links, key=lambda l: (l["finding"], l["related_to"], l["relation"], l["id"])):
        key = (l["id"])
        if key in seen:
            continue
        seen.add(key)
        out.append(l)
    # drop role-label duplicates the simple spec does not need
    cleaned = []
    for l in out:
        l.pop("related_finding", None)
        cleaned.append(l)
    return cleaned


def _short(text: str, limit: int = 80) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Risk summary (deterministic; from stored results only)
# ---------------------------------------------------------------------------

PRIORITIZED_TOP_N = 10


def build_risk_summary(
    findings: List[Dict[str, Any]],
    *,
    scan_id: Optional[str] = None,
    correlations: int = 0,
    top_n: int = PRIORITIZED_TOP_N,
) -> Dict[str, Any]:
    """Build a deterministic, self-describing risk summary from stored findings.

    Every count, every prioritized entry, and the formula metadata derive only
    from stored results; no dashboard value is hardcoded and no evidence is
    re-interpreted. Formatted determinically (keys sorted) for testability.
    """
    normalized, errors = normalize_all(findings)
    dedup = deduplicate_findings(normalized)
    merged = dedup["findings"]
    for f in merged:
        f["priority"] = finding_priority(f)
    prioritized = sorted(merged, key=_priority_sort_key)

    by_severity: Dict[str, int] = {}
    by_confidence: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    for f in merged:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
        by_confidence[f["confidence"]] = by_confidence.get(f["confidence"], 0) + 1
        by_status[f["verification_status"]] = by_status.get(f["verification_status"], 0) + 1
        cat_label = f["category"] if f["category_recognized"] else f"{f['category']} (unrecognized)"
        by_category[cat_label] = by_category.get(cat_label, 0) + 1

    suggestions: List[str] = []
    for f in prioritized:
        rem = (f.get("remediation") or "").strip()
        if rem and rem not in suggestions:
            suggestions.append(rem)
        if len(suggestions) >= top_n:
            break

    summary = {
        "scan_id": scan_id,
        "formula": {
            "name": FORMULA_NAME,
            "expression": FORMULA_EXPRESSION,
            "limitations": FORMULA_LIMITATIONS,
        },
        "counts": {
            "total": len(findings),
            "normalized": len(normalized),
            "deduplicated": len(merged),
            "duplicate_groups": dedup["duplicate_groups"],
            "malformed_skipped": len(errors),
            "correlations_considered": correlations,
            "by_severity": dict(sorted(by_severity.items())),
            "by_confidence": dict(sorted(by_confidence.items())),
            "by_verification_status": dict(sorted(by_status.items())),
            "by_category": dict(sorted(by_category.items())),
        },
        "prioritized": [
            {
                "id": f["id"],
                "title": f["title"],
                "category": f["category"],
                "severity": f["severity"],
                "confidence": f["confidence"],
                "verification_status": f["verification_status"],
                "affected_asset": f["affected_asset"],
                "source_modules": f.get("source_modules", []),
                "priority": f["priority"],
                "remediation": f.get("remediation", ""),
                "cwe": f.get("cwe"),
                "cve": f.get("cve"),
                "contributing_original_ids": f.get("contributing_original_ids", []),
            }
            for f in prioritized[:top_n]
        ],
        "remediation_suggestions": suggestions,
        "errors": errors,
    }
    return summary
