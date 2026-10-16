"""Report generation from stored scan data.

Both PDF and JSON reports are produced strictly from already-persisted scan
artifacts and findings. Nothing is invented to fill an empty section; when a
section has no source data, the report says so explicitly and explains why.

PDF output uses ReportLab with a simple, deterministic layout and generous
escaping of all untrusted content. Input strings are capped to keep the PDF
engine from blowing up on exceptionally long target-controlled fields (an
attacker-controlled URL or script body, for example).

The JSON report mirrors the same content, formatted for machine consumption and
reproducibility, and is never a "dump" of internal keys - it is a curated
document view with the same redaction discipline as the PDF.
"""

from __future__ import annotations

import html as _html
import json
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Dict, List, Optional

from reportlab.lib import colors as _colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.core.logging import get_logger

logger = get_logger("report")

# Internal alias used throughout the rendering code.
_Paragraph = Paragraph

# ---------------------------------------------------------------------------
# Constants / tuning
# ---------------------------------------------------------------------------

PAGE_SIZE = A4
CHAR_BUDGET_PER_FIELD = 8000  # safety cap on any single untrusted string
REDACTION = "***REDACTED***"

_SEVERITY_COLOR = {
    "critical": _colors.HexColor("#b30000"),
    "high": _colors.HexColor("#e36c09"),
    "medium": _colors.HexColor("#f0a500"),
    "low": _colors.HexColor("#548235"),
    "info": _colors.HexColor("#808080"),
    "unknown": _colors.HexColor("#808080"),
}


# ---------------------------------------------------------------------------
# HTML / text escaping for untrusted content
# ---------------------------------------------------------------------------

def _escape_html(text: str) -> str:
    """Escape user-controlled / target-controlled text for HTML + ReportLab."""
    return _html.escape(text or "", quote=True)


def _truncate(text: str, max_chars: int, suffix: str = "...") -> str:
    text = text or ""
    if len(text) <= max_chars:
        return text
    return text[: max_chars - len(suffix)] + suffix


def _cap_field(text: Any, budget: int = CHAR_BUDGET_PER_FIELD) -> str:
    """Normalize + cap a user-controlled field to a safe printable string."""
    if text is None:
        return ""
    if isinstance(text, str):
        s = text
    else:
        s = json.dumps(text, default=str, ensure_ascii=False)
    s = unicodedata.normalize("NFKC", s)
    s = _truncate(s, budget, "...")
    return s


def _json_snippet(value: Any, max_chars: int = 400) -> str:
    """A small, readable JSON snippet for evidence subtrees."""
    try:
        s = json.dumps(value, default=str, ensure_ascii=False, sort_keys=True)
    except Exception:
        s = str(value)
    return _truncate(s, max_chars, "...")


# ---------------------------------------------------------------------------
# Data models (report-facing, already stored)
# ---------------------------------------------------------------------------


@dataclass
class ReportPayload:
    """The curated document view produced from a scan + its stored data."""

    scan_id: str
    target: str
    authorized_scope: str
    scan_started_at: Optional[str]
    scan_finished_at: Optional[str]
    scan_status: str
    modules_requested: List[str]
    modules_executed: List[str]
    modules_available_but_skipped: List[str]
    modules_failed: List[str]
    modules_unavailable: List[str]
    methodology: str
    limitations: str
    summary_counts: Dict[str, Any]
    prioritized_findings: List[Dict[str, Any]]
    remediation_suggestions: List[str]
    correlation_links: List[Dict[str, Any]]
    risk_formula: Dict[str, Any]
    inventory: Dict[str, Any]
    finding_details: List[Dict[str, Any]]
    tool_errors: List[str]


# ---------------------------------------------------------------------------
# Evidence redaction helpers (consistent with the scanner's redaction rules)
# ---------------------------------------------------------------------------

_SECRET_FIELD_NAMES = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "secret_key",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "auth",
    "cookie",
    "set-cookie",
    "session",
    "session_id",
    "jwt",
    "private_key",
    "client_secret",
    "x-api-key",
    "proxy-authorization",
}


def _redact_evidence(evidence: Any) -> Any:
    """Recursively replace secret-looking values with a redaction marker.

    We do NOT attempt full semantic redaction of arbitrary hidden secrets
    inside free text; we only redact values under well-known sensitive keys
    and leave the rest as stored. This matches the scanner's session-token
    and header redaction discipline.
    """
    if isinstance(evidence, dict):
        out: Dict[str, Any] = {}
        for k, v in evidence.items():
            if str(k).lower() in _SECRET_FIELD_NAMES:
                out[k] = REDACTION
            else:
                out[k] = _redact_evidence(v)
        return out
    if isinstance(evidence, list):
        return [_redact_evidence(v) for v in evidence]
    return evidence


def _redacted_evidence_text(evidence: Any, max_chars: int = 900) -> str:
    """A readable, redacted snapshot of evidence for the report body."""
    redacted = _redact_evidence(evidence)
    return _json_snippet(redacted, max_chars)


# ---------------------------------------------------------------------------
# Build the report payload
# ---------------------------------------------------------------------------

def build_report_payload(
    scan_id: str,
    *,
    target: str,
    authorized_scope: str,
    scan_status: str,
    started_at: Optional[datetime],
    finished_at: Optional[datetime],
    modules_requested: List[str],
    modules_executed: List[str],
    modules_available_but_skipped: List[str],
    modules_failed: List[str],
    modules_unavailable: List[str],
    methodology: str,
    limitations: str,
    summary_counts: Dict[str, Any],
    prioritized_findings: List[Dict[str, Any]],
    remediation_suggestions: List[str],
    correlation_links: List[Dict[str, Any]],
    risk_formula: Dict[str, Any],
    inventory: Dict[str, Any],
    finding_details: List[Dict[str, Any]],
    tool_errors: List[str],
) -> ReportPayload:
    return ReportPayload(
        scan_id=scan_id,
        target=target,
        authorized_scope=authorized_scope,
        scan_started_at=(started_at.astimezone(timezone.utc).isoformat() if started_at else None),
        scan_finished_at=(finished_at.astimezone(timezone.utc).isoformat() if finished_at else None),
        scan_status=scan_status,
        modules_requested=sorted(modules_requested),
        modules_executed=sorted(modules_executed),
        modules_available_but_skipped=sorted(modules_available_but_skipped),
        modules_failed=sorted(modules_failed),
        modules_unavailable=sorted(modules_unavailable),
        methodology=methodology,
        limitations=limitations,
        summary_counts=summary_counts,
        prioritized_findings=prioritized_findings,
        remediation_suggestions=remediation_suggestions,
        correlation_links=correlation_links,
        risk_formula=risk_formula,
        inventory=inventory,
        finding_details=finding_details,
        tool_errors=sorted(set(tool_errors)),
    )


# ---------------------------------------------------------------------------
# PDF rendering
# ---------------------------------------------------------------------------


def _build_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    styles: Dict[str, ParagraphStyle] = {}
    styles["title"] = ParagraphStyle(
        "reportTitle", parent=base["Title"], fontSize=18,
        textColor=_colors.HexColor("#1f2937"), spaceAfter=6 * mm, leading=22,
    )
    styles["h1"] = ParagraphStyle(
        "reportH1", parent=base["Heading1"], fontSize=13,
        textColor=_colors.HexColor("#111827"), spaceBefore=8 * mm,
        spaceAfter=2.5 * mm, leading=16,
    )
    styles["h2"] = ParagraphStyle(
        "reportH2", parent=base["Heading2"], fontSize=10.5,
        textColor=_colors.HexColor("#374151"), spaceBefore=3 * mm,
        spaceAfter=1.5 * mm, leading=13,
    )
    styles["body"] = ParagraphStyle(
        "reportBody", parent=base["Normal"], fontSize=9,
        textColor=_colors.HexColor("#1f2937"), leading=11.5,
        spaceAfter=1.5 * mm, alignment=TA_JUSTIFY,
    )
    styles["mono"] = ParagraphStyle(
        "reportMono", parent=base["Code"], fontSize=8,
        textColor=_colors.HexColor("#374151"), leading=10, leftIndent=4,
        wordWrap="CJK",
    )
    styles["footer"] = ParagraphStyle(
        "reportFooter", parent=base["Normal"], fontSize=7.5,
        textColor=_colors.HexColor("#6b7280"), alignment=TA_CENTER,
    )
    return styles


def _severity_badge_html(severity: str) -> str:
    sev = (severity or "").lower()
    color = _SEVERITY_COLOR.get(sev, _colors.HexColor("#808080"))
    hexval = _colors.toColor(color).hexval()[2:]
    return f'<font color="#{hexval}">{_escape_html(sev.upper())}</font>'


def _add_modules_section(story: List[Any], payload: ReportPayload, styles: Dict[str, ParagraphStyle]) -> None:
    story.append(_Paragraph("Modules executed", styles["h2"]))
    lines: List[str] = []
    lines.append(f"<b>Modules requested:</b> {_escape_html(', '.join(payload.modules_requested) or '(none)')}")
    if payload.modules_executed:
        lines.append(f"<b>Modules executed:</b> {_escape_html(', '.join(payload.modules_executed))}")
    if payload.modules_unavailable:
        lines.append(f"<b>Modules unavailable:</b> {_escape_html(', '.join(payload.modules_unavailable))}")
    if payload.modules_failed:
        lines.append(f"<b>Modules that failed:</b> {_escape_html(', '.join(payload.modules_failed))}")
    if payload.modules_available_but_skipped:
        lines.append(f"<b>Modules available but not executed (not requested):</b> {_escape_html(', '.join(payload.modules_available_but_skipped))}")
    if not payload.modules_executed and not payload.modules_unavailable and not payload.modules_failed:
        lines.append("No modules were executed for this scan.")
    story.append(_Paragraph("<br/>".join(lines), styles["body"]))
    story.append(_Paragraph(
        "Module availability is recorded from actual artifact presence; "
        "unavailable modules are listed, never fabricated.",
        styles["body"],
    ))


def _add_inventory_section(story: List[Any], payload: ReportPayload, styles: Dict[str, ParagraphStyle]) -> None:
    inv = payload.inventory or {}
    added = False

    html_obj = inv.get("html_analysis") or inv.get("html")
    if isinstance(html_obj, dict) and html_obj:
        added = True
        story.append(_Paragraph("HTML analysis", styles["h2"]))
        title = ""
        if isinstance(html_obj.get("title"), str) and html_obj["title"]:
            title = _cap_field(html_obj["title"], 300)
        parts: List[str] = []
        if title:
            parts.append(f"Title: {_escape_html(title)}")
        meta_lines: List[str] = []
        for m in (html_obj.get("meta") or []):
            name = _cap_field(m.get("name"), 120)
            content = _cap_field(m.get("content"), 180)
            if name and content:
                meta_lines.append(f"{_escape_html(name)}: {_escape_html(content)}")
        if meta_lines:
            parts.append("Meta tags:<br/>" + "<br/>".join(meta_lines))
        link_lines: List[str] = []
        for l in (html_obj.get("links") or []):
            href = _cap_field(l.get("href"), 300)
            if href:
                kind = "external" if l.get("is_external") else "internal"
                link_lines.append(f"[{kind}] {_escape_html(href)}")
        if link_lines:
            parts.append("HTML links:<br/>" + "<br/>".join(link_lines))
        if not parts:
            parts.append("(no readable HTML summary available)")
        story.append(_Paragraph("<br/>".join(parts), styles["body"]))
        story.append(_Paragraph(
            "Derived from the server's HTML response only; embedded IFrames, "
            "server-side rendered fragments, and JS-injected content are not "
            "covered by this passive snapshot.",
            styles["body"],
        ))

    js_assets = inv.get("js_assets")
    if isinstance(js_assets, list) and js_assets:
        added = True
        story.append(_Paragraph("Discovered JavaScript assets", styles["h2"]))
        rows: List[List[str]] = []
        for a in js_assets:
            url = _cap_field(a.get("url"), 280)
            sz = a.get("size_bytes")
            sha = _cap_field(a.get("sha256"), 64)
            ctype = _cap_field(a.get("content_type"), 80)
            rows.append([
                _escape_html(url),
                str(sz) if isinstance(sz, int) else "n/a",
                _escape_html(ctype),
                _escape_html(sha),
            ])
        tbl = Table(rows, colWidths=[100 * mm, 28 * mm, 38 * mm, 30 * mm])
        tbl.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, _colors.HexColor("#d1d5db")),
            ("FONTNAME", (0, 0), (-1, -1), "Courier"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(tbl)
        story.append(_Paragraph(
            "URLs are shown as reported. Because these are target-controlled "
            "values, the report does not assert they were reachable or that "
            "their content was fully retrieved.",
            styles["body"],
        ))

    js_analysis = inv.get("js_analysis")
    if isinstance(js_analysis, dict) and js_analysis:
        added = True
        story.append(_Paragraph("Client-side script analysis", styles["h2"]))
        lines = []
        for i, sc in enumerate(js_analysis.get("secret_candidates") or [], 1):
            pattern = _cap_field(sc.get("pattern"), 80)
            ctx = _cap_field(sc.get("context"), 160)
            redacted = "yes" if sc.get("value_redacted") else "no"
            lines.append(f"{i}. {_escape_html(pattern)} - context: {_escape_html(ctx)} - value redacted: {redacted}")
        for i, api in enumerate(js_analysis.get("dangerous_apis") or [], 1):
            api_name = _cap_field(api.get("api"), 80)
            ctx = _cap_field(api.get("context"), 160)
            line = api.get("line")
            lines.append(f"{i}. dangerous API: {_escape_html(api_name)} - context: {_escape_html(ctx)} - line: {line if isinstance(line, int) else 'n/a'}")
        for i, ref in enumerate(js_analysis.get("insecure_http_refs") or [], 1):
            ctx = _cap_field(ref.get("context"), 160)
            line = ref.get("line")
            lines.append(f"{i}. insecure http:// reference - context: {_escape_html(ctx)} - line: {line if isinstance(line, int) else 'n/a'}")
        if js_analysis.get("debugger_usage"):
            lines.append(f"debugger statements: {len(js_analysis['debugger_usage'])} occurrence(s)")
        if not lines:
            lines.append("(no notable client-side observations)")
        story.append(_Paragraph("<br/>".join(lines), styles["body"]))
        story.append(_Paragraph(
            "Static analysis only. These are observations about the script "
            "text as scanned; they are not proof of runtime behavior, "
            "exploitation, or data leakage.",
            styles["body"],
        ))

    endpoints = inv.get("api_endpoints")
    if isinstance(endpoints, list) and endpoints:
        added = True
        story.append(_Paragraph("Discovered API endpoints", styles["h2"]))
        rows = []
        for e in endpoints:
            rows.append([
                _escape_html(_cap_field(e.get("url"), 280)),
                _escape_html(_cap_field(e.get("method"), 10)),
                _escape_html(_cap_field(e.get("source"), 60)),
                str(e.get("line")) if isinstance(e.get("line"), int) else "n/a",
                "yes" if e.get("dynamically_constructed") else "no",
                "yes" if e.get("partial") else "no",
            ])
        tbl = Table(rows, colWidths=[78 * mm, 20 * mm, 22 * mm, 12 * mm, 28 * mm, 26 * mm])
        tbl.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, _colors.HexColor("#d1d5db")),
            ("FONTNAME", (0, 0), (-1, -1), "Courier"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(tbl)
        story.append(_Paragraph(
            "Endpoint references are extracted from observed source text and "
            "headers only. The report does not test these endpoints and does "
            "not confirm they exist, accept the listed method, or leak data.",
            styles["body"],
        ))

    if not added:
        story.append(_Paragraph("Artifacts", styles["h2"]))
        story.append(_Paragraph(
            "No readable inventory sections were available for this scan.",
            styles["body"],
        ))


def _add_findings_section(story: List[Any], payload: ReportPayload, styles: Dict[str, ParagraphStyle]) -> None:
    story.append(_Paragraph("Finding details (grounded in stored evidence)", styles["h2"]))
    if not payload.finding_details:
        story.append(_Paragraph("No findings were stored for this scan.", styles["body"]))
        return
    for f in payload.finding_details:
        sev = _escape_html(f.get("severity", ""))
        conf = _escape_html(f.get("confidence", ""))
        story.append(_Paragraph(
            f"Finding: {_escape_html(f.get('title', '(untitled)'))} "
            f"[{_severity_badge_html(sev)} / {conf}]",
            styles["h2"],
        ))
        lines: List[str] = []
        lines.append(f"Source module: {_escape_html(f.get('source_module', ''))}")
        lines.append(f"Verification status: {_escape_html(f.get('verification_status', ''))}")
        if f.get("cwe"):
            lines.append(f"CWE: {_escape_html(f['cwe'])}")
        if f.get("cve"):
            lines.append(f"CVE: {_escape_html(f['cve'])}")
        if f.get("affected_asset"):
            lines.append(f"Affected asset: {_escape_html(f['affected_asset'])}")
        story.append(_Paragraph("<br/>".join(lines), styles["body"]))
        ev = _redacted_evidence_text(f.get("evidence"))
        story.append(_Paragraph("Evidence (redacted where sensitive):", styles["body"]))
        story.append(_Paragraph(_escape_html(ev), styles["mono"]))
        if f.get("remediation"):
            story.append(_Paragraph("Remediation guidance:", styles["body"]))
            story.append(_Paragraph(_escape_html(_cap_field(f["remediation"], 1500)), styles["body"]))
        if f.get("impact"):
            story.append(_Paragraph("Reported impact:", styles["body"]))
            story.append(_Paragraph(_escape_html(_cap_field(f["impact"], 1500)), styles["body"]))
        if f.get("description"):
            story.append(_Paragraph("Description:", styles["body"]))
            story.append(_Paragraph(_escape_html(_cap_field(f["description"], 1500)), styles["body"]))
        story.append(_Paragraph(
            "This section reproduces stored evidence only; it is not "
            "re-scanned and not AI-interpreted.",
            styles["body"],
        ))
        story.append(Spacer(1, 3 * mm))


def _add_correlation_section(story: List[Any], payload: ReportPayload, styles: Dict[str, ParagraphStyle]) -> None:
    story.append(_Paragraph("Correlations (review context only)", styles["h2"]))
    if not payload.correlation_links:
        story.append(_Paragraph("No correlation links were computed for this scan.", styles["body"]))
        return
    lines: List[str] = []
    for i, link in enumerate(payload.correlation_links, 1):
        a = _cap_field(link.get("finding_title") or link.get("finding"), 200)
        b = _cap_field(link.get("related_title") or link.get("related_to"), 200)
        rel = _escape_html(link.get("relation", ""))
        reason = _escape_html(_cap_field(link.get("reason"), 600))
        lines.append(f"{i}. Relation: {rel}<br/>Finding: {_escape_html(a)}<br/>Related to: {_escape_html(b)}<br/>Reason: {reason}")
    story.append(_Paragraph("<br/>".join(lines), styles["body"]))
    story.append(_Paragraph(
        "Correlations add context only; they never upgrade severity, "
        "confidence, or verification status.",
        styles["body"],
    ))


def _add_risk_section(story: List[Any], payload: ReportPayload, styles: Dict[str, ParagraphStyle]) -> None:
    story.append(_Paragraph("Risk summary", styles["h2"]))
    story.append(_Paragraph("Counts:", styles["body"]))
    count_lines: List[str] = []
    for k, v in sorted((payload.summary_counts or {}).items()):
        if isinstance(v, dict):
            count_lines.append(f"<b>{_escape_html(k)}:</b> " + ", ".join(f"{_escape_html(str(k2))}: {v2}" for k2, v2 in sorted(v.items())))
        else:
            count_lines.append(f"{_escape_html(k)}: {v}")
    if not count_lines:
        count_lines.append("(no counts available)")
    story.append(_Paragraph("<br/>".join(count_lines), styles["body"]))

    formula = payload.risk_formula or {}
    story.append(_Paragraph("Risk prioritization formula:", styles["body"]))
    story.append(_Paragraph(
        f"Name: {_escape_html(formula.get('name', ''))}<br/>"
        f"Expression: {_escape_html(_cap_field(formula.get('expression', ''), 500))}",
        styles["body"],
    ))

    if payload.prioritized_findings:
        lines = []
        for i, f in enumerate(payload.prioritized_findings, 1):
            title = _escape_html(f.get("title", "(untitled)"))
            sev = _escape_html(f.get("severity", ""))
            asset = _escape_html(f.get("affected_asset", ""))
            lines.append(f"{i}. [{sev}] {title} - {_escape_html(asset)} - priority {f.get('priority')}")
        story.append(_Paragraph("Prioritized findings (by formula):", styles["body"]))
        story.append(_Paragraph("<br/>".join(lines), styles["body"]))

    if payload.remediation_suggestions:
        lines = [f"* {_escape_html(_cap_field(s, 200))}" for s in payload.remediation_suggestions]
        story.append(_Paragraph("Remediation suggestions (from stored findings):", styles["body"]))
        story.append(_Paragraph("<br/>".join(lines), styles["body"]))


def _add_tool_errors_section(story: List[Any], payload: ReportPayload, styles: Dict[str, ParagraphStyle]) -> None:
    story.append(_Paragraph("Tool errors and partial results", styles["h2"]))
    if not payload.tool_errors:
        story.append(_Paragraph("No tool errors or partial results were recorded for this scan.", styles["body"]))
        return
    lines = [f"{i}. {_escape_html(e)}" for i, e in enumerate(payload.tool_errors, 1)]
    story.append(_Paragraph("<br/>".join(lines), styles["body"]))
    story.append(_Paragraph(
        "Errors are reproduced as stored; the report does not infer "
        "additional failure causes.",
        styles["body"],
    ))


def _render_pdf(payload: ReportPayload) -> bytes:
    # Keep content streams uncompressed: PDFs stay inspectable-greppable by
    # tools and tests, and the report text is auditable without a parser.
    import reportlab.rl_config as _rl_config
    _rl_config.pageCompression = 0
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=PAGE_SIZE,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"VibeShield AI - Scan report {payload.scan_id}",
        author="VibeShield AI",
        subject=payload.target,
    )
    styles = _build_styles()
    story: List[Any] = []

    story.append(_Paragraph("VibeShield AI", styles["title"]))
    story.append(_Paragraph(f"Scan report - {payload.scan_id}", styles["h1"]))
    story.append(_Paragraph(f"Target: {_escape_html(payload.target)}", styles["body"]))
    scope = _escape_html(payload.authorized_scope or "(not recorded)")
    story.append(_Paragraph(f"Authorized scope: {scope}", styles["body"]))
    story.append(HRFlowable(width="100%", thickness=0.6, color=_colors.HexColor("#d1d5db")))
    story.append(Spacer(1, 3 * mm))

    story.append(_Paragraph("Report metadata", styles["h2"]))
    story.append(_Paragraph(f"Scan started: {payload.scan_started_at or '(not started)'}", styles["body"]))
    story.append(_Paragraph(f"Scan finished: {payload.scan_finished_at or '(not finished)'}", styles["body"]))
    story.append(_Paragraph(f"Scan status: {_escape_html(payload.scan_status)}", styles["body"]))
    story.append(_Paragraph(f"Report generated: {datetime.now(timezone.utc).isoformat()}", styles["body"]))

    story.append(_Paragraph("Methodology", styles["h2"]))
    story.append(_Paragraph(_escape_html(payload.methodology), styles["body"]))
    story.append(_Paragraph("Limitations", styles["h2"]))
    story.append(_Paragraph(_escape_html(payload.limitations), styles["body"]))

    _add_modules_section(story, payload, styles)
    _add_inventory_section(story, payload, styles)
    _add_findings_section(story, payload, styles)
    _add_correlation_section(story, payload, styles)
    _add_risk_section(story, payload, styles)
    _add_tool_errors_section(story, payload, styles)

    story.append(HRFlowable(width="100%", thickness=0.4, color=_colors.HexColor("#d1d5db")))
    story.append(_Paragraph(
        "Generated by VibeShield AI. All content is derived from stored scan "
        "artifacts and findings. No data was fabricated to fill an empty section.",
        styles["footer"],
    ))

    doc.build(story)
    return buffer.getvalue()


def render_pdf_report(payload: ReportPayload) -> bytes:
    return _render_pdf(payload)


# ---------------------------------------------------------------------------
# JSON rendering
# ---------------------------------------------------------------------------

def sanitize_artifacts_for_report(artifacts: Any) -> Any:
    """Report-safe copy of the artifact inventory.

    Raw fetched bodies (e.g. ``js_assets[].content``) are target-controlled
    text that may contain live secrets; the scanner's own finding evidence is
    redacted, but the raw body in the artifact was not. Reports must never
    re-expose it, so bulk `content` fields are dropped (the inventory fields
    URL/size/hash/content-type are kept). Phase 8 regression fix.
    """
    if isinstance(artifacts, dict):
        out: Dict[str, Any] = {}
        for k, v in artifacts.items():
            if str(k) == "content":
                continue  # raw fetched body: never reproduced in a report
            out[str(k)] = sanitize_artifacts_for_report(v)
        return out
    if isinstance(artifacts, list):
        return [sanitize_artifacts_for_report(v) for v in artifacts]
    return artifacts


def _to_json_report(payload: ReportPayload) -> Dict[str, Any]:
    # Evidence in the JSON report is redacted with the same discipline as the
    # PDF; the report never emits raw secret-shaped values.
    finding_details = []
    for f in payload.finding_details:
        ff = dict(f)
        ff["evidence"] = _redact_evidence(ff.get("evidence"))
        finding_details.append(ff)
    return {
        "generated_by": "VibeShield AI",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": {
            "scan_id": payload.scan_id,
            "target": payload.target,
            "authorized_scope": payload.authorized_scope or "(not recorded)",
            "status": payload.scan_status,
            "started_at": payload.scan_started_at,
            "finished_at": payload.scan_finished_at,
            "modules_requested": payload.modules_requested,
            "modules_executed": payload.modules_executed,
            "modules_available_but_skipped": payload.modules_available_but_skipped,
            "modules_failed": payload.modules_failed,
            "modules_unavailable": payload.modules_unavailable,
        },
        "methodology": payload.methodology,
        "limitations": payload.limitations,
        "summary_counts": payload.summary_counts,
        "risk_formula": payload.risk_formula,
        "prioritized_findings": payload.prioritized_findings,
        "correlation_links": payload.correlation_links,
        "artifacts": sanitize_artifacts_for_report(payload.inventory),
        "finding_details": finding_details,
        "finding_details_note": (
            "No findings were stored for this scan." if not finding_details else ""
        ),
        "tool_errors": payload.tool_errors,
    }


def render_json_report(payload: ReportPayload) -> bytes:
    obj = _to_json_report(payload)
    return (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


# ---------------------------------------------------------------------------
# Factory helpers for assembling ReportPayload from a scan + API data
# ---------------------------------------------------------------------------

def default_methodology() -> str:
    return (
        "VibeShield AI performs a passive website assessment using the modules "
        "enabled for the scan. Passive modules inspect publicly observable data: "
        "DNS answers, TLS properties, HTTP responses and headers, cookies, HTML, "
        "linked JavaScript, and any API endpoints referenced from that content. "
        "No traffic is injected beyond the initial page fetch except where an "
        "enabled module legitimately requires an additional read of a discovered "
        "URL, and even then only after re-validating the destination. Project "
        "scans additionally run dependency-audit and source-analysis tooling "
        "against an operator-authorized local directory. Findings are normalized "
        "by severity, confidence, category and verification status, deduplicated "
        "without losing contributing sources, correlated with explicit, cautious "
        "reasons, and ranked by a documented deterministic formula."
    )


def default_limitations() -> str:
    return (
        "This is a passive assessment, not an active exploit test. Findings are "
        "observations, not confirmed vulnerabilities unless independently "
        "verified. Severity and confidence are separate fields and are never "
        "re-derived from each other; unknown values are marked unknown instead "
        "of guessed. No CVSS, EPSS, exploit-feed, or business-context data is "
        "used, and none is invented when the scanner did not report it. "
        "Cross-asset blast radius is not modeled. The report shows stored "
        "evidence with sensitive values redacted; it does not include raw "
        "network traffic, credentials, session tokens, or anything not already "
        "persisted by the scanner."
    )
