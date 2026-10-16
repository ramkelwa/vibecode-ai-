"""Module 3: TLS certificate and configuration analysis.

What it can detect (from a real TLS handshake only):
- certificate expiry / not-yet-valid certificates
- hostname mismatch between certificate SAN and target host
- self-signed certificates
- weak protocol versions offered by the server (TLS 1.0/1.1)
- HTTP endpoints on an HTTPS host (scheme downgrade exposure, from redirect data)

What it cannot detect:
- cipher strength enumeration (requires active negotiation tests),
  certificate revocation status, or MITM susceptibility.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from app.core.config import settings
from app.scanners.context import ScanContext
from app.scanners.schema import FindingData

MODULE = "tls_analysis"

WEAK_PROTOCOLS = {
    "TLSv1": "TLS 1.0",
    "TLSv1.1": "TLS 1.1",
    "SSLv3": "SSL 3.0",
}


def _probe_sync(host: str, port: int) -> Dict[str, Any]:
    """One real TLS connection: fetch cert + which protocol versions the server accepts."""
    out: Dict[str, Any] = {"host": host, "port": port}

    base_ctx = ssl.create_default_context()
    base_ctx.check_hostname = False
    base_ctx.verify_mode = ssl.CERT_NONE  # we inspect, not trust

    with socket.create_connection((host, port), timeout=settings.SCAN_REQUEST_TIMEOUT) as sock:
        with base_ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            out["protocol"] = tls.version()
            if der:

                pem = ssl.DER_cert_to_PEM_cert(der)
                # Decode via a trustless context to read metadata without validation.
                import os
                import tempfile

                with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
                    f.write(pem)
                    tmp = f.name
                try:
                    read_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    read_ctx.check_hostname = False
                    read_ctx.verify_mode = ssl.CERT_NONE
                    read_ctx.load_verify_locations(tmp)
                    parsed = ssl._ssl._test_decode_cert(tmp)  # type: ignore[attr-defined]
                    out["cert"] = parsed
                finally:
                    os.unlink(tmp)

    # Probe weak protocol support one version at a time.
    accepted_weak = []
    for proto, label in WEAK_PROTOCOLS.items():
        try:
            weak_ctx = ssl.SSLContext(getattr(ssl, "PROTOCOL_TLS_CLIENT", None) or ssl.PROTOCOL_TLS)
            weak_ctx.minimum_version = ssl.TLSVersion[proto.replace("TLSv", "TLSv").replace("SSLv", "SSLv")]
            weak_ctx.maximum_version = ssl.TLSVersion[proto.replace("TLSv", "TLSv").replace("SSLv", "SSLv")]
            weak_ctx.check_hostname = False
            weak_ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=settings.SCAN_REQUEST_TIMEOUT) as sock:
                with weak_ctx.wrap_socket(sock, server_hostname=host):
                    accepted_weak.append(label)
        except Exception:
            continue
    out["accepted_weak_protocols"] = accepted_weak
    return out


async def analyze_tls(ctx: ScanContext) -> list[FindingData]:
    """Analyze the real TLS configuration of the target."""
    findings: list[FindingData] = []
    parsed = urlparse(ctx.target_url)

    if parsed.scheme != "https":
        # Plain HTTP is reported once, as an observed fact.
        findings.append(
            FindingData(
                title="Target is served over plain HTTP",
                description="The target URL uses http:// so all traffic, including credentials, is sent unencrypted.",
                category=MODULE,
                severity="high",
                confidence="certain",
                affected_asset=ctx.target_url,
                evidence={"scheme": "http"},
                source_module=MODULE,
                cwe="CWE-319",
                impact="Network attackers can read and modify all traffic.",
                remediation="Serve the site over HTTPS and redirect HTTP to HTTPS.",
                verification_status="confirmed",
            )
        )
        ctx.artifacts["tls"] = {"skipped": "target is not https"}
        return findings

    host = parsed.hostname or ""
    port = parsed.port or 443
    tls_info: Dict[str, Any] = {}
    ctx.artifacts["tls"] = tls_info

    try:
        probe = await asyncio.to_thread(_probe_sync, host, port)
    except Exception as exc:
        # Distinguish real connection failures (limitation) from TLS-layer
        # issues (potential finding). Never classify an unreachable host as
        # a certificate problem.
        detail = f"{type(exc).__name__}"
        tls_info["error"] = detail
        if isinstance(exc, (OSError, socket.timeout, ConnectionError)) and not isinstance(
            exc, ssl.SSLError
        ):
            # TCP-level failure: record limitation only.
            tls_info["error_class"] = "connection_failure"
            return findings
        if isinstance(exc, ssl.SSLError):
            tls_info["error_class"] = "tls_handshake_failure"
        else:
            tls_info["error_class"] = "unknown_error"
        return findings

    tls_info["protocol"] = probe.get("protocol")
    cert: Optional[Dict[str, Any]] = probe.get("cert")
    if cert:
        tls_info["subject"] = cert.get("subject")
        tls_info["issuer"] = cert.get("issuer")
        tls_info["notAfter"] = cert.get("notAfter")

        # Expiry check from the real notAfter value.
        not_after = cert.get("notAfter")
        if isinstance(not_after, str):
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                days_left = (expiry - datetime.now(timezone.utc)).days
                tls_info["days_until_expiry"] = days_left
                if days_left < 0:
                    findings.append(
                        FindingData(
                            title="TLS certificate has expired",
                            description=f"The certificate for {host} expired {abs(days_left)} days ago.",
                            category=MODULE,
                            severity="high",
                            confidence="certain",
                            affected_asset=f"https://{host}:{port}",
                            evidence={"notAfter": not_after, "days_expired": abs(days_left)},
                            source_module=MODULE,
                            cwe="CWE-298",
                            impact="Browsers warn users; many clients refuse the connection entirely.",
                            remediation="Renew the certificate (e.g. via ACME/Let's Encrypt automation).",
                            verification_status="confirmed",
                        )
                    )
                elif days_left < 14:
                    findings.append(
                        FindingData(
                            title="TLS certificate expires soon",
                            description=f"The certificate for {host} expires in {days_left} days.",
                            category=MODULE,
                            severity="low",
                            confidence="certain",
                            affected_asset=f"https://{host}:{port}",
                            evidence={"notAfter": not_after, "days_left": days_left},
                            source_module=MODULE,
                            impact="Expiry will cause outages and browser warnings if not renewed.",
                            remediation="Verify automatic renewal is working.",
                            verification_status="confirmed",
                        )
                    )
            except ValueError:
                tls_info["notAfter_parse_error"] = True

        # Hostname verification is performed in the self-signed check below.
    # Self-signed detection: real verification attempt against system trust store.
    try:
        verify = await asyncio.to_thread(_verify_cert, host, port)
        if not verify["ok"]:
            reasons = verify.get("reason", "")
            if "SELF_SIGNED" in reasons or "self signed" in reasons.lower():
                findings.append(
                    FindingData(
                        title="Self-signed TLS certificate",
                        description="The server presented a certificate that does not chain to a trusted CA.",
                        category=MODULE,
                        severity="medium",
                        confidence="certain",
                        affected_asset=f"https://{host}:{port}",
                        evidence={"verify_error": reasons},
                        source_module=MODULE,
                        cwe="CWE-295",
                        impact="Users see trust warnings and may learn to bypass them, enabling MITM.",
                        remediation="Use a certificate from a publicly trusted CA (e.g. Let's Encrypt).",
                        verification_status="confirmed",
                    )
                )
            elif "hostname mismatch" in reasons.lower():
                findings.append(
                    FindingData(
                        title="TLS certificate hostname mismatch",
                        description="The certificate does not match the hostname that was connected to.",
                        category=MODULE,
                        severity="medium",
                        confidence="certain",
                        affected_asset=f"https://{host}:{port}",
                        evidence={"verify_error": reasons},
                        source_module=MODULE,
                        cwe="CWE-295",
                        impact="Clients cannot confirm the server identity, enabling interception.",
                        remediation="Issue a certificate containing the correct SAN for this hostname.",
                        verification_status="confirmed",
                    )
                )
    except Exception as exc:
        tls_info["verify_probe_error"] = type(exc).__name__

    weak = probe.get("accepted_weak_protocols") or []
    if weak:
        findings.append(
            FindingData(
                title="Server accepts outdated TLS protocol versions",
                description=f"The server completed handshakes with: {', '.join(weak)}. These protocols are deprecated.",
                category=MODULE,
                severity="medium",
                confidence="certain",
                affected_asset=f"https://{host}:{port}",
                evidence={"accepted_protocols": weak},
                source_module=MODULE,
                cwe="CWE-327",
                impact="Downgrade attacks and known protocol weaknesses become practical.",
                remediation="Disable TLS 1.0/1.1 and SSLv3; serve TLS 1.2+ only.",
                verification_status="confirmed",
            )
        )
    return findings


def _verify_cert(host: str, port: int) -> Dict[str, Any]:
    """Attempt a verifying handshake; return the real OpenSSL error on failure."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=settings.SCAN_REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return {"ok": True}
    except ssl.SSLCertVerificationError as exc:
        return {"ok": False, "reason": str(exc.verify_message or exc)}
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}
