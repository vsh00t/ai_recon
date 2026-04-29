"""Passive TLS certificate metadata extraction technique."""
from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timezone
from typing import ClassVar

from ai_recon.core.models import Finding, RunContext, Target
from ai_recon.techniques.base import Technique

_INTERNAL_SUFFIXES: tuple[str, ...] = (".internal", ".local", ".corp", ".lan", ".intranet", ".priv")


def _parse_cert_field(field: tuple) -> dict[str, str]:
    """Convert OpenSSL RDN tuple to a flat dict."""
    result = {}
    for rdn in field:
        for attr, value in rdn:
            result[attr] = value
    return result


def _extract_sans(cert: dict) -> list[str]:
    """Extract Subject Alternative Names from a parsed cert dict."""
    sans: list[str] = []
    alt_names = cert.get("subjectAltName", ())
    for kind, value in alt_names:
        if kind == "DNS":
            sans.append(value)
    return sans


def _cert_datetime(dt_str: str) -> datetime:
    """Parse OpenSSL datetime string (e.g. 'Apr 29 00:00:00 2026 GMT') into datetime."""
    try:
        # Python ssl module returns: 'Apr 29 00:00:00 2026 GMT'
        return datetime.strptime(dt_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.utcnow().replace(tzinfo=timezone.utc)


class TLSMetadataTechnique(Technique):
    id: ClassVar[str] = "passive.tls_metadata"
    intrusiveness: ClassVar = "passive"
    produces: ClassVar[set[str]] = {"infrastructure.tls", "infrastructure.hostnames"}

    async def applicable(self, target: Target) -> bool:
        return target.scheme == "https"

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        if target.scheme != "https":
            return findings

        cert_dict = await self._fetch_cert(target.host, target.port)
        if cert_dict is None:
            return findings

        # ── Parse fields ──────────────────────────────────────────────────────
        subject = _parse_cert_field(cert_dict.get("subject", ()))
        issuer = _parse_cert_field(cert_dict.get("issuer", ()))
        sans = _extract_sans(cert_dict)
        not_before_str = cert_dict.get("notBefore", "")
        not_after_str = cert_dict.get("notAfter", "")
        serial = cert_dict.get("serialNumber", "")

        not_after = _cert_datetime(not_after_str) if not_after_str else None
        not_before = _cert_datetime(not_before_str) if not_before_str else None

        # ── Emit main TLS finding ─────────────────────────────────────────────
        findings.append(
            self._make_finding(
                target,
                severity="info",
                confidence="high",
                title="TLS certificate metadata",
                evidence={
                    "subject_cn": subject.get("commonName", ""),
                    "subject": subject,
                    "issuer": issuer,
                    "sans": sans,
                    "not_before": not_before_str,
                    "not_after": not_after_str,
                    "serial": serial,
                },
            )
        )

        # ── Check expiry ──────────────────────────────────────────────────────
        if not_after:
            now_utc = datetime.now(tz=timezone.utc)
            days_remaining = (not_after - now_utc).days
            if days_remaining < 30:
                findings.append(
                    self._make_finding(
                        target,
                        severity="low",
                        confidence="high",
                        title="TLS certificate expiring soon",
                        evidence={
                            "not_after": not_after_str,
                            "days_remaining": days_remaining,
                        },
                    )
                )

        # ── Check for internal hostnames in SANs ──────────────────────────────
        internal_sans = [
            san for san in sans
            if any(san.lower().endswith(suffix) for suffix in _INTERNAL_SUFFIXES)
        ]
        if internal_sans:
            findings.append(
                self._make_finding(
                    target,
                    severity="medium",
                    confidence="high",
                    title="Internal hostnames in TLS SAN",
                    evidence={"sans": internal_sans},
                )
            )

        # ── Check self-signed ─────────────────────────────────────────────────
        subject_cn = subject.get("commonName", "")
        subject_o = subject.get("organizationName", "")
        issuer_cn = issuer.get("commonName", "")
        issuer_o = issuer.get("organizationName", "")

        if subject_cn == issuer_cn and subject_o == issuer_o:
            findings.append(
                self._make_finding(
                    target,
                    severity="low",
                    confidence="high",
                    title="Self-signed TLS certificate",
                    evidence={
                        "subject_cn": subject_cn,
                        "issuer_cn": issuer_cn,
                    },
                )
            )

        return findings

    @staticmethod
    async def _fetch_cert(host: str, port: int) -> dict | None:
        """Open a raw TLS connection and return the parsed peer certificate dict."""
        loop = asyncio.get_event_loop()
        try:
            cert_dict = await loop.run_in_executor(
                None,
                lambda: TLSMetadataTechnique._sync_get_cert(host, port),
            )
            return cert_dict
        except Exception:
            return None

    @staticmethod
    def _sync_get_cert(host: str, port: int) -> dict:
        """Synchronous TLS handshake to retrieve the certificate."""
        context = ssl.create_default_context()
        # Allow unverified certs so we can still inspect self-signed ones
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with context.wrap_socket(
            __import__("socket").create_connection((host, port), timeout=10),
            server_hostname=host,
        ) as ssock:
            return ssock.getpeercert()
