"""Passive HTTP header fingerprinting technique.

Header taxonomy is loaded from ``catalogs/ai_headers.yaml`` so the
detector stays generic and easy to extend without code changes.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import ClassVar

import yaml

from ai_recon.core.models import Finding, RunContext, Target
from ai_recon.techniques.base import Technique

_CATALOG = Path(__file__).parent.parent.parent / "catalogs" / "ai_headers.yaml"

# Mapping section_name -> severity for findings.
_SECTION_SEVERITY: dict[str, str] = {
    "ai_backend_hints":     "medium",
    "rag_hints":            "medium",
    "orchestration_hints":  "low",
    "vendor_hints":         "low",
    "infra_hints":          "info",
    "rate_limit_hints":     "info",
}


@lru_cache(maxsize=1)
def _load_catalog() -> dict[str, list[str]]:
    """Return ``{section_name: [header_name, ...]}``."""
    try:
        data = yaml.safe_load(_CATALOG.read_text()) or {}
    except FileNotFoundError:
        return {}
    out: dict[str, list[str]] = {}
    for section, items in data.items():
        if not isinstance(items, list):
            continue
        names: list[str] = []
        for it in items:
            if isinstance(it, dict) and "name" in it:
                names.append(str(it["name"]))
            elif isinstance(it, str):
                names.append(it)
        out[section] = names
    return out


def _section_for(header_name: str) -> str | None:
    cat = _load_catalog()
    lower = header_name.lower()
    for section, names in cat.items():
        if any(lower == n.lower() for n in names):
            return section
    return None

# Gateway patterns: (regex, canonical_name)
_GATEWAY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"nginx", re.IGNORECASE), "nginx"),
    (re.compile(r"apache", re.IGNORECASE), "Apache"),
    (re.compile(r"kong", re.IGNORECASE), "Kong Gateway"),
    (re.compile(r"envoy", re.IGNORECASE), "Envoy Proxy"),
    (re.compile(r"caddy", re.IGNORECASE), "Caddy"),
    (re.compile(r"traefik", re.IGNORECASE), "Traefik"),
    (re.compile(r"cloudflare", re.IGNORECASE), "Cloudflare"),
]


class HeaderFingerprintTechnique(Technique):
    id: ClassVar[str] = "passive.header_fingerprint"
    intrusiveness: ClassVar = "passive"
    produces: ClassVar[set[str]] = {"infrastructure.gateway", "infrastructure.server", "ai.backend_hint"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        client = self.ctx.http_client
        url = target.base_url
        response = None

        # Try HEAD first, fall back to GET
        try:
            response = await client.head(url + "/", skip_rate_limit=False)
        except Exception:
            pass

        if response is None or response.status_code >= 400:
            try:
                response = await client.get(url + "/")
            except Exception:
                return findings

        headers = response.headers
        catalog = _load_catalog()

        # Collect any header listed in the catalog (case-insensitive lookup).
        for section, names in catalog.items():
            severity = _SECTION_SEVERITY.get(section, "info")
            for header_name in names:
                value = headers.get(header_name)
                if not value:
                    continue
                findings.append(
                    self._make_finding(
                        target,
                        severity=severity,
                        confidence="high",
                        title=f"{section}: {header_name}={value}",
                        evidence={
                            "section": section,
                            "header": header_name,
                            "value": value,
                            "url": url,
                        },
                    )
                )

        # Check Server header for known gateway patterns
        server_value = headers.get("Server", "")
        via_value = headers.get("Via", "")
        combined_server = f"{server_value} {via_value}".strip()

        if combined_server:
            for pattern, gateway_type in _GATEWAY_PATTERNS:
                if pattern.search(combined_server):
                    # Avoid duplicating already-emitted "AI header: Server=..." findings
                    findings.append(
                        self._make_finding(
                            target,
                            severity="info",
                            confidence="high",
                            title=f"Infrastructure: {gateway_type}",
                            evidence={
                                "header": "Server",
                                "value": server_value,
                                "via": via_value,
                                "url": url,
                                "gateway_type": gateway_type,
                            },
                        )
                    )
                    break  # Only report the first match to avoid noise

        # Check Kong-specific latency headers as a secondary gateway signal
        if headers.get("X-Kong-Proxy-Latency") or headers.get("X-Kong-Upstream-Latency"):
            already_reported = any(
                f.evidence.get("gateway_type") == "Kong Gateway" for f in findings
            )
            if not already_reported:
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="high",
                        title="Infrastructure: Kong Gateway",
                        evidence={
                            "header": "X-Kong-Proxy-Latency",
                            "value": headers.get("X-Kong-Proxy-Latency", ""),
                            "url": url,
                            "gateway_type": "Kong Gateway",
                        },
                    )
                )

        # Envoy signal via upstream service-time header
        if headers.get("X-Envoy-Upstream-Service-Time"):
            already_reported = any(
                f.evidence.get("gateway_type") == "Envoy Proxy" for f in findings
            )
            if not already_reported:
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="high",
                        title="Infrastructure: Envoy Proxy",
                        evidence={
                            "header": "X-Envoy-Upstream-Service-Time",
                            "value": headers.get("X-Envoy-Upstream-Service-Time", ""),
                            "url": url,
                            "gateway_type": "Envoy Proxy",
                        },
                    )
                )

        # Aggregated AI-stack disclosure summary (any backend/RAG hint).
        ai_section = catalog.get("ai_backend_hints", [])
        rag_section = catalog.get("rag_hints", [])
        ai_disclosed = {h: headers.get(h) for h in ai_section if headers.get(h)}
        rag_disclosed = {h: headers.get(h) for h in rag_section if headers.get(h)}

        if ai_disclosed or rag_disclosed:
            findings.append(
                self._make_finding(
                    target,
                    severity="medium",
                    confidence="high",
                    title="AI stack disclosed via response headers",
                    evidence={
                        "ai_backend": ai_disclosed,
                        "rag": rag_disclosed,
                        "url": url,
                    },
                )
            )

        return findings
