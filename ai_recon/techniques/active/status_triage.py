"""Status triage technique — probes wordlist of API paths, classifies HTTP responses."""
from __future__ import annotations

import asyncio
from typing import ClassVar

import httpx

from ai_recon.core.models import Finding, RunContext, Target
from ai_recon.core.errors import TechniqueAborted
from ai_recon.techniques.base import Technique

WORDLIST: list[str] = [
    "v1/chat/completions", "v1/models", "v1/embeddings", "v1/completions",
    "api/chat", "api/v2/chat", "api/ask", "api/query", "api/generate",
    "api/messages", "api/completions", "auth", "billing", "admin",
    "users", "keys", "tokens", "config", "settings", "internal",
    "debug", "metrics", "health", "docs", "openapi.json", "swagger.json",
]

# status → (classification, severity, description)
_STATUS_MAP: dict[int, tuple[str, str, str]] = {
    200: ("public",              "medium", "Unexpected public access"),
    401: ("protected",           "info",   "Endpoint exists but requires authentication"),
    403: ("protected",           "info",   "Endpoint exists but access is forbidden"),
    405: ("exists_wrong_method", "info",   "Endpoint exists — try different HTTP method"),
    429: ("rate_limited",        "info",   "Rate-limited — endpoint active"),
    500: ("server_error",        "low",    "Server error — endpoint exists"),
}


async def _probe(client: httpx.AsyncClient, url: str) -> tuple[str, int, dict]:
    try:
        resp = await client.get(url, timeout=8.0, follow_redirects=False)
        return url, resp.status_code, {
            "content_type": resp.headers.get("content-type", ""),
            "content_length": resp.headers.get("content-length", ""),
            "server": resp.headers.get("server", ""),
        }
    except httpx.TimeoutException:
        return url, -1, {"error": "timeout"}
    except Exception as exc:
        return url, -1, {"error": str(exc)}


class StatusTriage(Technique):
    id: ClassVar[str] = "active.status_triage"
    intrusiveness: ClassVar[str] = "low"
    produces: ClassVar[set[str]] = {"service.endpoint_map"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        summary: dict[str, dict] = {}

        async with httpx.AsyncClient(timeout=10.0) as client:
            tasks = [
                _probe(client, f"{target.base_url.rstrip('/')}/{path}")
                for path in WORDLIST
            ]
            # Run with mild concurrency cap
            semaphore = asyncio.Semaphore(10)

            async def bounded(coro):
                async with semaphore:
                    return await coro

            results = await asyncio.gather(
                *[bounded(t) for t in tasks], return_exceptions=True
            )

        for item in results:
            if isinstance(item, Exception):
                continue
            url, status, meta = item
            path = url.split(target.base_url.rstrip("/") + "/", 1)[-1]

            if status not in _STATUS_MAP:
                summary[path] = {"status": status, "classification": "absent"}
                continue

            classification, severity, description = _STATUS_MAP[status]
            summary[path] = {"status": status, "classification": classification, **meta}

            # Emit per-path finding for interesting statuses
            findings.append(
                self._make_finding(
                    target,
                    severity=severity,
                    confidence="high",
                    title=f"{description}: /{path} → HTTP {status}",
                    evidence={
                        "path": path,
                        "url": url,
                        "status_code": status,
                        "classification": classification,
                        **meta,
                    },
                    references=[],
                )
            )

        # Aggregate summary finding
        findings.append(
            self._make_finding(
                target,
                severity="info",
                confidence="high",
                title=f"Status triage complete: {len(WORDLIST)} paths probed",
                evidence={
                    "endpoint_map": summary,
                    "public_count":   sum(1 for v in summary.values() if v.get("classification") == "public"),
                    "protected_count": sum(1 for v in summary.values() if v.get("classification") == "protected"),
                    "error_count":    sum(1 for v in summary.values() if v.get("classification") == "server_error"),
                },
                references=[],
            )
        )

        return findings
