"""Quick port/API sweep for basic recon profiles.

Performs a fast TCP open-port check on common AI/web ports, then probes a
small set of common API endpoints on each open port.
"""
from __future__ import annotations

import asyncio
from typing import ClassVar

import httpx

from ai_recon.core.models import Finding, Target
from ai_recon.techniques.base import Technique


_QUICK_PORTS: list[int] = [
    80, 443, 3000, 4000, 5000, 8000, 8080, 8443, 11434,
]

_COMMON_API_PATHS: list[str] = [
    "api/health",
    "api/status",
    "api/version",
    "api/config",
    "v1/models",
    "v1/chat/completions",
    "health",
    "healthz",
    "readyz",
    "version",
    "openapi.json",
    "swagger.json",
]


async def _port_open(host: str, port: int, timeout: float = 1.2) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _probe_endpoint(client: httpx.AsyncClient, url: str) -> dict | None:
    try:
        resp = await client.head(url, timeout=4.0, follow_redirects=False)
        method = "HEAD"
        if resp.status_code in (405, 501):
            resp = await client.get(url, timeout=4.0, follow_redirects=False)
            method = "GET"
        return {
            "status": resp.status_code,
            "method": method,
            "content_type": resp.headers.get("content-type", ""),
        }
    except Exception:
        return None


class QuickPortApiSweep(Technique):
    id: ClassVar[str] = "active.quick_port_api_sweep"
    intrusiveness: ClassVar[str] = "low"
    produces: ClassVar[set[str]] = {"service.ports", "service.paths"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        host = target.host

        checks = [_port_open(host, p) for p in _QUICK_PORTS]
        is_open = await asyncio.gather(*checks, return_exceptions=False)
        open_ports = [p for p, ok in zip(_QUICK_PORTS, is_open) if ok]

        findings.append(
            self._make_finding(
                target,
                severity="info",
                confidence="high",
                title=f"Quick port sweep: {len(open_ports)} open / {len(_QUICK_PORTS)} tested",
                evidence={
                    "tested_ports": _QUICK_PORTS,
                    "open_ports": open_ports,
                },
                references=[],
            )
        )

        endpoint_hits: list[dict] = []
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
            for port in open_ports:
                scheme = "https" if port in (443, 8443) else "http"
                tasks = []
                for path in _COMMON_API_PATHS:
                    tasks.append(_probe_endpoint(client, f"{scheme}://{host}:{port}/{path}"))
                results = await asyncio.gather(*tasks, return_exceptions=False)

                for path, res in zip(_COMMON_API_PATHS, results):
                    if not res:
                        continue
                    if res["status"] not in (400, 404, 410):
                        endpoint_hits.append(
                            {
                                "port": port,
                                "scheme": scheme,
                                "path": path,
                                "status": res["status"],
                                "method": res["method"],
                                "content_type": res["content_type"],
                            }
                        )

        if endpoint_hits:
            findings.append(
                self._make_finding(
                    target,
                    severity="medium",
                    confidence="high",
                    title=f"Quick API sweep: {len(endpoint_hits)} endpoint(s) responded on open ports",
                    evidence={
                        "hits": endpoint_hits,
                        "paths_tested_per_port": _COMMON_API_PATHS,
                    },
                    references=[],
                )
            )
        else:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="high",
                    title="Quick API sweep: no common endpoint hits on open ports",
                    evidence={
                        "open_ports": open_ports,
                        "paths_tested_per_port": _COMMON_API_PATHS,
                    },
                    references=[],
                )
            )

        return findings
