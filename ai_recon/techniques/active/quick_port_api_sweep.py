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
    80, 81, 82, 83, 84, 85, 88,
    443, 444, 445, 591, 593, 631,
    1080, 3000, 3001, 3002, 3333,
    4000, 5000, 5001, 5050, 5601, 5984,
    7000, 7001,
    8000, 8001, 8002, 8008, 8010, 8080, 8081, 8082, 8088, 8090,
    8181, 8200, 8333, 8443, 8500, 8600, 8888, 8889,
    9000, 9001, 9043, 9090, 9200, 9300, 9443,
    11434,
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

_V1_ENUM_PATHS: list[str] = [
    "v1/auth",
    "v1/billing",
    "v1/chat/completions",
    "v1/completions",
    "v1/embeddings",
    "v1/moderations",
    "v1/models",
    "v1/users",
]

_HEALTH_PATHS: list[str] = [
    "api/health", "api/status", "-/health", "healthz", "livez",
    "readyz", "metrics", "info", "status", "health",
]

_CHAT_PATHS: list[str] = [
    "v1/chat/completions",
    "chat/completions",
    "api/chat/completions",
    "api/v1/chat/completions",
]


def _interesting_headers(headers: httpx.Headers) -> dict[str, str]:
    keep: dict[str, str] = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl in ("server", "via", "content-type") or kl.startswith("x-kong-") or kl.startswith("ratelimit") or kl.startswith("x-ratelimit"):
            keep[k] = v
    return keep


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
            "headers": _interesting_headers(resp.headers),
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
        v1_matrix: list[dict] = []
        per_port_replay: list[dict] = []

        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
            for port in open_ports:
                scheme = "https" if port in (443, 8443) else "http"
                port_result: dict = {
                    "port": port,
                    "scheme": scheme,
                    "root": {},
                    "health_hits": [],
                    "models_probe": {},
                    "chat_probes": [],
                    "common_hits": [],
                    "v1_matrix": [],
                }

                # 1) Root/header probe
                root_probe = await _probe_endpoint(client, f"{scheme}://{host}:{port}/")
                if root_probe:
                    port_result["root"] = {
                        "status": root_probe["status"],
                        "method": root_probe["method"],
                        "headers": root_probe["headers"],
                    }

                # 2) Health probes
                health_tasks = [
                    _probe_endpoint(client, f"{scheme}://{host}:{port}/{path}")
                    for path in _HEALTH_PATHS
                ]
                health_results = await asyncio.gather(*health_tasks, return_exceptions=False)
                for path, res in zip(_HEALTH_PATHS, health_results):
                    if not res:
                        continue
                    if res["status"] not in (400, 404, 410):
                        port_result["health_hits"].append(
                            {
                                "path": path,
                                "status": res["status"],
                                "method": res["method"],
                                "headers": res["headers"],
                            }
                        )

                # 3) OpenAI-compatible baseline probes
                models_probe = await _probe_endpoint(client, f"{scheme}://{host}:{port}/v1/models")
                if models_probe:
                    port_result["models_probe"] = {
                        "status": models_probe["status"],
                        "method": models_probe["method"],
                        "headers": models_probe["headers"],
                    }

                for chat_path in _CHAT_PATHS:
                    chat_url = f"{scheme}://{host}:{port}/{chat_path}"
                    try:
                        chat_resp = await client.post(
                            chat_url,
                            json={
                                "model": "gpt-3.5-turbo",
                                "messages": [{"role": "user", "content": "Hi"}],
                                "max_tokens": 8,
                            },
                            timeout=5.0,
                        )
                        port_result["chat_probes"].append(
                            {
                                "path": chat_path,
                                "status": chat_resp.status_code,
                                "headers": _interesting_headers(chat_resp.headers),
                            }
                        )
                    except Exception:
                        continue

                # 4) Common API path sweep
                tasks = []
                for path in _COMMON_API_PATHS:
                    tasks.append(_probe_endpoint(client, f"{scheme}://{host}:{port}/{path}"))
                results = await asyncio.gather(*tasks, return_exceptions=False)

                for path, res in zip(_COMMON_API_PATHS, results):
                    if not res:
                        continue
                    if res["status"] not in (400, 404, 410):
                        hit = {
                            "port": port,
                            "scheme": scheme,
                            "path": path,
                            "status": res["status"],
                            "method": res["method"],
                            "content_type": res["content_type"],
                            "headers": res["headers"],
                        }
                        endpoint_hits.append(hit)
                        port_result["common_hits"].append(
                            {
                                "path": path,
                                "status": res["status"],
                                "method": res["method"],
                                "headers": res["headers"],
                            }
                        )

                # 5) Explicit 401-vs-404 versioned API matrix
                v1_tasks = []
                for path in _V1_ENUM_PATHS:
                    v1_tasks.append(_probe_endpoint(client, f"{scheme}://{host}:{port}/{path}"))
                v1_results = await asyncio.gather(*v1_tasks, return_exceptions=False)
                for path, res in zip(_V1_ENUM_PATHS, v1_results):
                    if not res:
                        continue
                    row = {
                        "port": port,
                        "scheme": scheme,
                        "path": path,
                        "status": res["status"],
                        "method": res["method"],
                        "headers": res["headers"],
                    }
                    v1_matrix.append(row)
                    port_result["v1_matrix"].append(row)

                per_port_replay.append(port_result)

        protected_hits = [h for h in endpoint_hits if h["status"] == 401]
        protected_v1_hits = [h for h in v1_matrix if h["status"] == 401]
        gateway_hits = [
            h for h in endpoint_hits
            if h.get("headers", {}).get("Server", "").lower().startswith("kong/")
            or any(k.lower().startswith("x-kong-") for k in h.get("headers", {}))
        ]

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

        if protected_hits:
            findings.append(
                self._make_finding(
                    target,
                    severity="medium",
                    confidence="high",
                    title=f"Protected API endpoint(s) discovered on open ports: {len(protected_hits)}",
                    evidence={"protected_hits": protected_hits},
                    references=[],
                )
            )

        if protected_v1_hits:
            findings.append(
                self._make_finding(
                    target,
                    severity="high",
                    confidence="high",
                    title=f"401-vs-404 enumeration: {len(protected_v1_hits)} protected endpoint(s) confirmed (exist but require auth)",
                    evidence={
                        "technique": "Endpoints returning 401 exist on the server but require authentication. Endpoints returning 404 do not exist and are suppressed.",
                        "protected_endpoints": protected_v1_hits,
                        "paths_probed": _V1_ENUM_PATHS,
                    },
                    references=[],
                )
            )
        elif open_ports:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="high",
                    title="401-vs-404 enumeration: no protected versioned endpoints found (all returned 404)",
                    evidence={
                        "technique": "Probed common versioned API paths. All returned 404 (do not exist) or no response.",
                        "paths_probed": _V1_ENUM_PATHS,
                        "ports_scanned": open_ports,
                    },
                    references=[],
                )
            )

        if gateway_hits:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="high",
                    title=f"Gateway/API-management headers observed on open ports: {len(gateway_hits)}",
                    evidence={"gateway_hits": gateway_hits},
                    references=[],
                )
            )

        if per_port_replay:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="high",
                    title=f"Per-open-port initial-test replay completed: {len(per_port_replay)} port(s)",
                    evidence={
                        "ports_replayed": len(per_port_replay),
                        "per_port": per_port_replay,
                    },
                    references=[],
                )
            )

        return findings
