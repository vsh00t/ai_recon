"""Service discovery technique — crawls paths, checks robots/sitemap, port-scans AI ports."""
from __future__ import annotations

import asyncio
import re
from typing import ClassVar
from urllib.parse import urljoin, urlparse

import httpx

from ai_recon.core.models import Finding, RunContext, Target
from ai_recon.core.errors import TechniqueAborted
from ai_recon.techniques.base import Technique

AI_PORTS: list[int] = [
    80, 443, 8000, 8008, 8080, 8443, 8888,
    11434, 4000, 3000, 5000, 5001, 6333, 8001, 19530,
]

_HREF_RE = re.compile(r'href=["\']([^"\'#?]+)["\']', re.IGNORECASE)
_SRC_RE  = re.compile(r'src=["\']([^"\'#?]+)["\']',  re.IGNORECASE)
_LINK_RE = re.compile(r'<link[^>]+href=["\']([^"\'#?]+)["\']', re.IGNORECASE)


def _extract_paths(html: str, base_url: str) -> set[str]:
    paths: set[str] = set()
    parsed_base = urlparse(base_url)
    for pattern in (_HREF_RE, _SRC_RE, _LINK_RE):
        for raw in pattern.findall(html):
            raw = raw.strip()
            if not raw or raw.startswith("data:") or raw.startswith("mailto:"):
                continue
            parsed = urlparse(raw)
            if parsed.scheme in ("http", "https"):
                # Only keep same-host paths
                if parsed.netloc == parsed_base.netloc:
                    if parsed.path:
                        paths.add(parsed.path.lstrip("/"))
            elif not parsed.scheme and parsed.path:
                paths.add(parsed.path.lstrip("/"))
    return paths


async def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _head_service_hint(client: httpx.AsyncClient, scheme: str, host: str, port: int) -> dict:
    url = f"{scheme}://{host}:{port}/"
    try:
        resp = await client.head(url, timeout=5.0, follow_redirects=True)
        return {
            "status_code": resp.status_code,
            "server": resp.headers.get("server", ""),
            "content_type": resp.headers.get("content-type", ""),
            "x_powered_by": resp.headers.get("x-powered-by", ""),
        }
    except Exception as exc:
        return {"error": str(exc)}


class ServiceDiscovery(Technique):
    id: ClassVar[str] = "active.service_discovery"
    intrusiveness: ClassVar[str] = "low"
    produces: ClassVar[set[str]] = {"service.ports", "service.paths"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        discovered_paths: set[str] = set()

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            # ── 1. Crawl base URL for links ──────────────────────────────────
            try:
                resp = await client.get(f"{target.base_url}/")
                html = resp.text
                discovered_paths |= _extract_paths(html, target.base_url)
            except Exception:
                html = ""

            # ── 2. robots.txt ────────────────────────────────────────────────
            try:
                robots_resp = await client.get(f"{target.base_url}/robots.txt")
                if robots_resp.status_code == 200:
                    for line in robots_resp.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith(("allow:", "disallow:")):
                            path = line.split(":", 1)[1].strip().lstrip("/")
                            if path and path != "*":
                                discovered_paths.add(path.split("?")[0])
            except Exception:
                pass

            # ── 3. sitemap.xml ───────────────────────────────────────────────
            try:
                sitemap_resp = await client.get(f"{target.base_url}/sitemap.xml")
                if sitemap_resp.status_code == 200:
                    locs = re.findall(r"<loc>([^<]+)</loc>", sitemap_resp.text)
                    base_parsed = urlparse(target.base_url)
                    for loc in locs:
                        p = urlparse(loc)
                        if p.path:
                            discovered_paths.add(p.path.lstrip("/"))
            except Exception:
                pass

            # ── 4. Port scan ─────────────────────────────────────────────────
            parsed = urlparse(target.base_url)
            host = parsed.hostname or target.host

            scan_tasks = [_port_open(host, port) for port in AI_PORTS]
            results = await asyncio.gather(*scan_tasks, return_exceptions=True)

            open_ports: list[int] = []
            for port, result in zip(AI_PORTS, results):
                if result is True:
                    open_ports.append(port)

            # ── 5. HEAD each open port for service hint ──────────────────────
            for port in open_ports:
                scheme = "https" if port in (443, 8443) else "http"
                hint = await _head_service_hint(client, scheme, host, port)

                # Guess service from headers + port
                service = "unknown"
                server_hdr = hint.get("server", "").lower()
                if "ollama" in server_hdr or port == 11434:
                    service = "ollama"
                elif "vllm" in server_hdr or port in (8000, 8001):
                    service = "vllm/openai-compat"
                elif "qdrant" in server_hdr or port == 6333:
                    service = "qdrant"
                elif "milvus" in server_hdr or port == 19530:
                    service = "milvus"
                elif "nginx" in server_hdr:
                    service = "nginx"
                elif "caddy" in server_hdr:
                    service = "caddy"
                elif server_hdr:
                    service = server_hdr.split("/")[0]

                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="high",
                        title=f"Open port: {host}:{port} ({service})",
                        evidence={
                            "host": host,
                            "port": port,
                            "service_hint": service,
                            "head_response": hint,
                        },
                        references=[],
                    )
                )

            # ── 6. Paths summary finding ─────────────────────────────────────
            if discovered_paths:
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="medium",
                        title=f"Discovered {len(discovered_paths)} unique paths",
                        evidence={
                            "paths": sorted(discovered_paths),
                            "sources": ["html_crawl", "robots.txt", "sitemap.xml"],
                        },
                        references=[],
                    )
                )

        return findings
