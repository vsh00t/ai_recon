"""Vector-DB endpoint probe.

Probes well-known administrative endpoints of common vector databases
(Chroma, Qdrant, Weaviate, Milvus, Pinecone, pgvector via PostgREST).
Identifies the vendor and reports any unauthenticated admin surface.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import ClassVar

import httpx
import yaml

from ai_recon.core.models import Finding, Target
from ai_recon.techniques.base import Technique


_CATALOG = Path(__file__).parent.parent.parent / "catalogs" / "vector_dbs.yaml"


def _load_signatures() -> list[dict]:
    try:
        data = yaml.safe_load(_CATALOG.read_text()) or {}
    except FileNotFoundError:
        data = {}
    return data.get("vector_dbs", []) or _DEFAULT_SIGNATURES


_DEFAULT_SIGNATURES: list[dict] = [
    {"name": "chroma",   "paths": ["/api/v1/heartbeat", "/api/v1/collections"]},
    {"name": "qdrant",   "paths": ["/collections", "/cluster"]},
    {"name": "weaviate", "paths": ["/v1/meta", "/v1/schema"]},
    {"name": "milvus",   "paths": ["/api/v1/health", "/api/v1/collections"]},
    {"name": "pgvector", "paths": ["/rpc/version"]},  # via PostgREST
]


class VectorDBProbe(Technique):
    id: ClassVar[str] = "infra.vector_db_probe"
    intrusiveness: ClassVar[str] = "low"
    requires: ClassVar[set[str]] = set()
    produces: ClassVar[set[str]] = {"infra.vector_db"}

    async def run(self, target: Target) -> list[Finding]:
        sigs = _load_signatures()
        findings: list[Finding] = []
        detected: list[dict] = []

        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:

            async def probe(name: str, path: str) -> tuple[str, str, int, str]:
                url = f"{target.base_url.rstrip('/')}{path}"
                try:
                    r = await client.get(url)
                    return name, path, r.status_code, r.text[:300]
                except Exception as exc:
                    return name, path, -1, str(exc)

            tasks = [probe(s["name"], p) for s in sigs for p in s["paths"]]
            results = await asyncio.gather(*tasks)

        for name, path, status, body in results:
            if 200 <= status < 400:
                detected.append({"vendor": name, "path": path,
                                 "status": status, "preview": body[:200]})
                findings.append(
                    self._make_finding(
                        target,
                        severity="medium",
                        confidence="high",
                        title=f"Vector DB '{name}' admin endpoint reachable: {path}",
                        evidence={"vendor": name, "path": path,
                                  "status": status, "preview": body[:300]},
                    )
                )

        findings.append(
            self._make_finding(
                target,
                severity="info",
                confidence="high",
                title=f"Vector-DB probe: {len(detected)} endpoint(s) detected",
                evidence={"detected": detected, "probed": len(results)},
            )
        )
        return findings
