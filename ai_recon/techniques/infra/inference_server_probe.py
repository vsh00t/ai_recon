"""Inference-server endpoint probe.

Detects the underlying inference runtime (Ollama, vLLM, TGI, llama.cpp
server, Triton, LM Studio, LocalAI, OpenLLM) by querying signature paths.
"""

from __future__ import annotations

import asyncio
from typing import ClassVar

import httpx

from ai_recon.core.models import Finding, Target
from ai_recon.techniques.base import Technique


_SIGNATURES: list[dict] = [
    {"name": "ollama",      "path": "/api/tags",       "marker": "models"},
    {"name": "ollama",      "path": "/api/version",    "marker": "version"},
    {"name": "vllm",        "path": "/v1/models",      "marker": "vllm"},
    {"name": "vllm",        "path": "/version",        "marker": "vllm"},
    {"name": "tgi",         "path": "/info",           "marker": "model_id"},
    {"name": "tgi",         "path": "/metrics",        "marker": "tgi_"},
    {"name": "llamacpp",    "path": "/health",         "marker": "ok"},
    {"name": "llamacpp",    "path": "/props",          "marker": "default_generation_settings"},
    {"name": "lmstudio",    "path": "/v1/models",      "marker": "lmstudio"},
    {"name": "localai",     "path": "/readyz",         "marker": "OK"},
    {"name": "localai",     "path": "/v1/models",      "marker": "localai"},
    {"name": "triton",      "path": "/v2/health/ready","marker": ""},
    {"name": "triton",      "path": "/v2/models",      "marker": "triton"},
    {"name": "openllm",     "path": "/v1/models",      "marker": "openllm"},
    {"name": "ray-serve",   "path": "/-/routes",       "marker": "ray"},
]


class InferenceServerProbe(Technique):
    id: ClassVar[str] = "infra.inference_server_probe"
    intrusiveness: ClassVar[str] = "passive"
    requires: ClassVar[set[str]] = set()
    produces: ClassVar[set[str]] = {"infra.inference_server"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        detected: dict[str, dict] = {}

        async with httpx.AsyncClient(timeout=6.0, follow_redirects=False) as client:

            async def probe(sig: dict) -> tuple[dict, int, str]:
                url = f"{target.base_url.rstrip('/')}{sig['path']}"
                try:
                    r = await client.get(url)
                    return sig, r.status_code, r.text[:400]
                except Exception as exc:
                    return sig, -1, str(exc)

            results = await asyncio.gather(*(probe(s) for s in _SIGNATURES))

        for sig, status, body in results:
            if 200 <= status < 400 and (not sig["marker"] or sig["marker"].lower() in body.lower()):
                cur = detected.get(sig["name"])
                hit = {"name": sig["name"], "path": sig["path"],
                       "status": status, "preview": body[:200]}
                detected[sig["name"]] = hit
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="high",
                        title=f"Inference server detected: {sig['name']} ({sig['path']})",
                        evidence=hit,
                    )
                )

        findings.append(
            self._make_finding(
                target,
                severity="info",
                confidence="high",
                title=f"Inference-server probe: {len(detected)} runtime(s)",
                evidence={"detected": list(detected.values())},
            )
        )
        return findings
