"""CI / CD configuration scanner.

Looks for CI configuration files frequently checked into webroots
(/.github/workflows/*, /.gitlab-ci.yml, /Jenkinsfile, etc.) that often
expose pipeline structure, secret references and AI-related steps.
"""

from __future__ import annotations

import asyncio
import re
from typing import ClassVar

import httpx

from ai_recon.core.models import Finding, Target
from ai_recon.techniques.base import Technique


_PATHS: list[str] = [
    "/.github/workflows/main.yml",
    "/.github/workflows/ci.yml",
    "/.github/workflows/deploy.yml",
    "/.gitlab-ci.yml",
    "/Jenkinsfile",
    "/azure-pipelines.yml",
    "/bitbucket-pipelines.yml",
    "/.circleci/config.yml",
    "/.drone.yml",
    "/.travis.yml",
    "/buildkite/pipeline.yml",
]

_AI_KEYWORDS = re.compile(
    r"(?i)\b(?:openai|anthropic|huggingface|langchain|llm|gpt|claude|gemini|"
    r"ollama|vllm|tgi|bedrock|azure-openai|prompt|embed)\b"
)
_SECRET_KEYWORDS = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|token|password|credential)\b"
)


class CIConfigScan(Technique):
    id: ClassVar[str] = "passive.ci_config_scan"
    intrusiveness: ClassVar[str] = "passive"
    requires: ClassVar[set[str]] = set()
    produces: ClassVar[set[str]] = {"infra.ci_config"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        found: list[dict] = []

        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:

            async def fetch(p: str) -> tuple[str, int, str]:
                url = f"{target.base_url.rstrip('/')}{p}"
                try:
                    r = await client.get(url)
                    return p, r.status_code, r.text[:30_000]
                except Exception:
                    return p, -1, ""

            results = await asyncio.gather(*(fetch(p) for p in _PATHS))

        for path, status, body in results:
            if not (200 <= status < 300) or "<html" in body[:200].lower():
                continue
            ai_hits     = bool(_AI_KEYWORDS.search(body))
            secret_hits = len(_SECRET_KEYWORDS.findall(body))
            entry = {"path": path, "status": status,
                     "ai_keywords": ai_hits, "secret_refs": secret_hits,
                     "preview": body[:400]}
            found.append(entry)
            sev = "medium" if ai_hits and secret_hits >= 1 else "low"
            findings.append(
                self._make_finding(
                    target, severity=sev, confidence="medium",
                    title=f"CI config exposed: {path}",
                    evidence=entry,
                )
            )

        findings.append(
            self._make_finding(
                target,
                severity="info",
                confidence="high",
                title=f"CI scan: {len(found)} config(s) reachable",
                evidence={"found": found, "probed": len(_PATHS)},
            )
        )
        return findings
