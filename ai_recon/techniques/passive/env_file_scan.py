"""Env-file scanner.

Looks for accidental web-served ``.env``, ``.env.local`` and similar files.
Extracts variable names (NEVER values, never logs secrets) and matches keys
against AI-relevant patterns (OPENAI_API_KEY, HF_TOKEN, etc).
"""

from __future__ import annotations

import asyncio
import re
from typing import ClassVar

import httpx

from ai_recon.core.models import Finding, Target
from ai_recon.techniques.base import Technique


_PATHS: list[str] = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.envrc",
    "/config/.env",
    "/app/.env",
    "/.env.example",
]

_AI_KEY_RE = re.compile(
    r"(?i)\b(?:OPENAI|ANTHROPIC|HUGGINGFACE|HF|GOOGLE_GENAI|GEMINI|MISTRAL|"
    r"COHERE|TOGETHER|REPLICATE|GROQ|FIREWORKS|AZURE_OPENAI|BEDROCK|"
    r"LANGCHAIN|LANGSMITH|PINECONE|WEAVIATE|QDRANT|CHROMA|MILVUS)_"
    r"(?:API[_-]?KEY|TOKEN|SECRET|ENDPOINT)\b"
)


def _vars_only(text: str) -> list[str]:
    """Extract variable NAMES only — never values."""
    names: list[str] = []
    for m in re.finditer(r"^\s*([A-Z_][A-Z0-9_]*)\s*=", text, re.MULTILINE):
        names.append(m.group(1))
    return names


class EnvFileScan(Technique):
    id: ClassVar[str] = "passive.env_file_scan"
    intrusiveness: ClassVar[str] = "passive"
    produces: ClassVar[set[str]] = {"infra.env_exposure"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        leaks: list[dict] = []

        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:

            async def fetch(p: str) -> tuple[str, int, str]:
                url = f"{target.base_url.rstrip('/')}{p}"
                try:
                    r = await client.get(url)
                    return p, r.status_code, r.text
                except Exception:
                    return p, -1, ""

            results = await asyncio.gather(*(fetch(p) for p in _PATHS))

        for path, status, body in results:
            if not (200 <= status < 300):
                continue
            # Reject HTML pages disguised as .env
            if "<html" in body[:200].lower():
                continue
            names = _vars_only(body)
            if not names:
                continue
            ai_keys = [n for n in names if _AI_KEY_RE.search(n)]
            entry = {
                "path": path,
                "var_count": len(names),
                "var_names": names[:50],
                "ai_relevant_var_names": ai_keys,
            }
            leaks.append(entry)
            sev = "high" if ai_keys else "medium"
            findings.append(
                self._make_finding(
                    target, severity=sev, confidence="high",
                    title=f"Exposed .env file: {path} ({len(names)} vars)",
                    evidence=entry,
                )
            )

        findings.append(
            self._make_finding(
                target, severity="info", confidence="high",
                title=f"Env scan: {len(leaks)} exposed file(s)",
                evidence={"leaks_count": len(leaks), "probed": len(_PATHS)},
            )
        )
        return findings
