"""Passive OSINT model card lookup technique (HuggingFace + Ollama)."""
from __future__ import annotations

import logging
from typing import ClassVar

import httpx

from ai_recon.core.models import Finding, RunContext, Target
from ai_recon.techniques.base import Technique

logger = logging.getLogger(__name__)

# This technique makes outbound requests to external OSINT services.
# It intentionally bypasses the scope-enforced AIReconClient and uses a plain
# httpx.AsyncClient for these known-safe, read-only, external OSINT URLs only.
EXTERNAL_OSINT = True

_HF_API_BASE = "https://huggingface.co/api"
_OLLAMA_LIB_BASE = "https://ollama.com/library"
_TIMEOUT = 15.0


def _looks_like_hf_model_id(name: str) -> bool:
    """Return True if the name looks like an org/model HuggingFace ID."""
    return "/" in name and not name.startswith("http")


def _extract_model_hints(ctx: RunContext) -> list[str]:
    """Pull model name hints from the run context (if stored by earlier techniques)."""
    hints: list[str] = []
    model_hints = getattr(ctx, "model_hints", None)
    if model_hints and isinstance(model_hints, list):
        hints.extend(model_hints)
    return hints


class OSINTModelCardTechnique(Technique):
    id: ClassVar[str] = "passive.osint_model_card"
    intrusiveness: ClassVar = "passive"
    produces: ClassVar[set[str]] = {"ai.model_card", "ai.training_data"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        model_hints = _extract_model_hints(self.ctx)

        if not model_hints:
            return findings

        logger.warning(
            "[osint_model_card] Making external OSINT requests to huggingface.co and ollama.com. "
            "These requests bypass scope enforcement — this is intentional for external OSINT only."
        )

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(_TIMEOUT),
            follow_redirects=True,
            http2=True,
        ) as osint_client:
            for model_name in model_hints:
                model_name = model_name.strip()
                if not model_name:
                    continue

                # ── HuggingFace direct lookup (org/model format) ───────────────
                if _looks_like_hf_model_id(model_name):
                    findings.extend(
                        await self._lookup_hf_direct(osint_client, target, model_name)
                    )

                # ── HuggingFace name-based search ─────────────────────────────
                findings.extend(
                    await self._lookup_hf_search(osint_client, target, model_name)
                )

                # ── Ollama library check ───────────────────────────────────────
                findings.extend(
                    await self._lookup_ollama(osint_client, target, model_name)
                )

        return findings

    async def _lookup_hf_direct(
        self, client: httpx.AsyncClient, target: Target, model_id: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        url = f"{_HF_API_BASE}/models/{model_id}"
        try:
            resp = await client.get(url)
        except Exception:
            return findings

        if resp.status_code != 200:
            return findings

        try:
            data = resp.json()
        except Exception:
            return findings

        if not isinstance(data, dict):
            return findings

        card_data = data.get("cardData", {}) or {}
        datasets = card_data.get("datasets", [])
        evidence = {
            "model_id": data.get("modelId", model_id),
            "pipeline_tag": data.get("pipeline_tag"),
            "library_name": data.get("library_name"),
            "created_at": data.get("createdAt"),
            "last_modified": data.get("lastModified"),
            "tags": data.get("tags", []),
            "license": card_data.get("license"),
            "datasets": datasets,
            "language": card_data.get("language"),
            "source_url": f"https://huggingface.co/{model_id}",
        }

        findings.append(
            self._make_finding(
                target,
                severity="info",
                confidence="high",
                title=f"Model card found on HuggingFace: {model_id}",
                evidence=evidence,
            )
        )

        if datasets:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="high",
                    title="Training datasets disclosed",
                    evidence={
                        "model_id": model_id,
                        "datasets": datasets,
                        "source_url": f"https://huggingface.co/{model_id}",
                    },
                )
            )

        return findings

    async def _lookup_hf_search(
        self, client: httpx.AsyncClient, target: Target, model_name: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        # Sanitise model_name for query (strip org prefix if present)
        search_term = model_name.split("/")[-1] if "/" in model_name else model_name
        url = f"{_HF_API_BASE}/models"
        try:
            resp = await client.get(url, params={"search": search_term, "limit": "5"})
        except Exception:
            return findings

        if resp.status_code != 200:
            return findings

        try:
            results = resp.json()
        except Exception:
            return findings

        if not isinstance(results, list) or not results:
            return findings

        model_ids = [r.get("modelId", "") for r in results if isinstance(r, dict)]
        model_ids = [m for m in model_ids if m]

        if model_ids:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="medium",
                    title=f"HuggingFace model search results for: {search_term}",
                    evidence={
                        "search_term": search_term,
                        "matches": model_ids,
                        "source_url": f"{_HF_API_BASE}/models?search={search_term}&limit=5",
                    },
                )
            )

        return findings

    async def _lookup_ollama(
        self, client: httpx.AsyncClient, target: Target, model_name: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        # Use just the base name for Ollama (strip tag and org)
        base_name = model_name.split("/")[-1].split(":")[0].lower()
        url = f"{_OLLAMA_LIB_BASE}/{base_name}"
        try:
            resp = await client.get(url)
        except Exception:
            return findings

        if resp.status_code == 200:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="medium",
                    title=f"Model found in Ollama library: {base_name}",
                    evidence={
                        "model_name": base_name,
                        "source_url": url,
                    },
                )
            )

        return findings
