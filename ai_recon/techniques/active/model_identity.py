"""Model identity technique — asks model to self-identify and matches against vendors catalog."""
from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

import yaml

from ai_recon.adapters.llm_protocol.openai_compat import OpenAICompatAdapter
from ai_recon.core.models import Finding, Message, ModelProfile, RunContext, Target
from ai_recon.core.errors import TechniqueAborted
from ai_recon.techniques.base import Technique

CATALOG_DIR = Path(__file__).parent.parent.parent / "catalogs"


def _load_vendors() -> list[dict]:
    path = CATALOG_DIR / "vendors.yaml"
    try:
        with path.open() as fh:
            data = yaml.safe_load(fh)
        return data.get("vendors", [])
    except Exception:
        return []


def _score_vendor(vendor: dict, text: str) -> float:
    patterns: list[str] = vendor.get("self_id_patterns", [])
    if not patterns:
        return 0.0
    matched = sum(
        1 for p in patterns if re.search(p, text, re.IGNORECASE)
    )
    return round(matched / len(patterns), 4)


class ModelIdentity(Technique):
    id: ClassVar[str] = "active.model_identity"
    intrusiveness: ClassVar[str] = "low"
    produces: ClassVar[set[str]] = {"model.vendor", "model.family"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        vendors = _load_vendors()

        # Build adapter
        adapter = getattr(self.ctx, "llm_adapter", None)
        if adapter is None:
            adapter = OpenAICompatAdapter(base_url=target.base_url)

        prompt = (
            "What model are you? Which company created you? "
            "Be specific about version if you know it."
        )

        try:
            resp = await adapter.chat([Message(role="user", content=prompt)])
            text = resp.text
        except Exception as exc:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="low",
                    title="Model identity probe failed",
                    evidence={"error": str(exc)},
                    references=[],
                )
            )
            return findings

        # Score each vendor
        scores: list[tuple[float, dict]] = []
        for vendor in vendors:
            score = _score_vendor(vendor, text)
            if score > 0.0:
                scores.append((score, vendor))

        scores.sort(key=lambda x: x[0], reverse=True)

        if not scores:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="low",
                    title="Model identity: unrecognised vendor",
                    evidence={"response_text": text, "vendor": None, "confidence": 0.0},
                    references=[],
                )
            )
            return findings

        top_score, top_vendor = scores[0]
        vendor_id = top_vendor.get("id", "unknown")
        display_name = top_vendor.get("display_name", vendor_id)
        families: list[str] = top_vendor.get("families", [])

        # Try to determine family from response text
        matched_family: str | None = None
        for family in families:
            if re.search(re.escape(family), text, re.IGNORECASE):
                matched_family = family
                break
        if matched_family is None and families:
            matched_family = families[0]

        profile = ModelProfile(
            vendor=vendor_id,
            family=matched_family,
            confidence=top_score,
        )

        # Store on ctx for subsequent techniques
        try:
            self.ctx.model_profile = profile  # type: ignore[attr-defined]
        except Exception:
            pass

        findings.append(
            self._make_finding(
                target,
                severity="info",
                confidence="high" if top_score >= 0.5 else "medium" if top_score >= 0.2 else "low",
                title=f"Model identity: {display_name} {matched_family or ''}".strip(),
                evidence={
                    "response_text": text,
                    "vendor": vendor_id,
                    "display_name": display_name,
                    "family": matched_family,
                    "confidence": top_score,
                    "all_scores": [
                        {"vendor": v.get("id"), "score": s} for s, v in scores[:5]
                    ],
                },
                references=[],
            )
        )

        return findings
