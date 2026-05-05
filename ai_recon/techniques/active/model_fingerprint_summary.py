"""Model fingerprint summary technique.

Aggregates the results of model_identity, model_contradiction, model_behavior,
model_cutoff and context_window into a single operational finding that maps
directly to the "Fingerprinting and Model Identification" methodology.

Run this last in the fingerprinting sequence so that ctx.model_profile is
fully populated by the other techniques before this one executes.
"""
from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import yaml

from ai_recon.adapters.llm_protocol.openai_compat import OpenAICompatAdapter
from ai_recon.core.models import Finding, Target
from ai_recon.techniques.base import Technique

CATALOG_DIR = Path(__file__).parent.parent.parent / "catalogs"

# Known context window thresholds associated with model families
_CONTEXT_FINGERPRINTS: list[tuple[int, int, str]] = [
    # (lower_bound, upper_bound, label)
    (0,      512,     "< 1K tokens — very small model (1B-3B) or misconfigured"),
    (512,    5000,    "~4K tokens — Llama 3.x default, GPT-3.5-turbo style"),
    (5000,   10000,   "~8K tokens — Llama 3.2 extended, Mistral 7B default"),
    (10000,  20000,   "~16K tokens — Mistral 7B extended / Llama 70B default"),
    (20000,  40000,   "~32K tokens — Qwen2.5 7B/14B, Llama 3.1 extended"),
    (40000,  70000,   "~64K tokens — Qwen2.5 72B, DeepSeek 7B extended"),
    (70000,  150000,  "~128K tokens — Mistral Large, Qwen2.5 32B+"),
    (150000, 250000,  "~200K tokens — Claude 3/4 style"),
    (250000, 600000,  "~400K tokens — GPT-4 128K / Claude extended"),
    (600000, 10**9,   "> 600K tokens — frontier model (GPT-5, Gemini 2)"),
]


def _classify_context_window(tokens: int) -> str:
    for lo, hi, label in _CONTEXT_FINGERPRINTS:
        if lo <= tokens < hi:
            return label
    return f"{tokens:,} tokens — unclassified"


def _load_vendor_info(vendor_id: str) -> dict:
    path = CATALOG_DIR / "vendors.yaml"
    try:
        with path.open() as fh:
            data = yaml.safe_load(fh)
        for v in data.get("vendors", []):
            if v.get("id") == vendor_id:
                return v
    except Exception:
        pass
    return {}


def _severity_for_confidence(confidence: float) -> str:
    if confidence >= 0.7:
        return "medium"
    if confidence >= 0.4:
        return "low"
    return "info"


class ModelFingerprintSummary(Technique):
    """Consolidates all fingerprinting signals into one summary finding."""

    id: ClassVar[str] = "active.model_fingerprint_summary"
    intrusiveness: ClassVar[str] = "low"
    requires: ClassVar[set[str]] = {"model.vendor"}
    produces: ClassVar[set[str]] = {"model.fingerprint_summary"}

    async def run(self, target: Target) -> list[Finding]:
        profile = getattr(self.ctx, "model_profile", None)
        contradiction = getattr(self.ctx, "contradiction_result", None)

        # ── Gather all signals ────────────────────────────────────────────────
        vendor_id: str | None = getattr(profile, "vendor", None) if profile else None
        family: str | None = getattr(profile, "family", None) if profile else None
        identity_confidence: float = getattr(profile, "confidence", 0.0) if profile else 0.0
        knowledge_cutoff: str | None = getattr(profile, "knowledge_cutoff", None) if profile else None
        context_window: int | None = getattr(profile, "context_window", None) if profile else None
        verbosity_score: float | None = getattr(profile, "verbosity_score", None) if profile else None
        code_style: dict = getattr(profile, "code_style_signature", {}) if profile else {}

        vendor_info = _load_vendor_info(vendor_id) if vendor_id else {}
        display_name = vendor_info.get("display_name", vendor_id or "Unknown")
        attack_surface = vendor_info.get("attack_surface_hints", [])
        jailbreak_notes = vendor_info.get("jailbreak_notes", "")

        # ── Contradiction enrichment ──────────────────────────────────────────
        contradiction_confidence: str = "n/a"
        contradiction_vendors: list[str] = []
        small_model_signal = False
        if contradiction:
            rate = contradiction.get("correction_rate", 0.0)
            small_model_signal = contradiction.get("small_model_signal", False)
            contradiction_vendors = contradiction.get("likely_vendors", [])
            if rate >= 0.6:
                contradiction_confidence = "high (model self-corrects)"
            elif rate >= 0.3:
                contradiction_confidence = "medium (partial self-correction)"
            elif small_model_signal:
                contradiction_confidence = "low — model accepted false attribution (small model)"
            else:
                contradiction_confidence = "low (no corrections observed)"

        # ── Context window classification ─────────────────────────────────────
        context_label: str | None = None
        if context_window is not None and context_window > 0:
            context_label = _classify_context_window(context_window)

        # ── Aggregate overall confidence ──────────────────────────────────────
        signals = 0
        total_weight = 0.0

        if identity_confidence > 0:
            signals += 1
            total_weight += identity_confidence
        if contradiction_vendors:
            signals += 1
            total_weight += 0.8
        if knowledge_cutoff and knowledge_cutoff != "unknown":
            signals += 1
            total_weight += 0.6
        if context_window and context_window > 0:
            signals += 1
            total_weight += 0.5
        if verbosity_score is not None:
            signals += 1
            total_weight += 0.3

        overall_confidence = round(total_weight / signals, 4) if signals else 0.0
        severity = _severity_for_confidence(overall_confidence)

        # ── Build human-readable conclusion ──────────────────────────────────
        conclusion_parts: list[str] = []

        if vendor_id:
            family_str = f" ({family})" if family else ""
            conclusion_parts.append(
                f"Identity: {display_name}{family_str} "
                f"(identity probe confidence: {identity_confidence:.0%})"
            )
        else:
            conclusion_parts.append("Identity: unknown — no vendor matched")

        if contradiction_vendors:
            conclusion_parts.append(
                f"Contradiction probes confirmed: {', '.join(contradiction_vendors)}"
            )
        elif small_model_signal:
            conclusion_parts.append(
                "Contradiction probes: model accepted false attribution "
                "— likely a small/low-capacity model (< 7B params)"
            )

        if knowledge_cutoff:
            conclusion_parts.append(f"Knowledge cutoff: {knowledge_cutoff}")

        if context_label:
            conclusion_parts.append(
                f"Context window: ~{context_window:,} tokens — {context_label}"
            )

        if verbosity_score is not None:
            style_parts = []
            if code_style.get("docstrings"):
                style_parts.append("docstrings")
            if code_style.get("edge_cases"):
                style_parts.append("edge-case handling")
            if code_style.get("type_hints"):
                style_parts.append("type hints")
            verbosity_label = (
                "high verbosity" if verbosity_score > 0.6
                else "medium verbosity" if verbosity_score > 0.3
                else "low verbosity (concise)"
            )
            style_str = f" — code style: {', '.join(style_parts)}" if style_parts else ""
            conclusion_parts.append(f"Behavior: {verbosity_label}{style_str}")

        if attack_surface:
            conclusion_parts.append(
                f"Attack surface hints: {'; '.join(attack_surface)}"
            )
        if jailbreak_notes:
            conclusion_parts.append(f"Jailbreak notes: {jailbreak_notes}")

        conclusion = "\n".join(f"  • {p}" for p in conclusion_parts)
        title_vendor = f"{display_name}{' ' + family if family else ''}" if vendor_id else "Unknown"

        finding_title = (
            f"Model Fingerprint Summary: {title_vendor} "
            f"(confidence {overall_confidence:.0%})"
        )

        return [
            self._make_finding(
                target,
                severity=severity,
                confidence="high" if overall_confidence >= 0.7 else "medium" if overall_confidence >= 0.4 else "low",
                title=finding_title,
                evidence={
                    "conclusion": conclusion,
                    "overall_confidence": overall_confidence,
                    "signals_used": signals,
                    "vendor": vendor_id,
                    "display_name": display_name,
                    "family": family,
                    "identity_probe_confidence": identity_confidence,
                    "contradiction": {
                        "confidence_label": contradiction_confidence,
                        "likely_vendors": contradiction_vendors,
                        "small_model_signal": small_model_signal,
                    },
                    "knowledge_cutoff": knowledge_cutoff,
                    "context_window": {
                        "tokens": context_window,
                        "classification": context_label,
                    },
                    "behavior": {
                        "verbosity_score": verbosity_score,
                        "code_style": code_style,
                    },
                    "attack_surface_hints": attack_surface,
                    "jailbreak_notes": jailbreak_notes,
                },
                references=[],
            )
        ]
