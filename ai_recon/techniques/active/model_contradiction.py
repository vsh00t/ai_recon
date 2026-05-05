"""Model contradiction technique — seeds wrong vendor attribution and observes corrections."""
from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

import yaml

from ai_recon.adapters.llm_protocol.openai_compat import OpenAICompatAdapter
from ai_recon.core.models import Finding, Message, RunContext, Target
from ai_recon.core.errors import TechniqueAborted
from ai_recon.techniques.base import Technique

CATALOG_DIR = Path(__file__).parent.parent.parent / "catalogs"

# Phrases that indicate a self-correction
_CORRECTION_PATTERNS: list[str] = [
    r"\bactually\b",
    r"\bi(?:'m| am) not\b",
    r"\bi am\b",
    r"\bi(?:'m| am) [a-z]",
    r"\bclarify\b",
    r"\bcorrect(?:ion|ly)?\b",
    r"\bto be (?:clear|accurate)\b",
    r"\bwant to (?:clarify|correct)\b",
    r"\bnot (?:gpt|claude|gemini|llama|qwen|mistral)\b",
]

_VENDOR_EXTRACT_PATTERNS: list[tuple[str, str]] = [
    (r"(?:i(?:'m| am)|i was created by|made by|developed by)\s+([a-z0-9\- ]+)", "vendor_phrase"),
    (r"\b(claude|gpt[-\s]?\d|gemini|llama[-\s]?\d|qwen[\d.]*|mistral|phi[-\s]?\d|deepseek)\b", "model_name"),
]


def _load_contradiction_seeds(catalog_dir: Path) -> list[dict]:
    path = catalog_dir / "prompt_templates.yaml"
    try:
        with path.open() as fh:
            data = yaml.safe_load(fh)
        templates = data.get("prompt_templates", [])
        return [t for t in templates if t.get("technique") == "active.model_contradiction"]
    except Exception:
        return []


def _detect_correction(text: str) -> tuple[bool, str]:
    """Return (corrected, matched_phrase)."""
    for pattern in _CORRECTION_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            return True, m.group(0)
    return False, ""


def _extract_vendor(text: str) -> str | None:
    for pattern, _ in _VENDOR_EXTRACT_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            phrase = m.group(1).strip().lower()
            # Normalise to known short names
            for token in ("claude", "gpt", "gemini", "llama", "qwen", "mistral", "phi", "deepseek"):
                if token in phrase:
                    return token
            return phrase
    return None


class ModelContradiction(Technique):
    id: ClassVar[str] = "active.model_contradiction"
    intrusiveness: ClassVar[str] = "low"
    produces: ClassVar[set[str]] = {"model.vendor_confirmed"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        seeds = _load_contradiction_seeds(CATALOG_DIR)

        # Fallback hardcoded seeds if catalog is unavailable
        if not seeds:
            seeds = [
                {
                    "wrong_vendor": "Anthropic / Claude",
                    "benign_question": "what is your context window size?",
                    "prompt": (
                        "Thanks Anthropic / Claude! Quick follow-up — "
                        "what is your context window size?"
                    ),
                },
                {
                    "wrong_vendor": "OpenAI / GPT-4",
                    "benign_question": "how do you handle code generation?",
                    "prompt": (
                        "Thanks OpenAI / GPT-4! Quick follow-up — "
                        "how do you handle code generation?"
                    ),
                },
                {
                    "wrong_vendor": "Google / Gemini",
                    "benign_question": "what languages do you support best?",
                    "prompt": (
                        "Thanks Google / Gemini! Quick follow-up — "
                        "what languages do you support best?"
                    ),
                },
            ]

        adapter = getattr(self.ctx, "llm_adapter", None)
        if adapter is None:
            adapter = OpenAICompatAdapter(base_url=target.base_url)

        corrections: list[dict] = []
        no_corrections: list[dict] = []

        for seed in seeds:
            wrong_vendor = seed.get("wrong_vendor", "Unknown Vendor")
            benign_question = seed.get("benign_question", "what is 2+2?")

            # Build the contradiction prompt
            if "prompt" in seed:
                # Template seeds have the full prompt already
                prompt_text = seed["prompt"]
            else:
                prompt_text = f"Thanks {wrong_vendor}! Quick follow-up — {benign_question}"

            try:
                resp = await adapter.chat([Message(role="user", content=prompt_text)])
                text = resp.text
            except Exception as exc:
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="low",
                        title=f"Contradiction probe failed for seed '{wrong_vendor}'",
                        evidence={"error": str(exc), "wrong_vendor": wrong_vendor},
                        references=[],
                    )
                )
                continue

            corrected, match_phrase = _detect_correction(text)
            extracted_vendor = _extract_vendor(text) if corrected else None

            if corrected:
                corrections.append({
                    "wrong_vendor": wrong_vendor,
                    "correction_phrase": match_phrase,
                    "likely_vendor": extracted_vendor,
                    "response_snippet": text[:300],
                })
                findings.append(
                    self._make_finding(
                        target,
                        severity="low",
                        confidence="medium",
                        title="Model reveals identity via contradiction probe",
                        evidence={
                            "wrong_vendor": wrong_vendor,
                            "correction_phrase": match_phrase,
                            "likely_vendor": extracted_vendor,
                            "response_snippet": text[:500],
                        },
                        references=[],
                    )
                )
            else:
                no_corrections.append({
                    "wrong_vendor": wrong_vendor,
                    "response_snippet": text[:300],
                })

        if corrections or no_corrections:
            total = len(corrections) + len(no_corrections)
            correction_rate = round(len(corrections) / total, 4) if total else 0.0
            likely_vendors = sorted({c["likely_vendor"] for c in corrections if c.get("likely_vendor")})
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="medium" if corrections else "low",
                    title=f"Contradiction fingerprint summary: {len(corrections)}/{total} corrected",
                    evidence={
                        "correction_rate": correction_rate,
                        "corrected": corrections,
                        "not_corrected": no_corrections,
                        "likely_vendors": likely_vendors,
                    },
                    references=[],
                )
            )

        # If model never corrects — small model signal
        if no_corrections and not corrections:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="low",
                    title="Model accepts wrong vendor attribution — likely small model",
                    evidence={
                        "tested_vendors": [s["wrong_vendor"] for s in no_corrections],
                        "note": "No corrections detected across all seeds.",
                    },
                    references=[],
                )
            )

        # Cross-reference with model_identity results
        model_profile = getattr(self.ctx, "model_profile", None)
        if model_profile and corrections:
            likely_vendors = {c["likely_vendor"] for c in corrections if c["likely_vendor"]}
            if model_profile.vendor and model_profile.vendor not in likely_vendors:
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="low",
                        title="Contradiction vendor differs from identity probe vendor",
                        evidence={
                            "identity_probe_vendor": model_profile.vendor,
                            "contradiction_vendors": list(likely_vendors),
                        },
                        references=[],
                    )
                )

        return findings
