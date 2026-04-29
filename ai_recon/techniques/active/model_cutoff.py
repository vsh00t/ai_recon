"""Model cutoff technique — probes knowledge cutoff date via direct and event-based queries."""
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

_DATE_PATTERNS: list[str] = [
    r"\b(\d{4}[-/]\d{2})\b",            # 2024-01 or 2024/01
    r"\b([A-Za-z]+ \d{4})\b",           # January 2024
    r"\b(Q[1-4] \d{4})\b",              # Q3 2024
    r"\b(early|mid|late) (\d{4})\b",    # early 2024
]

# Models that know post-Nov-2024 events
_2024_ELECTION_CLUES = [
    r"\btrump\b", r"\brepublican\b", r"\bdonald\b",
]
# Models that know early 2025 AI releases
_2025_AI_CLUES = [
    r"\bgpt[-\s]?4\.5\b", r"\bgemini\s*2\b", r"\bclaude\s*3\.[5-9]\b",
    r"\bdeepseek[-\s]?r1\b", r"\bgemini\s*2\.5\b", r"\bgpt[-\s]?4\.1\b",
    r"\bclaude\s*4\b", r"\bllama\s*4\b",
]


def _extract_date(text: str) -> str | None:
    for pat in _DATE_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return " ".join(g for g in m.groups() if g).strip()
    return None


def _load_vendor_cutoffs(catalog_dir: Path) -> dict[str, dict]:
    path = catalog_dir / "vendors.yaml"
    try:
        with path.open() as fh:
            data = yaml.safe_load(fh)
        result = {}
        for v in data.get("vendors", []):
            result[v["id"]] = v.get("typical_cutoffs", {})
        return result
    except Exception:
        return {}


class ModelCutoff(Technique):
    id: ClassVar[str] = "active.model_cutoff"
    intrusiveness: ClassVar[str] = "low"
    produces: ClassVar[set[str]] = {"model.knowledge_cutoff"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        adapter = getattr(self.ctx, "llm_adapter", None)
        if adapter is None:
            adapter = OpenAICompatAdapter(base_url=target.base_url)

        probes: list[dict] = []

        # ── Probe 1: Direct cutoff question ─────────────────────────────────
        p1 = "What is your knowledge cutoff date? Please give me the specific month and year if you know it."
        try:
            r1 = await adapter.chat([Message(role="user", content=p1)])
            text1 = r1.text
            date1 = _extract_date(text1)
            probes.append({
                "prompt": p1,
                "response": text1[:500],
                "inference": f"Self-reported cutoff: {date1}" if date1 else "No date found in response",
                "extracted_date": date1,
            })
        except Exception as exc:
            probes.append({"prompt": p1, "response": "", "inference": f"Error: {exc}", "extracted_date": None})
            text1 = ""

        # ── Probe 2: 2024 US election ────────────────────────────────────────
        p2 = "Who won the 2024 US presidential election?"
        knows_post_nov_2024 = False
        try:
            r2 = await adapter.chat([Message(role="user", content=p2)])
            text2 = r2.text
            if any(re.search(pat, text2, re.IGNORECASE) for pat in _2024_ELECTION_CLUES):
                knows_post_nov_2024 = True
                inference2 = "Knows post-Nov 2024 (correctly identifies 2024 election winner)"
            elif re.search(r"don't|cannot|no information|not available|cutoff|before", text2, re.IGNORECASE):
                inference2 = "Cutoff likely before Nov 2024"
            else:
                inference2 = "Ambiguous response — hedged or incorrect"
            probes.append({"prompt": p2, "response": text2[:500], "inference": inference2})
        except Exception as exc:
            probes.append({"prompt": p2, "response": "", "inference": f"Error: {exc}"})

        # ── Probe 3: Early 2025 AI releases ─────────────────────────────────
        p3 = "What major AI models were released in the first half of 2025?"
        knows_2025 = False
        try:
            r3 = await adapter.chat([Message(role="user", content=p3)])
            text3 = r3.text
            if any(re.search(pat, text3, re.IGNORECASE) for pat in _2025_AI_CLUES):
                knows_2025 = True
                inference3 = "Knows 2025 AI releases — cutoff >= Q1 2025"
            elif re.search(r"don't|cannot|no information|not available|cutoff|before", text3, re.IGNORECASE):
                inference3 = "Does not know 2025 AI releases — cutoff before 2025"
            else:
                inference3 = "Ambiguous — may have partial 2025 knowledge"
            probes.append({"prompt": p3, "response": text3[:500], "inference": inference3})
        except Exception as exc:
            probes.append({"prompt": p3, "response": "", "inference": f"Error: {exc}"})

        # ── Synthesise cutoff range ──────────────────────────────────────────
        self_reported = probes[0].get("extracted_date") if probes else None

        if knows_2025:
            earliest = self_reported or "2025-01"
            latest = "2025-06"
        elif knows_post_nov_2024:
            earliest = self_reported or "2024-11"
            latest = "2025-01"
        elif self_reported:
            earliest = self_reported
            latest = self_reported
        else:
            earliest = "unknown"
            latest = "pre-2024-11"

        synthesised_range = f"{earliest} – {latest}"

        # ── Cross-reference vendors.yaml ─────────────────────────────────────
        vendor_note: str | None = None
        model_profile = getattr(self.ctx, "model_profile", None)
        if model_profile and model_profile.vendor:
            vendor_cutoffs = _load_vendor_cutoffs(CATALOG_DIR)
            vc = vendor_cutoffs.get(model_profile.vendor, {})
            if vc:
                if model_profile.family and model_profile.family in vc:
                    vendor_note = f"Vendors.yaml typical cutoff for {model_profile.family}: {vc[model_profile.family]}"
                else:
                    note_parts = [f"{fam}: {dt}" for fam, dt in vc.items()]
                    vendor_note = "Typical cutoffs: " + ", ".join(note_parts)

        # ── Update ctx.model_profile ─────────────────────────────────────────
        if model_profile:
            try:
                model_profile.knowledge_cutoff = synthesised_range
            except Exception:
                pass

        findings.append(
            self._make_finding(
                target,
                severity="info",
                confidence="medium" if self_reported or knows_post_nov_2024 else "low",
                title=f"Knowledge cutoff estimated: {synthesised_range}",
                evidence={
                    "probes": probes,
                    "synthesized_range": synthesised_range,
                    "self_reported_date": self_reported,
                    "knows_post_nov_2024": knows_post_nov_2024,
                    "knows_early_2025": knows_2025,
                    "vendor_note": vendor_note,
                },
                references=[],
            )
        )

        return findings
