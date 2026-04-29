"""Model behavior technique — behavioral fingerprinting via probes."""
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

# Correct answer for arithmetic probe: 847 * 293 = 248171
_ARITHMETIC_CORRECT = 248171

# Correct answer for multistep reasoning probe
_MULTISTEP_CORRECT = "eve"


def _word_count(text: str) -> int:
    return len(text.split())


def _has_code_block(text: str) -> bool:
    return bool(re.search(r"```", text))


def _has_base_case(text: str) -> bool:
    return bool(re.search(r"\bbase\s+case\b", text, re.IGNORECASE))


def _has_recursive_call(text: str) -> bool:
    return bool(re.search(r"\brecursi(?:on|ve|vely)\b", text, re.IGNORECASE))


def _has_docstring(text: str) -> bool:
    return bool(re.search(r'"""', text)) or bool(re.search(r"'''", text))


def _has_edge_cases(text: str) -> bool:
    return bool(re.search(r"\b(0|negative|zero|edge|corner|special)\b", text, re.IGNORECASE))


def _has_type_hints(text: str) -> bool:
    return bool(re.search(r"def\s+\w+\s*\(.*:\s*\w+", text))


def _count_lines(text: str) -> int:
    return len([l for l in text.splitlines() if l.strip()])


def _load_prompt(template_id: str, catalog_dir: Path) -> str | None:
    path = catalog_dir / "prompt_templates.yaml"
    try:
        with path.open() as fh:
            data = yaml.safe_load(fh)
        for t in data.get("prompt_templates", []):
            if t.get("id") == template_id:
                return t.get("prompt", "").strip()
    except Exception:
        pass
    return None


def _load_vendors() -> list[dict]:
    path = CATALOG_DIR / "vendors.yaml"
    try:
        with path.open() as fh:
            data = yaml.safe_load(fh)
        return data.get("vendors", [])
    except Exception:
        return []


def _match_behavior_signature(
    verbosity: float,
    code_style: dict,
    vendors: list[dict],
) -> str | None:
    """Return the vendor id whose behavior_signature best matches the observations."""
    best_vendor: str | None = None
    best_score = -1

    for v in vendors:
        sig = v.get("behavior_signature", {})
        score = 0

        # Verbosity
        vb = sig.get("verbosity", "")
        if vb == "high" and verbosity > 0.6:
            score += 2
        elif vb == "medium" and 0.3 <= verbosity <= 0.6:
            score += 2
        elif vb == "low" and verbosity < 0.3:
            score += 2

        # Docstrings
        ds = sig.get("docstrings", "")
        if ds == "common" and code_style.get("docstrings"):
            score += 1
        elif ds == "rare" and not code_style.get("docstrings"):
            score += 1

        # Edge cases
        ec = sig.get("edge_cases", "")
        if ec == "common" and code_style.get("edge_cases"):
            score += 1
        elif ec == "rare" and not code_style.get("edge_cases"):
            score += 1

        # Type hints
        if code_style.get("type_hints"):
            score += 1  # bonus for any vendor that uses modern Python

        if score > best_score:
            best_score = score
            best_vendor = v.get("id")

    return best_vendor


class ModelBehavior(Technique):
    id: ClassVar[str] = "active.model_behavior"
    intrusiveness: ClassVar[str] = "low"
    produces: ClassVar[set[str]] = {"model.behavior_signature"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        adapter = getattr(self.ctx, "llm_adapter", None)
        if adapter is None:
            adapter = OpenAICompatAdapter(base_url=target.base_url)

        vendors = _load_vendors()

        # Load prompts (fallback to hardcoded if catalog unavailable)
        recursion_prompt = (
            _load_prompt("recursion_probe", CATALOG_DIR)
            or "Explain recursion to a senior developer in one paragraph."
        )
        prime_prompt = (
            _load_prompt("prime_probe", CATALOG_DIR)
            or "Write a Python function to check if a number is prime. Include proper error handling."
        )
        arithmetic_prompt = (
            _load_prompt("arithmetic_probe", CATALOG_DIR)
            or "Calculate 847 * 293. Show only the result."
        )
        multistep_prompt = (
            _load_prompt("multistep_reasoning", CATALOG_DIR)
            or (
                "Alice is taller than Bob. Bob is taller than Carol. "
                "Carol is taller than Dave. Dave is taller than Eve. "
                "Who is the shortest?"
            )
        )

        probe_results: list[dict] = []
        word_counts: list[int] = []

        # ── Probe A: recursion ───────────────────────────────────────────────
        try:
            r = await adapter.chat([Message(role="user", content=recursion_prompt)])
            text = r.text
            wc = _word_count(text)
            word_counts.append(wc)
            probe_results.append({
                "name": "recursion_probe",
                "word_count": wc,
                "has_base_case": _has_base_case(text),
                "has_recursive_call": _has_recursive_call(text),
                "code_block": _has_code_block(text),
                "examples_given": bool(re.search(r"\bexample\b|\bfor instance\b|\be\.g\b", text, re.IGNORECASE)),
            })
        except Exception as exc:
            probe_results.append({"name": "recursion_probe", "error": str(exc), "word_count": 0})

        # ── Probe B: prime function ──────────────────────────────────────────
        try:
            r = await adapter.chat([Message(role="user", content=prime_prompt)])
            text = r.text
            wc = _word_count(text)
            word_counts.append(wc)
            probe_results.append({
                "name": "prime_probe",
                "word_count": wc,
                "has_docstring": _has_docstring(text),
                "has_edge_cases": _has_edge_cases(text),
                "has_type_hints": _has_type_hints(text),
                "code_length_lines": _count_lines(text),
            })
        except Exception as exc:
            probe_results.append({"name": "prime_probe", "error": str(exc), "word_count": 0})

        # ── Probe C: arithmetic ──────────────────────────────────────────────
        try:
            r = await adapter.chat([Message(role="user", content=arithmetic_prompt)])
            text = r.text
            wc = _word_count(text)
            word_counts.append(wc)
            # Check answer — look for the number in the response
            numbers = re.findall(r"\b\d[\d,]*\b", text.replace(",", ""))
            numeric_answers = [int(n.replace(",", "")) for n in numbers if n.replace(",", "").isdigit()]
            correct = _ARITHMETIC_CORRECT in numeric_answers
            probe_results.append({
                "name": "arithmetic_probe",
                "word_count": wc,
                "correct": correct,
                "response_length": "short" if wc <= 10 else "verbose",
                "found_numbers": numeric_answers[:5],
            })
        except Exception as exc:
            probe_results.append({"name": "arithmetic_probe", "error": str(exc), "word_count": 0})

        # ── Probe D: multistep reasoning ─────────────────────────────────────
        try:
            r = await adapter.chat([Message(role="user", content=multistep_prompt)])
            text = r.text
            wc = _word_count(text)
            word_counts.append(wc)
            correct = bool(re.search(r"\beve\b", text, re.IGNORECASE))
            reasoning_steps = len(re.findall(
                r"\d+\.\s|\bfirst\b|\bsecond\b|\bthird\b|\btherefore\b|\bthus\b|\bso\b",
                text, re.IGNORECASE
            ))
            probe_results.append({
                "name": "multistep_reasoning",
                "word_count": wc,
                "correct_answer": correct,
                "reasoning_steps_shown": reasoning_steps,
            })
        except Exception as exc:
            probe_results.append({"name": "multistep_reasoning", "error": str(exc), "word_count": 0})

        # ── Compute aggregate metrics ────────────────────────────────────────
        valid_wc = [r.get("word_count", 0) for r in probe_results if r.get("word_count", 0) > 0]
        max_wc = 300  # normalisation ceiling
        verbosity_score = round(
            min(sum(valid_wc) / (len(valid_wc) * max_wc), 1.0)
            if valid_wc else 0.0,
            4,
        )

        prime_result = next((r for r in probe_results if r["name"] == "prime_probe"), {})
        code_style_signature = {
            "docstrings": prime_result.get("has_docstring", False),
            "edge_cases": prime_result.get("has_edge_cases", False),
            "type_hints": prime_result.get("has_type_hints", False),
        }

        likely_vendor = _match_behavior_signature(verbosity_score, code_style_signature, vendors)

        # ── Update ctx.model_profile ─────────────────────────────────────────
        model_profile = getattr(self.ctx, "model_profile", None)
        if model_profile is None:
            try:
                self.ctx.model_profile = ModelProfile(  # type: ignore[attr-defined]
                    vendor=likely_vendor,
                    verbosity_score=verbosity_score,
                    code_style_signature=code_style_signature,
                )
            except Exception:
                pass
        else:
            try:
                model_profile.verbosity_score = verbosity_score
                model_profile.code_style_signature = code_style_signature
                if model_profile.vendor is None:
                    model_profile.vendor = likely_vendor
            except Exception:
                pass

        findings.append(
            self._make_finding(
                target,
                severity="info",
                confidence="medium",
                title="Model behavior fingerprint",
                evidence={
                    "verbosity_score": verbosity_score,
                    "code_style": code_style_signature,
                    "likely_vendor_match": likely_vendor,
                    "probe_details": probe_results,
                },
                references=[],
            )
        )

        return findings
