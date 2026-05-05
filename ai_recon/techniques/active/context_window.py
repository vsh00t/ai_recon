"""Context window technique — binary-searches context limit using a recall marker."""
from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

import yaml
from ulid import ULID

from ai_recon.adapters.llm_protocol.openai_compat import OpenAICompatAdapter
from ai_recon.core.models import Finding, Message, RunContext, Target
from ai_recon.core.errors import TechniqueAborted
from ai_recon.techniques.base import Technique

CATALOG_DIR = Path(__file__).parent.parent.parent / "catalogs"

# Candidate sizes to search (in tokens)
_SIZES: list[int] = [
    1024, 4096, 8192, 16384, 32768, 65536, 131072, 200704, 409600, 1048576,
]

# Approximate tokens: 4 chars ≈ 1 token; "padding " is 2 tokens
_FILLER_WORD = "padding "
_FILLER_CHARS_PER_TOKEN = 4


def _count_tokens(text: str) -> int:
    """Rough token estimate: 4 chars per token."""
    return max(1, len(text) // _FILLER_CHARS_PER_TOKEN)


def _build_filler(n_tokens: int) -> str:
    """Build a filler string of approximately n_tokens tokens."""
    word_len = len(_FILLER_WORD)
    chars_needed = n_tokens * _FILLER_CHARS_PER_TOKEN
    repetitions = max(1, chars_needed // word_len)
    return _FILLER_WORD * repetitions


def _load_marker_template(catalog_dir: Path) -> tuple[str, str]:
    """Return (marker_template, recall_template) from catalog, or fallback."""
    path = catalog_dir / "prompt_templates.yaml"
    marker_tpl = "Remember this secret code exactly: {marker}. Acknowledge with 'Understood, {marker}' and nothing else."
    recall_tpl = "What was the secret code I told you to remember earlier in our conversation? Please repeat it exactly."
    try:
        with path.open() as fh:
            data = yaml.safe_load(fh)
        for t in data.get("prompt_templates", []):
            if t.get("id") == "context_marker":
                marker_tpl = t.get("prompt", marker_tpl).strip()
            elif t.get("id") == "context_recall":
                recall_tpl = t.get("prompt", recall_tpl).strip()
    except Exception:
        pass
    return marker_tpl, recall_tpl


async def _test_recall(
    adapter,
    marker: str,
    marker_template: str,
    recall_template: str,
    n_tokens: int,
) -> bool:
    """Return True if the model recalls the marker after n_tokens of filler."""
    intro = marker_template.format(marker=marker)
    filler = _build_filler(max(0, n_tokens - _count_tokens(intro) - _count_tokens(recall_template) - 20))
    recall = recall_template

    messages = [
        Message(role="user", content=intro),
        Message(role="assistant", content=f"Understood, {marker}"),
        Message(role="user", content=filler if filler.strip() else "Continue."),
        Message(role="assistant", content="Understood."),
        Message(role="user", content=recall),
    ]
    try:
        resp = await adapter.chat(messages)
        return marker in resp.text
    except Exception:
        return False


class ContextWindow(Technique):
    id: ClassVar[str] = "active.context_window"
    intrusiveness: ClassVar[str] = "low"
    produces: ClassVar[set[str]] = {"model.context_window"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        adapter = getattr(self.ctx, "llm_adapter", None)
        if adapter is None:
            adapter = OpenAICompatAdapter(base_url=target.base_url)

        marker = f"RECON-MARKER-{str(ULID())[:8]}"
        marker_template, recall_template = _load_marker_template(CATALOG_DIR)

        # ── Initial ack ──────────────────────────────────────────────────────
        intro = marker_template.format(marker=marker)
        try:
            ack = await adapter.chat([Message(role="user", content=intro)])
            if marker not in ack.text:
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="low",
                        title="Context window probe: model did not acknowledge marker",
                        evidence={"marker": marker, "ack_response": ack.text[:300]},
                        references=[],
                    )
                )
                return findings
        except Exception as exc:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="low",
                    title="Context window probe failed — could not send initial message",
                    evidence={"error": str(exc), "marker": marker},
                    references=[],
                )
            )
            return findings

        # ── Linear search to find first failing size ─────────────────────────
        binary_results: list[dict] = []
        last_success_idx = -1
        first_failure_idx = len(_SIZES)

        for idx, size in enumerate(_SIZES):
            recalled = await _test_recall(adapter, marker, marker_template, recall_template, size)
            binary_results.append({"tokens": size, "recalled": recalled})
            if recalled:
                last_success_idx = idx
            else:
                first_failure_idx = idx
                break  # first failure found — no need to test larger sizes

        # ── Binary search refinement ─────────────────────────────────────────
        lower_bound = 0
        upper_bound: int | None = None
        if last_success_idx >= 0 and first_failure_idx < len(_SIZES):
            lo = _SIZES[last_success_idx]
            hi = _SIZES[first_failure_idx]
            # Up to 4 bisection steps
            for _ in range(4):
                mid = (lo + hi) // 2
                if mid <= lo or mid >= hi:
                    break
                recalled = await _test_recall(adapter, marker, marker_template, recall_template, mid)
                binary_results.append({"tokens": mid, "recalled": recalled, "bisection": True})
                if recalled:
                    lo = mid
                else:
                    hi = mid
            estimated = lo
            lower_bound = lo
            upper_bound = hi
        elif last_success_idx >= 0:
            # Recalled at all tested sizes
            estimated = _SIZES[last_success_idx]
            lower_bound = estimated
        else:
            # Never recalled — very small or unresponsive
            estimated = 0
            upper_bound = _SIZES[0]

        # ── Cross-reference vendors.yaml ─────────────────────────────────────
        vendor_hint: str | None = None
        model_profile = getattr(self.ctx, "model_profile", None)
        if model_profile and model_profile.vendor:
            catalog_path = CATALOG_DIR / "vendors.yaml"
            try:
                with catalog_path.open() as fh:
                    data = yaml.safe_load(fh)
                for v in data.get("vendors", []):
                    if v.get("id") == model_profile.vendor:
                        hints = v.get("context_window_hints", {})
                        if hints:
                            hint_parts = [f"{fam}: {sz:,}" for fam, sz in hints.items()]
                            vendor_hint = "Known context sizes: " + "; ".join(hint_parts)
                        break
            except Exception:
                pass

        # ── Update ctx.model_profile ─────────────────────────────────────────
        if model_profile and estimated > 0:
            try:
                model_profile.context_window = estimated
            except Exception:
                pass

        confidence = "medium" if estimated > 0 else "low"
        title = (
            f"Context window estimated: ~{estimated:,} tokens"
            if estimated > 0
            else "Context window probe inconclusive"
        )

        findings.append(
            self._make_finding(
                target,
                severity="info",
                confidence=confidence,
                title=title,
                evidence={
                    "marker": marker,
                    "binary_search_results": binary_results,
                    "estimated_tokens": estimated,
                    "lower_bound_tokens": lower_bound,
                    "upper_bound_tokens": upper_bound,
                    "filler_strategy": "repetitive text (~4 chars/token)",
                    "vendor_context_hint": vendor_hint,
                },
                references=[],
            )
        )

        return findings
