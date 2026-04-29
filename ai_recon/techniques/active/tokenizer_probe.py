"""Tokenizer probe technique — identifies tokenizer family by comparing token counts."""
from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

from ai_recon.adapters.llm_protocol.openai_compat import OpenAICompatAdapter
from ai_recon.core.models import Finding, Message, RunContext, Target
from ai_recon.core.errors import TechniqueAborted
from ai_recon.core.tokens import _REGISTRY, SimpleCharTokenizer, get_tokenizer
from ai_recon.techniques.base import Technique

CATALOG_DIR = Path(__file__).parent.parent.parent / "catalogs"

# Test strings with known tokenization characteristics
_TEST_STRINGS: dict[str, str] = {
    "test_ascii":    "The quick brown fox",
    "test_cjk":      "你好世界",
    "test_emoji":    "🎉🔥💡🚀✨",
    "test_code":     "def foo(): return None",
    "test_repeated": "token " * 50,
}


def _expected_counts(test_name: str, test_str: str) -> dict[str, int]:
    """Compute expected token count for each registered tokenizer."""
    result: dict[str, int] = {}
    for tok_name in list(_REGISTRY.keys()) + ["simple"]:
        try:
            tok = get_tokenizer(tok_name) if tok_name != "simple" else SimpleCharTokenizer()
            result[tok_name] = tok.count(test_str)
        except Exception:
            result[tok_name] = -1
    return result


def _match_tokenizer(
    test_results: list[dict],
) -> tuple[str | None, float]:
    """
    Match observed token counts against each tokenizer's expected counts.
    Returns (best_tokenizer_name, confidence 0-1).
    """
    tokenizer_names = list(_REGISTRY.keys())
    scores: dict[str, int] = {name: 0 for name in tokenizer_names}

    for result in test_results:
        observed = result.get("observed_tokens")
        if observed is None:
            continue
        expected_map = result.get("expected_by_tokenizer", {})
        # Find which tokenizer is closest
        best_delta = None
        best_tok = None
        for tok_name, exp_count in expected_map.items():
            if tok_name not in scores:
                continue
            if exp_count < 0:
                continue
            delta = abs(observed - exp_count)
            if best_delta is None or delta < best_delta:
                best_delta = delta
                best_tok = tok_name
        if best_tok:
            scores[best_tok] += 1

    if not scores:
        return None, 0.0

    best = max(scores, key=lambda k: scores[k])
    total_valid = sum(1 for r in test_results if r.get("observed_tokens") is not None)
    confidence = round(scores[best] / total_valid, 4) if total_valid > 0 else 0.0
    return best, confidence


class TokenizerProbe(Technique):
    id: ClassVar[str] = "active.tokenizer_probe"
    intrusiveness: ClassVar[str] = "low"
    produces: ClassVar[set[str]] = {"model.tokenizer"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        adapter = getattr(self.ctx, "llm_adapter", None)
        if adapter is None:
            adapter = OpenAICompatAdapter(base_url=target.base_url)

        test_results: list[dict] = []
        any_usage_exposed = False

        for test_name, test_str in _TEST_STRINGS.items():
            expected_map = _expected_counts(test_name, test_str)
            prompt = f"Repeat the following text exactly as-is, nothing else:\n\n{test_str}"
            try:
                resp = await adapter.chat([Message(role="user", content=prompt)])
                usage = resp.usage
                observed_tokens: int | None = None
                if usage and usage.prompt_tokens is not None:
                    observed_tokens = usage.prompt_tokens
                    any_usage_exposed = True

                test_results.append({
                    "test_name": test_name,
                    "test_string": test_str,
                    "observed_tokens": observed_tokens,
                    "expected_by_tokenizer": expected_map,
                    "usage_raw": {
                        "prompt_tokens": usage.prompt_tokens if usage else None,
                        "completion_tokens": usage.completion_tokens if usage else None,
                    },
                })
            except Exception as exc:
                test_results.append({
                    "test_name": test_name,
                    "test_string": test_str,
                    "observed_tokens": None,
                    "error": str(exc),
                    "expected_by_tokenizer": expected_map,
                })

        if not any_usage_exposed:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="high",
                    title="Token usage not exposed — tokenizer probe inconclusive",
                    evidence={
                        "test_results": test_results,
                        "note": "API did not return usage.prompt_tokens in any response.",
                    },
                    references=[],
                )
            )
            return findings

        matched_tokenizer, confidence = _match_tokenizer(test_results)

        # Update ctx.model_profile
        model_profile = getattr(self.ctx, "model_profile", None)
        if model_profile and matched_tokenizer:
            try:
                model_profile.tokenizer = matched_tokenizer
            except Exception:
                pass

        findings.append(
            self._make_finding(
                target,
                severity="info",
                confidence="high" if confidence >= 0.6 else "medium" if confidence >= 0.4 else "low",
                title=f"Tokenizer identified: {matched_tokenizer or 'unknown'}",
                evidence={
                    "test_results": test_results,
                    "matched_tokenizer": matched_tokenizer,
                    "confidence": confidence,
                    "registered_tokenizers": list(_REGISTRY.keys()),
                },
                references=[],
            )
        )

        return findings
