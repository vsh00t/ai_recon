"""Cost oracle — infer pricing tier and cross-validate model identity.

When ``usage`` is exposed by the API, combine prompt/completion token counts
with payload sizes to estimate effective per-token cost (relative). When
combined with the tokenizer family fingerprint, this often pins the vendor
even when the model name is hidden behind a proxy.

Outputs are heuristic; this module reports relative ratios, not real prices.
"""

from __future__ import annotations

import time
from typing import ClassVar

from ai_recon.adapters.llm_protocol.openai_compat import OpenAICompatAdapter
from ai_recon.core.models import Finding, Message, Target
from ai_recon.techniques.base import Technique


_BENCH_PROMPTS: list[str] = [
    "Hi.",
    "Write a one-paragraph product description for a tea kettle.",
    "Explain TCP slow start in three sentences.",
]


# Known reference tiers (tokens/s, very rough)
_TIER_RANGES: list[tuple[str, float, float]] = [
    ("frontier_premium",   0.0, 25.0),
    ("frontier_standard", 25.0, 60.0),
    ("mid_tier",          60.0, 150.0),
    ("small_or_local",   150.0, 10_000.0),
]


def _tier_for(tokens_per_sec: float) -> str:
    for name, lo, hi in _TIER_RANGES:
        if lo <= tokens_per_sec < hi:
            return name
    return "unknown"


class CostOracle(Technique):
    id: ClassVar[str] = "infra.cost_oracle"
    intrusiveness: ClassVar[str] = "low"
    requires: ClassVar[set[str]] = set()
    produces: ClassVar[set[str]] = {"infra.cost_signals", "model.size_hint"}

    async def run(self, target: Target) -> list[Finding]:
        adapter = getattr(self.ctx, "llm_adapter", None) or OpenAICompatAdapter(
            base_url=target.base_url
        )

        samples: list[dict] = []
        for p in _BENCH_PROMPTS:
            t0 = time.monotonic()
            try:
                resp = await adapter.chat([Message(role="user", content=p)])
            except Exception as exc:
                samples.append({"prompt": p, "error": str(exc)})
                continue
            dt = time.monotonic() - t0
            usage = resp.usage
            ct = usage.completion_tokens if usage and usage.completion_tokens else None
            samples.append({
                "prompt": p,
                "duration_s": round(dt, 3),
                "completion_tokens": ct,
                "tokens_per_sec": round(ct / dt, 2) if ct and dt > 0 else None,
                "usage_exposed": usage is not None,
            })

        rates = [s["tokens_per_sec"] for s in samples if s.get("tokens_per_sec")]
        avg = round(sum(rates) / len(rates), 2) if rates else None
        tier = _tier_for(avg) if avg is not None else "unknown"

        # Push a size hint into ctx.model_profile if we have one
        mp = getattr(self.ctx, "model_profile", None)
        if mp is not None and tier != "unknown":
            try:
                mp.size_hint = tier  # type: ignore[attr-defined]
            except Exception:
                pass

        return [
            self._make_finding(
                target,
                severity="info",
                confidence="medium",
                title=f"Cost-oracle tier estimate: {tier} (avg {avg} tok/s)",
                evidence={
                    "samples": samples,
                    "average_tokens_per_sec": avg,
                    "tier": tier,
                    "usage_exposed": all(s.get("usage_exposed") for s in samples
                                         if "error" not in s),
                },
            )
        ]
