"""RAG threshold technique — estimates retrieval score threshold by degrading query quality."""
from __future__ import annotations

import random
import re
from pathlib import Path
from typing import ClassVar

from ai_recon.core.models import Finding, Target
from ai_recon.techniques.base import Technique
from ai_recon.techniques.active.rag_boundary import _parse_sources_from_response
from ai_recon.techniques.active.rag_probe import rag_chat

CATALOG_DIR = Path(__file__).parent.parent.parent / "catalogs"

_SYNONYMS: dict[str, str] = {
    "vacation":    "time-off",
    "policy":      "guidelines",
    "policies":    "guidelines",
    "expense":     "cost",
    "expenses":    "costs",
    "api":         "interface",
    "employee":    "staff",
    "employees":   "staff",
    "company":     "organisation",
    "document":    "file",
    "documents":   "files",
    "security":    "protection",
    "onboarding":  "orientation",
    "incident":    "issue",
    "retention":   "storage",
    "roadmap":     "plan",
}

_DEFAULT_QUERY = "What is the vacation policy?"


def _apply_synonyms(text: str) -> str:
    """Replace nouns with synonyms using the static map."""
    result = text
    for original, synonym in _SYNONYMS.items():
        result = re.sub(r"\b" + re.escape(original) + r"\b", synonym, result, flags=re.IGNORECASE)
    return result


def _apply_typos(text: str) -> str:
    """Randomly swap 2 characters in 2 words."""
    words = text.split()
    rng = random.Random(42)  # deterministic for reproducibility
    # Pick 2 long-enough words to mangle
    candidates = [i for i, w in enumerate(words) if len(w) >= 4 and w.isalpha()]
    chosen = rng.sample(candidates, min(2, len(candidates)))
    for idx in chosen:
        w = list(words[idx])
        i = rng.randint(0, len(w) - 2)
        w[i], w[i + 1] = w[i + 1], w[i]
        words[idx] = "".join(w)
    return " ".join(words)


def _best_score_from_sources(sources) -> float | None:
    """Return the highest combined/vector score from sources, or None."""
    best: float | None = None
    for s in sources:
        for score in (s.combined_score, s.vector_score):
            if score is not None:
                if best is None or score > best:
                    best = score
    return best


class RAGThreshold(Technique):
    id: ClassVar[str] = "active.rag_threshold"
    intrusiveness: ClassVar[str] = "low"
    produces: ClassVar[set[str]] = {"rag.threshold"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        # Pick a known-good query from rag_mapping results if available
        base_query = _DEFAULT_QUERY
        rag_profile = getattr(self.ctx, "rag_profile", None)
        if rag_profile and rag_profile.documents:
            first_doc = rag_profile.documents[0]
            if first_doc.title and first_doc.title != "unknown":
                base_query = f"Tell me about {first_doc.title}"

        # Build 3 variants
        exact_query   = base_query
        synonym_query = _apply_synonyms(base_query)
        typo_query    = _apply_typos(base_query)

        variant_results: dict[str, dict] = {}

        for variant_name, query in [
            ("exact",   exact_query),
            ("synonym", synonym_query),
            ("typo",    typo_query),
        ]:
            try:
                resp = await rag_chat(self.ctx, target, query)
                sources = _parse_sources_from_response(resp.text, resp.raw)
                best_score = _best_score_from_sources(sources)
                variant_results[variant_name] = {
                    "query": query,
                    "sources_count": len(sources),
                    "best_score": best_score,
                    "retrieval_info": resp.raw.get("retrieval_info"),
                }
            except Exception as exc:
                variant_results[variant_name] = {
                    "query": query,
                    "sources_count": 0,
                    "best_score": None,
                    "error": str(exc),
                }

        # Determine threshold range
        exact_score   = variant_results["exact"].get("best_score")
        synonym_score = variant_results["synonym"].get("best_score")
        typo_score    = variant_results["typo"].get("best_score")

        exact_count   = variant_results["exact"].get("sources_count", 0)
        synonym_count = variant_results["synonym"].get("sources_count", 0)
        typo_count    = variant_results["typo"].get("sources_count", 0)

        # Find threshold — where sources first drop to 0
        lo: float | None = None
        hi: float | None = None

        if exact_count > 0 and synonym_count == 0:
            lo = None
            hi = exact_score
            threshold_est = exact_score or 0.0
            classification = "strict_threshold"
        elif synonym_count > 0 and typo_count == 0:
            lo = synonym_score
            hi = exact_score
            threshold_est = ((lo or 0.0) + (hi or 0.0)) / 2
            classification = "semantic_threshold_observed"
        elif typo_count == 0 and exact_count == 0:
            threshold_est = 1.0  # Everything fails — threshold is above 1.0 (no RAG)
            lo = None
            hi = None
            classification = "no_retrieval_observed"
        else:
            # All variants return results — threshold below typo score
            threshold_est = (typo_score or 0.0) * 0.9
            lo = 0.0
            hi = typo_score
            classification = "tolerant_threshold"

        # Update rag_profile
        if rag_profile:
            try:
                rag_profile.inferred_threshold = threshold_est
            except Exception:
                pass

        findings.append(
            self._make_finding(
                target,
                severity="info",
                confidence="medium" if exact_count > 0 else "low",
                title=f"RAG retrieval threshold estimated: ~{threshold_est:.3f}",
                evidence={
                    "base_query": base_query,
                    "exact_score": exact_score,
                    "exact_sources": exact_count,
                    "synonym_query": synonym_query,
                    "synonym_score": synonym_score,
                    "synonym_sources": synonym_count,
                    "typo_query": typo_query,
                    "typo_score": typo_score,
                    "typo_sources": typo_count,
                    "threshold_range": (lo, hi),
                    "estimated_threshold": threshold_est,
                    "classification": classification,
                    "variant_results": variant_results,
                },
                references=[],
            )
        )

        return findings
