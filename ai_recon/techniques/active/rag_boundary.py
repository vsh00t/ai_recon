"""RAG boundary technique — detects whether a RAG pipeline is active and its metadata exposure."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import ClassVar

import yaml

from ai_recon.adapters.llm_protocol.openai_compat import OpenAICompatAdapter
from ai_recon.core.models import DocumentRef, Finding, Message, RAGProfile, RunContext, Target
from ai_recon.core.errors import TechniqueAborted
from ai_recon.techniques.base import Technique

CATALOG_DIR = Path(__file__).parent.parent.parent / "catalogs"

# Citation markers that appear in RAG responses
_CITATION_PATTERNS: list[str] = [
    r"\[\d+\]",              # [1], [2]
    r"\[Source\s*:",         # [Source: ...]
    r"\[Doc\s*:",            # [Doc: ...]
    r"\bsource\s*\d+\b",     # source 1
    r"\bReference\s*\d+\b",  # Reference 1
    r"\(source\b",           # (source
    r"\baccording to\b",     # according to [document]
]


def _parse_sources_from_response(resp_text: str, resp_raw: dict) -> list[DocumentRef]:
    """Extract DocumentRef objects from response JSON or text citations."""
    sources: list[DocumentRef] = []

    # Try JSON fields first
    for key in ("sources", "references", "documents", "context", "citations"):
        raw_sources = resp_raw.get(key)
        if raw_sources and isinstance(raw_sources, list):
            for s in raw_sources:
                if isinstance(s, dict):
                    sources.append(
                        DocumentRef(
                            title=s.get("title") or s.get("name") or s.get("filename") or "unknown",
                            chunk_id=s.get("chunk_id") or s.get("id"),
                            snippet=s.get("snippet") or s.get("content") or s.get("text"),
                            vector_score=s.get("vector_score") or s.get("score"),
                            bm25_score=s.get("bm25_score"),
                            combined_score=s.get("combined_score") or s.get("relevance_score"),
                        )
                    )
            if sources:
                return sources

    # Try to find citation markers in text
    for pat in _CITATION_PATTERNS:
        if re.search(pat, resp_text, re.IGNORECASE):
            # Cannot extract full metadata from text citations
            sources.append(
                DocumentRef(
                    title="[text citation detected]",
                    snippet=re.search(pat, resp_text, re.IGNORECASE).group(0),
                )
            )
    return sources


def _load_template_prompt(template_id: str, catalog_dir: Path) -> str | None:
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


class RAGBoundary(Technique):
    id: ClassVar[str] = "active.rag_boundary"
    intrusiveness: ClassVar[str] = "low"
    produces: ClassVar[set[str]] = {"rag.detected", "rag.metadata_level"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        adapter = getattr(self.ctx, "llm_adapter", None)
        if adapter is None:
            adapter = OpenAICompatAdapter(base_url=target.base_url)

        generic_prompt = (
            _load_template_prompt("rag_boundary_generic", CATALOG_DIR)
            or "What is 2+2?"
        )
        specific_prompt = (
            _load_template_prompt("rag_boundary_specific", CATALOG_DIR)
            or "What is the company vacation policy?"
        )

        # ── Send generic query ───────────────────────────────────────────────
        generic_sources: list[DocumentRef] = []
        try:
            r_generic = await adapter.chat([Message(role="user", content=generic_prompt)])
            generic_sources = _parse_sources_from_response(r_generic.text, r_generic.raw)
        except Exception as exc:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="low",
                    title="RAG boundary generic probe failed",
                    evidence={"error": str(exc)},
                    references=[],
                )
            )

        # ── Send specific query ──────────────────────────────────────────────
        specific_sources: list[DocumentRef] = []
        try:
            r_specific = await adapter.chat([Message(role="user", content=specific_prompt)])
            specific_sources = _parse_sources_from_response(r_specific.text, r_specific.raw)
        except Exception as exc:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="low",
                    title="RAG boundary specific probe failed",
                    evidence={"error": str(exc)},
                    references=[],
                )
            )

        # ── Classify RAG behaviour ───────────────────────────────────────────
        has_generic_sources  = len(generic_sources)  > 0
        has_specific_sources = len(specific_sources) > 0

        rag_detected = False
        boundary_detected = False
        severity = "info"
        title = "RAG pipeline not detected"
        classification = "no_rag"

        if not has_generic_sources and has_specific_sources:
            rag_detected = True
            boundary_detected = True
            severity = "medium"
            title = "RAG pipeline detected — boundary identified"
            classification = "rag_with_boundary"
        elif has_generic_sources and has_specific_sources:
            rag_detected = True
            severity = "medium"
            title = "RAG pipeline detected — always active"
            classification = "rag_always_active"
        elif not has_generic_sources and not has_specific_sources:
            title = "RAG pipeline not detected (no sources in either probe)"
            classification = "no_rag"
        else:
            # Generic has sources but specific doesn't — unusual
            rag_detected = True
            severity = "info"
            title = "RAG pipeline detected on generic query (unusual)"
            classification = "rag_generic_only"

        # ── Parse metadata exposure level ────────────────────────────────────
        all_sources = generic_sources + specific_sources
        metadata_exposed: dict = {}
        exposure_level = "none"

        if all_sources:
            has_chunk_id = any(s.chunk_id for s in all_sources)
            has_scores   = any(s.vector_score or s.combined_score for s in all_sources)
            has_snippets = any(s.snippet for s in all_sources)
            metadata_exposed = {
                "chunk_ids": has_chunk_id,
                "scores": has_scores,
                "snippets": has_snippets,
                "sample_source": {
                    "title":          all_sources[0].title,
                    "chunk_id":       all_sources[0].chunk_id,
                    "vector_score":   all_sources[0].vector_score,
                    "combined_score": all_sources[0].combined_score,
                } if all_sources else {},
            }
            if has_chunk_id and has_scores and has_snippets:
                exposure_level = "detailed"
            elif has_scores or has_snippets:
                exposure_level = "moderate"
            elif all_sources:
                exposure_level = "minimal"

        # ── Update ctx.rag_profile ───────────────────────────────────────────
        rag_profile = getattr(self.ctx, "rag_profile", None)
        if rag_profile is None:
            try:
                self.ctx.rag_profile = RAGProfile(  # type: ignore[attr-defined]
                    detected=rag_detected,
                    exposure_level=exposure_level,
                )
            except Exception:
                pass
        else:
            try:
                rag_profile.detected = rag_detected
                rag_profile.exposure_level = exposure_level
            except Exception:
                pass

        findings.append(
            self._make_finding(
                target,
                severity=severity,
                confidence="medium" if rag_detected else "low",
                title=title,
                evidence={
                    "classification": classification,
                    "generic_sources": [s.model_dump() for s in generic_sources],
                    "specific_sources": [s.model_dump() for s in specific_sources],
                    "metadata_exposed": metadata_exposed,
                    "exposure_level": exposure_level,
                    "boundary_detected": boundary_detected,
                },
                references=[],
            )
        )

        return findings
