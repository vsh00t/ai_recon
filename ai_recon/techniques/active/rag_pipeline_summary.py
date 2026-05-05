"""RAG pipeline summary technique.

Consolidates the outputs of rag_boundary, rag_mapping, rag_threshold and
rag_metadata_leak into a single operational finding describing whether RAG is
active, what documents were exposed, how retrieval behaves, and what metadata
is leaking.
"""
from __future__ import annotations

from typing import Any, ClassVar

from ai_recon.core.models import Finding, Target
from ai_recon.techniques.base import Technique


def _severity_for_summary(confidence: float, metadata_leak_items: int) -> str:
    if metadata_leak_items >= 3:
        return "high"
    if confidence >= 0.7:
        return "medium"
    if confidence >= 0.4:
        return "low"
    return "info"


class RAGPipelineSummary(Technique):
    id: ClassVar[str] = "active.rag_pipeline_summary"
    intrusiveness: ClassVar[str] = "low"
    requires: ClassVar[set[str]] = {
        "rag.detected",
        "rag.document_inventory",
        "rag.threshold",
        "rag.metadata_exposure",
    }
    produces: ClassVar[set[str]] = {"rag.pipeline_summary"}

    async def run(self, target: Target) -> list[Finding]:
        rag_profile = getattr(self.ctx, "rag_profile", None)
        boundary = getattr(self.ctx, "rag_boundary_result", None) or {}
        metadata = getattr(self.ctx, "rag_metadata_result", None) or {}

        detected = bool(getattr(rag_profile, "detected", False)) if rag_profile else False
        exposure_level = getattr(rag_profile, "exposure_level", "none") if rag_profile else "none"
        documents = getattr(rag_profile, "documents", []) if rag_profile else []
        threshold = getattr(rag_profile, "inferred_threshold", None) if rag_profile else None
        chunking = getattr(rag_profile, "chunking", None) if rag_profile else None
        retrieval = getattr(rag_profile, "retrieval", None) if rag_profile else None

        boundary_classification = boundary.get("classification")
        boundary_detected = boundary.get("boundary_detected")
        metadata_by_kind = metadata.get("by_kind", {})
        metadata_items = sum(len(values) for values in metadata_by_kind.values())

        signals = 0
        score = 0.0
        if detected:
            signals += 1
            score += 0.9
        if documents:
            signals += 1
            score += 0.8
        if threshold is not None:
            signals += 1
            score += 0.6
        if exposure_level != "none":
            signals += 1
            score += 0.7
        if metadata_items > 0:
            signals += 1
            score += 0.8
        overall_confidence = round(score / signals, 4) if signals else 0.0

        conclusion_parts: list[str] = []
        if detected:
            conclusion_parts.append(
                f"RAG active: yes ({boundary_classification or 'classification unavailable'})"
            )
        else:
            conclusion_parts.append("RAG active: not confirmed")

        if boundary_detected:
            conclusion_parts.append("Retrieval boundary observed between generic and in-corpus queries")

        if documents:
            sample_titles = ", ".join(doc.title for doc in documents[:5])
            suffix = "" if len(documents) <= 5 else " ..."
            conclusion_parts.append(
                f"Knowledge base mapping: {len(documents)} document(s) discovered ({sample_titles}{suffix})"
            )

        if chunking:
            docs_with_chunks = chunking.get("documents_with_chunk_ids")
            multi_chunks = chunking.get("documents_with_multiple_chunks")
            max_chunk = chunking.get("max_chunk_ordinal_observed")
            conclusion_parts.append(
                "Chunking observed: "
                f"{docs_with_chunks} doc(s) with chunk IDs, "
                f"{multi_chunks} doc(s) spanning multiple chunks, "
                f"max chunk ordinal {max_chunk}"
            )

        if threshold is not None:
            conclusion_parts.append(f"Retrieval threshold estimate: ~{threshold:.3f}")

        if retrieval:
            conclusion_parts.append(
                "Retrieval timing: "
                f"avg retrieval {retrieval.get('avg_retrieval_time_ms')} ms, "
                f"avg generation {retrieval.get('avg_generation_time_ms')} ms"
            )

        conclusion_parts.append(f"Metadata exposure level: {exposure_level}")
        if metadata_items:
            conclusion_parts.append(
                f"Metadata leakage: {metadata_items} item(s) across {len(metadata_by_kind)} category(ies)"
            )

        conclusion = "\n".join(f"  • {part}" for part in conclusion_parts)
        severity = _severity_for_summary(overall_confidence, metadata_items)
        confidence = "high" if overall_confidence >= 0.7 else "medium" if overall_confidence >= 0.4 else "low"

        return [
            self._make_finding(
                target,
                severity=severity,
                confidence=confidence,
                title=f"RAG Pipeline Summary: {len(documents)} document(s), exposure {exposure_level}",
                evidence={
                    "conclusion": conclusion,
                    "overall_confidence": overall_confidence,
                    "rag_detected": detected,
                    "boundary": boundary,
                    "documents_count": len(documents),
                    "sample_documents": [doc.model_dump() for doc in documents[:10]],
                    "chunking": chunking,
                    "retrieval": retrieval,
                    "inferred_threshold": threshold,
                    "metadata_exposure_level": exposure_level,
                    "metadata_leak": metadata,
                },
                references=[],
            )
        ]