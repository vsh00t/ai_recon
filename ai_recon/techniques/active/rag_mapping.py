"""RAG mapping technique — systematically maps the RAG knowledge base by topic."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, ClassVar

from ai_recon.core.models import DocumentRef, Finding, RAGProfile, RunContext, Target
from ai_recon.techniques.base import Technique
from ai_recon.techniques.active.rag_boundary import _parse_sources_from_response
from ai_recon.techniques.active.rag_probe import rag_chat

CATALOG_DIR = Path(__file__).parent.parent.parent / "catalogs"

DEFAULT_TOPICS: list[str] = [
    "PTO policy",
    "employee handbook",
    "internal API endpoints",
    "API documentation",
    "system architecture",
    "security policies",
    "incident response",
    "data retention",
    "benefits and compensation",
    "developer portal",
    "incident response",
]

_QUERY_TEMPLATES: list[str] = [
    "What is the {topic}?",
    "Tell me about {topic}",
    "Where can I find {topic} information?",
    "What does the company say about {topic}?",
    "Summarize {topic} policy",
    "What internal documentation mentions {topic}?",
]


def _chunk_ordinal(chunk_id: str) -> int | None:
    match = re.search(r"(\d+)$", chunk_id)
    return int(match.group(1)) if match else None


class RAGMapping(Technique):
    id: ClassVar[str] = "active.rag_mapping"
    intrusiveness: ClassVar[str] = "low"
    produces: ClassVar[set[str]] = {"rag.document_inventory"}

    # Configurable options
    def __init__(self, ctx: RunContext, topics: list[str] | None = None, queries_per_topic: int = 5) -> None:
        super().__init__(ctx)
        self._topics = topics or DEFAULT_TOPICS
        self._queries_per_topic = min(queries_per_topic, len(_QUERY_TEMPLATES))

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        # document_inventory: title → {chunk_ids, scores, snippets}
        document_inventory: dict[str, dict[str, Any]] = {}
        retrieval_infos: list[dict[str, Any]] = []

        for topic in self._topics:
            query_templates = _QUERY_TEMPLATES[: self._queries_per_topic]
            for template in query_templates:
                query = template.format(topic=topic)
                try:
                    resp = await rag_chat(self.ctx, target, query)
                    sources = _parse_sources_from_response(resp.text, resp.raw)
                except Exception:
                    continue

                if isinstance(resp.raw.get("retrieval_info"), dict):
                    retrieval_infos.append(resp.raw["retrieval_info"])

                for src in sources:
                    title = src.title or "unknown"
                    if title not in document_inventory:
                        document_inventory[title] = {
                            "chunk_ids": [],
                            "scores": [],
                            "snippets": [],
                            "topics_hit": [],
                            "query_examples": [],
                        }
                    entry = document_inventory[title]
                    if src.chunk_id and src.chunk_id not in entry["chunk_ids"]:
                        entry["chunk_ids"].append(src.chunk_id)
                    if src.combined_score is not None or src.vector_score is not None:
                        score = src.combined_score or src.vector_score
                        if score not in entry["scores"]:
                            entry["scores"].append(score)
                    if src.snippet and src.snippet not in entry["snippets"]:
                        entry["snippets"].append(src.snippet[:200])
                    if topic not in entry["topics_hit"]:
                        entry["topics_hit"].append(topic)
                    if query not in entry["query_examples"]:
                        entry["query_examples"].append(query)

        total_chunks = sum(len(v["chunk_ids"]) for v in document_inventory.values())
        docs_found = len(document_inventory)

        if docs_found == 0:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="low",
                    title="RAG mapping: no documents discovered",
                    evidence={
                        "topics_tested": self._topics,
                        "queries_per_topic": self._queries_per_topic,
                        "note": "No source metadata returned — RAG may not be active or uses in-band citations only.",
                    },
                    references=[],
                )
            )
            return findings

        chunking_summary: dict[str, Any] = {
            "documents_with_chunk_ids": 0,
            "max_chunk_ordinal_observed": None,
            "documents_with_multiple_chunks": 0,
        }
        max_ordinal: int | None = None
        for info in document_inventory.values():
            ordinals = [
                _chunk_ordinal(chunk_id)
                for chunk_id in info["chunk_ids"]
                if chunk_id
            ]
            ordinals = [value for value in ordinals if value is not None]
            if info["chunk_ids"]:
                chunking_summary["documents_with_chunk_ids"] += 1
            if len(info["chunk_ids"]) > 1:
                chunking_summary["documents_with_multiple_chunks"] += 1
            if ordinals:
                local_max = max(ordinals)
                max_ordinal = local_max if max_ordinal is None else max(max_ordinal, local_max)
        chunking_summary["max_chunk_ordinal_observed"] = max_ordinal

        retrieval_summary: dict[str, Any] = {}
        if retrieval_infos:
            retrieval_summary = {
                "sample_count": len(retrieval_infos),
                "avg_retrieval_time_ms": round(sum(float(r.get("retrieval_time_ms", 0.0)) for r in retrieval_infos) / len(retrieval_infos), 3),
                "avg_generation_time_ms": round(sum(float(r.get("generation_time_ms", 0.0)) for r in retrieval_infos) / len(retrieval_infos), 3),
                "avg_total_time_ms": round(sum(float(r.get("total_time_ms", 0.0)) for r in retrieval_infos) / len(retrieval_infos), 3),
            }

        # Main inventory finding
        findings.append(
            self._make_finding(
                target,
                severity="medium",
                confidence="high",
                title=f"RAG knowledge base mapped: {docs_found} documents discovered",
                evidence={
                    "document_inventory": document_inventory,
                    "total_chunks": total_chunks,
                    "topics_covered": self._topics,
                    "queries_per_topic": self._queries_per_topic,
                    "chunking_summary": chunking_summary,
                    "retrieval_summary": retrieval_summary,
                },
                references=[],
            )
        )

        findings.append(
            self._make_finding(
                target,
                severity="info",
                confidence="medium",
                title="RAG chunking and retrieval behavior observed",
                evidence={
                    "chunking_summary": chunking_summary,
                    "retrieval_summary": retrieval_summary,
                },
                references=[],
            )
        )

        # Per-document finding
        for title, info in document_inventory.items():
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="high",
                    title=f"Document discovered: {title}",
                    evidence={
                        "title": title,
                        "chunk_ids": info["chunk_ids"],
                        "scores": info["scores"],
                        "snippets": info["snippets"],
                        "topics_hit": info["topics_hit"],
                        "query_examples": info["query_examples"][:3],
                    },
                    references=[],
                )
            )

        # Update ctx.rag_profile
        rag_profile = getattr(self.ctx, "rag_profile", None)
        if rag_profile is None:
            try:
                self.ctx.rag_profile = RAGProfile(  # type: ignore[attr-defined]
                    detected=True,
                    chunking=chunking_summary,
                    retrieval=retrieval_summary,
                    documents=[
                        DocumentRef(title=title, chunk_id=info["chunk_ids"][0] if info["chunk_ids"] else None)
                        for title, info in document_inventory.items()
                    ],
                )
            except Exception:
                pass
        else:
            try:
                rag_profile.detected = True
                rag_profile.chunking = chunking_summary
                rag_profile.retrieval = retrieval_summary
                rag_profile.documents = [
                    DocumentRef(title=title, chunk_id=info["chunk_ids"][0] if info["chunk_ids"] else None)
                    for title, info in document_inventory.items()
                ]
            except Exception:
                pass

        return findings
