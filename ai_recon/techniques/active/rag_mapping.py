"""RAG mapping technique — systematically maps the RAG knowledge base by topic."""
from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from ai_recon.adapters.llm_protocol.openai_compat import OpenAICompatAdapter
from ai_recon.core.models import DocumentRef, Finding, Message, RAGProfile, RunContext, Target
from ai_recon.core.errors import TechniqueAborted
from ai_recon.techniques.base import Technique
from ai_recon.techniques.active.rag_boundary import _parse_sources_from_response

CATALOG_DIR = Path(__file__).parent.parent.parent / "catalogs"

DEFAULT_TOPICS: list[str] = [
    "vacation policy",
    "expense reports",
    "API documentation",
    "system architecture",
    "security policies",
    "onboarding",
    "organizational structure",
    "product roadmap",
    "incident response",
    "data retention",
]

_QUERY_TEMPLATES: list[str] = [
    "What is the {topic}?",
    "Tell me about {topic}",
    "Where can I find {topic} information?",
    "What does the company say about {topic}?",
    "Summarize {topic} policy",
]


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

        adapter = getattr(self.ctx, "llm_adapter", None)
        if adapter is None:
            adapter = OpenAICompatAdapter(base_url=target.base_url)

        # document_inventory: title → {chunk_ids, scores, snippets}
        document_inventory: dict[str, dict[str, Any]] = {}

        for topic in self._topics:
            query_templates = _QUERY_TEMPLATES[: self._queries_per_topic]
            for template in query_templates:
                query = template.format(topic=topic)
                try:
                    resp = await adapter.chat([Message(role="user", content=query)])
                    sources = _parse_sources_from_response(resp.text, resp.raw)
                except Exception:
                    continue

                for src in sources:
                    title = src.title or "unknown"
                    if title not in document_inventory:
                        document_inventory[title] = {
                            "chunk_ids": [],
                            "scores": [],
                            "snippets": [],
                            "topics_hit": [],
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
                rag_profile.documents = [
                    DocumentRef(title=title, chunk_id=info["chunk_ids"][0] if info["chunk_ids"] else None)
                    for title, info in document_inventory.items()
                ]
            except Exception:
                pass

        return findings
