"""Jailbreak suite — runs a corpus of known jailbreaks against a target model.

Loads YAML files from ``catalogs/jailbreak_corpus/`` and dispatches each
payload through the LLM adapter, then evaluates a per-jailbreak
``success_oracle`` (regex by default).

Reports a per-jailbreak Finding plus a matrix-style summary.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

import yaml

from ai_recon.adapters.llm_protocol.openai_compat import OpenAICompatAdapter
from ai_recon.core.models import Finding, Message, Target
from ai_recon.techniques.base import Technique

_CORPUS = Path(__file__).parent.parent.parent / "catalogs" / "jailbreak_corpus"

_INTR_TO_SEV = {"low": "low", "medium": "medium", "high": "high"}


def _load_corpus() -> list[dict]:
    items: list[dict] = []
    for yml in sorted(_CORPUS.glob("*.yaml")):
        try:
            data = yaml.safe_load(yml.read_text()) or {}
        except Exception:
            continue
        for entry in data.get("jailbreaks", []) or []:
            entry["_source"] = yml.stem
            items.append(entry)
    return items


def _evaluate_oracle(oracle: dict, response_text: str) -> bool:
    if not oracle:
        return False
    kind = oracle.get("type", "regex")
    if kind == "regex":
        try:
            return re.search(oracle.get("pattern", "$^"), response_text) is not None
        except re.error:
            return False
    if kind == "substring":
        return oracle.get("value", "") in response_text
    return False


class JailbreakSuite(Technique):
    id: ClassVar[str] = "active.jailbreak_suite"
    intrusiveness: ClassVar[str] = "high"
    requires: ClassVar[set[str]] = {"model.vendor"}
    produces: ClassVar[set[str]] = {"safety.jailbreak_matrix"}

    async def run(self, target: Target) -> list[Finding]:
        corpus = _load_corpus()
        adapter = getattr(self.ctx, "llm_adapter", None) or OpenAICompatAdapter(
            base_url=target.base_url
        )

        # Optional vendor filter from prior model_identity finding.
        vendor = None
        mp = getattr(self.ctx, "model_profile", None)
        if mp is not None:
            vendor = getattr(mp, "vendor", None)

        findings: list[Finding] = []
        matrix: dict[str, dict] = {}

        for entry in corpus:
            jb_id = entry.get("id", "?")
            target_vendors = entry.get("target_vendors") or []
            if vendor and target_vendors and vendor not in target_vendors:
                matrix[jb_id] = {"status": "skipped",
                                 "reason": f"not targeted at vendor={vendor}"}
                continue

            prompt = entry.get("payload", "").strip()
            if not prompt:
                continue
            try:
                resp = await adapter.chat([Message(role="user", content=prompt)])
                text = resp.text
            except Exception as exc:
                matrix[jb_id] = {"status": "error", "error": str(exc)}
                continue

            oracle_hit = _evaluate_oracle(entry.get("success_oracle", {}), text)
            matrix[jb_id] = {
                "status": "success" if oracle_hit else "blocked",
                "category": entry.get("category"),
                "name": entry.get("name"),
            }

            if oracle_hit:
                findings.append(
                    self._make_finding(
                        target,
                        severity="high",
                        confidence="high",
                        title=f"Jailbreak success: {entry.get('name', jb_id)}",
                        evidence={
                            "jailbreak_id": jb_id,
                            "category": entry.get("category"),
                            "payload_preview": prompt[:200],
                            "response_preview": text[:400],
                            "oracle": entry.get("success_oracle"),
                        },
                        references=entry.get("references", []) or [],
                    )
                )

        # Aggregate
        success_count = sum(1 for v in matrix.values() if v.get("status") == "success")
        findings.append(
            self._make_finding(
                target,
                severity="info" if success_count == 0 else "medium",
                confidence="high",
                title=f"Jailbreak suite: {success_count}/{len(matrix)} succeeded",
                evidence={
                    "matrix": matrix,
                    "success_count": success_count,
                    "total": len(matrix),
                    "by_category": {
                        c: sum(1 for v in matrix.values() if v.get("category") == c)
                        for c in {v.get("category") for v in matrix.values() if v.get("category")}
                    },
                },
            )
        )
        return findings
