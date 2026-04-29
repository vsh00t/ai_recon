"""Report generation: JSON, Markdown, HTML, and SARIF 2.1.0."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ai_recon.core.models import Finding, Report

# Severity → SARIF level mapping
_SARIF_LEVEL = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}

_SEVERITY_EMOJI = {
    "info": "ℹ️",
    "low": "🟡",
    "medium": "🟠",
    "high": "🔴",
    "critical": "🚨",
}


class ReportEmitter:
    """Serialises a Report to various formats."""

    def __init__(self, report: Report) -> None:
        self._r = report

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        return self._r.model_dump_json(indent=indent)

    def write_json(self, path: Path) -> None:
        path.write_text(self.to_json())

    # ------------------------------------------------------------------
    # Markdown
    # ------------------------------------------------------------------

    def to_markdown(self) -> str:
        r = self._r
        lines: list[str] = [
            f"# ai-recon Report — {r.scope.engagement.name}",
            "",
            f"**Run ID:** `{r.run_id}`  ",
            f"**Profile:** `{r.profile}`  ",
            f"**Started:** {r.started_at.isoformat()}  ",
            f"**Finished:** {r.finished_at.isoformat()}  ",
            f"**Authorization:** `{r.scope.engagement.authorization_ref}`  ",
            "",
        ]
        if r.diff_vs:
            lines += [f"> Diffed against run `{r.diff_vs}`", ""]

        # Findings summary
        counts: dict[str, int] = {}
        for f in r.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        lines += ["## Summary", ""]
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in counts:
                lines.append(f"- {_SEVERITY_EMOJI[sev]} **{sev.upper()}**: {counts[sev]}")
        lines.append("")

        # Model profiles
        if r.model_profiles:
            lines += ["## Model Profiles", ""]
            for tid, mp in r.model_profiles.items():
                lines += [
                    f"### Target `{tid}`",
                    f"- Vendor: `{mp.vendor or '?'}`  Family: `{mp.family or '?'}`  "
                    f"Size: `{mp.size_hint or '?'}`",
                    f"- Cutoff: `{mp.knowledge_cutoff or '?'}`  "
                    f"Context window: `{mp.context_window or '?'}` tokens",
                    f"- Tokenizer: `{mp.tokenizer or '?'}`  "
                    f"Confidence: `{mp.confidence:.0%}`",
                    "",
                ]

        # RAG profiles
        if r.rag_profiles:
            lines += ["## RAG Profiles", ""]
            for tid, rp in r.rag_profiles.items():
                lines += [
                    f"### Target `{tid}`",
                    f"- Detected: `{rp.detected}`  "
                    f"Exposure: `{rp.exposure_level}`  "
                    f"Vector store: `{rp.vector_store or '?'}`",
                    f"- Embedding: `{rp.embedding_model or '?'}`  "
                    f"Threshold: `{rp.inferred_threshold or '?'}`",
                    f"- Documents indexed: {len(rp.documents)}",
                    "",
                ]

        # Findings detail
        lines += ["## Findings", ""]
        for sev in ("critical", "high", "medium", "low", "info"):
            sevfinds = [f for f in r.findings if f.severity == sev]
            if not sevfinds:
                continue
            lines += [f"### {_SEVERITY_EMOJI[sev]} {sev.upper()}", ""]
            for f in sevfinds:
                lines += [
                    f"#### {f.title}",
                    f"- **ID:** `{f.id}`  **Technique:** `{f.technique}`  "
                    f"**Target:** `{f.target_id}`",
                    f"- **Confidence:** `{f.confidence}`  "
                    f"**Intrusiveness:** `{f.intrusiveness}`  "
                    f"**At:** {f.detected_at.isoformat()}",
                    "",
                ]
                if f.evidence:
                    lines += ["<details><summary>Evidence</summary>", "", "```json"]
                    lines.append(json.dumps(f.evidence, indent=2, default=str))
                    lines += ["```", "", "</details>", ""]
                if f.references:
                    lines += ["**References:**"]
                    for ref in f.references:
                        lines.append(f"- {ref}")
                    lines.append("")

        return "\n".join(lines)

    def write_markdown(self, path: Path) -> None:
        path.write_text(self.to_markdown())

    # ------------------------------------------------------------------
    # SARIF 2.1.0
    # ------------------------------------------------------------------

    def to_sarif(self) -> dict[str, Any]:
        r = self._r
        rules: list[dict] = []
        seen_rules: set[str] = set()
        results: list[dict] = []

        for f in r.findings:
            if f.technique not in seen_rules:
                seen_rules.add(f.technique)
                rules.append({
                    "id": f.technique,
                    "name": f.technique.replace(".", "_"),
                    "shortDescription": {"text": f.technique},
                    "properties": {"intrusiveness": f.intrusiveness},
                })
            results.append({
                "ruleId": f.technique,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f.title},
                "properties": {
                    "confidence": f.confidence,
                    "target_id": f.target_id,
                    "severity": f.severity,
                    "evidence": f.evidence,
                },
            })

        return {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ai-recon",
                            "version": "0.1.0",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "run_id": r.run_id,
                        "profile": r.profile,
                        "engagement": r.scope.engagement.name,
                    },
                }
            ],
        }

    def write_sarif(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_sarif(), indent=2))

    # ------------------------------------------------------------------
    # HTML (simple, self-contained)
    # ------------------------------------------------------------------

    def to_html(self) -> str:
        md = self.to_markdown()
        # Minimal HTML wrapper; a real build could use markdown2 or mistune
        escaped = md.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ai-recon — {self._r.scope.engagement.name}</title>
<style>
  body {{ font-family: monospace; max-width: 960px; margin: auto; padding: 2rem; }}
  pre {{ background: #f4f4f4; padding: 1rem; overflow-x: auto; }}
</style>
</head>
<body>
<pre>{escaped}</pre>
</body>
</html>"""

    def write_html(self, path: Path) -> None:
        path.write_text(self.to_html())

    # ------------------------------------------------------------------
    # Diff
    # ------------------------------------------------------------------

    @staticmethod
    def diff(base: Report, head: Report) -> dict[str, Any]:
        base_ids = {f.id for f in base.findings}
        head_ids = {f.id for f in head.findings}
        new_findings = [f for f in head.findings if f.id not in base_ids]
        resolved = [f for f in base.findings if f.id not in head_ids]
        return {
            "base_run_id": base.run_id,
            "head_run_id": head.run_id,
            "new_findings": [f.model_dump() for f in new_findings],
            "resolved_findings": [f.model_dump() for f in resolved],
            "new_count": len(new_findings),
            "resolved_count": len(resolved),
        }
