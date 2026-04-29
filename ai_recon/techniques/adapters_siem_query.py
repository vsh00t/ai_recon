"""SIEM query technique — issues a search to the configured SIEM adapter
to test whether ai-recon's own activity has been detected, and surfaces
the matching events in the report.

Registered under id ``adapters.siem_query`` per profile YAML naming.
"""

from __future__ import annotations

from typing import ClassVar

from datetime import datetime, timedelta, timezone

from ai_recon.core.models import Finding, Target
from ai_recon.techniques.base import Technique


_DEFAULT_TERMS: list[str] = [
    "prompt injection",
    "jailbreak",
    "system prompt",
    "DAN",
]


class SIEMQuery(Technique):
    id: ClassVar[str] = "adapters.siem_query"
    intrusiveness: ClassVar[str] = "passive"
    requires: ClassVar[set[str]] = set()
    produces: ClassVar[set[str]] = {"siem.events"}

    async def run(self, target: Target) -> list[Finding]:
        siem = getattr(self.ctx, "siem_adapter", None)
        if siem is None or not hasattr(siem, "search"):
            return [self._make_finding(
                target, severity="info", confidence="high",
                title="SIEM query skipped (no adapter configured)",
                evidence={"reason": "no_siem_adapter"},
            )]

        cfg = getattr(self.ctx, "config", {}) or {}
        params = cfg.get("adapters.siem_query", {}) if isinstance(cfg, dict) else {}
        terms = params.get("search_terms") or _DEFAULT_TERMS
        lookback = int(params.get("lookback_hours") or 24)
        since = datetime.now(timezone.utc) - timedelta(hours=lookback)

        findings: list[Finding] = []
        per_term: list[dict] = []
        total_events = 0
        for term in terms:
            try:
                events = await siem.search(term, since=since)
            except Exception as exc:
                per_term.append({"term": term, "error": str(exc)})
                continue
            count = len(events)
            total_events += count
            per_term.append({
                "term": term,
                "count": count,
                "events_sample": [str(e) for e in events[:5]],
            })

        sev = "low" if total_events > 0 else "info"
        findings.append(
            self._make_finding(
                target, severity=sev, confidence="high",
                title=f"SIEM query: {total_events} event(s) across "
                      f"{len(terms)} term(s) (last {lookback}h)",
                evidence={
                    "lookback_hours": lookback,
                    "total_events": total_events,
                    "per_term": per_term,
                },
            )
        )
        return findings
