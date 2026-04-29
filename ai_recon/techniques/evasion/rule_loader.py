"""Loads SIEM detection rules and compiles them into a regex matcher set."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ai_recon.adapters.siem.base import DetectionRule, SIEMAdapter
from ai_recon.techniques.evasion.kql_to_regex import CompiledRule, query_to_regex


@dataclass
class RuleSet:
    """Compiled detection rules ready for pre-flight matching."""

    rules: list[CompiledRule]

    def matches(self, content: str) -> list[CompiledRule]:
        return [r for r in self.rules if r.regex.search(content)]


async def load_ruleset(adapter: SIEMAdapter) -> RuleSet:
    """Pull rules from a SIEM adapter and compile each one to a regex."""
    raw: Iterable[DetectionRule] = await adapter.list_detection_rules()
    compiled: list[CompiledRule] = []
    for r in raw:
        pat = query_to_regex(r.query, r.query_language)
        if pat is None:
            continue
        compiled.append(
            CompiledRule(
                rule_id=r.id,
                language=r.query_language,
                regex=pat,
                raw_query=r.query,
            )
        )
    return RuleSet(rules=compiled)
