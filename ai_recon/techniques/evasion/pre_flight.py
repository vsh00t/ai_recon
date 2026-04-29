"""Pre-flight gate: evaluate each outbound prompt against the SIEM ruleset
and rephrase or abort before sending.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ai_recon.core.errors import TechniqueAborted
from ai_recon.techniques.evasion.rephraser import Rephraser
from ai_recon.techniques.evasion.rule_loader import RuleSet


PreFlightAction = Literal["pass", "rephrase", "abort"]


@dataclass
class PreFlightDecision:
    action: PreFlightAction
    rewritten_prompt: str | None
    matched_rules: list[str]
    intent_id: str | None
    reason: str


class PreFlight:
    """Decision engine. Stateless — safe to share between techniques.

    Strategy:
      1. If no rules match the prompt → pass.
      2. If rules match and a safe rephrase exists → rephrase.
      3. If rules match and no rephrase exists → abort (TechniqueAborted).
         Never silently send the original prompt.
    """

    def __init__(self, ruleset: RuleSet, rephraser: Rephraser) -> None:
        self._rules = ruleset
        self._rephraser = rephraser

    def evaluate(self, prompt: str, technique_id: str = "") -> PreFlightDecision:
        matches = self._rules.matches(prompt)
        if not matches:
            return PreFlightDecision(
                action="pass",
                rewritten_prompt=prompt,
                matched_rules=[],
                intent_id=None,
                reason="no rule match",
            )

        rule_ids = [r.rule_id for r in matches]
        intent = self._rephraser.find_intent(prompt)
        rewritten = self._rephraser.rephrase(prompt) if intent else None

        if rewritten is not None:
            return PreFlightDecision(
                action="rephrase",
                rewritten_prompt=rewritten,
                matched_rules=rule_ids,
                intent_id=intent.id if intent else None,
                reason=f"matched {len(rule_ids)} rule(s); rephrased via intent={intent.id if intent else '?'}",
            )

        return PreFlightDecision(
            action="abort",
            rewritten_prompt=None,
            matched_rules=rule_ids,
            intent_id=None,
            reason=f"matched {len(rule_ids)} rule(s); no safe rephrase available",
        )

    def enforce(self, prompt: str, technique_id: str) -> str:
        """Convenience: returns the safe prompt or raises TechniqueAborted."""
        d = self.evaluate(prompt, technique_id)
        if d.action == "abort":
            raise TechniqueAborted(
                technique_id,
                f"pre-flight blocked: matched={d.matched_rules}; {d.reason}",
            )
        return d.rewritten_prompt or prompt
