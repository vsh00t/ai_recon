"""Map "risky" prompt phrasings to safe equivalents using rephrase_intents.yaml."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

CATALOG = Path(__file__).parent.parent.parent / "catalogs" / "rephrase_intents.yaml"


@dataclass
class Intent:
    id: str
    risky_phrasings: list[str]
    safe_phrasings: list[str]
    description: str = ""


@dataclass
class Rephraser:
    """Look up safe equivalents for a prompt by matching risky phrasings.

    Returns ``None`` when no intent matches — callers must treat this as
    "no safe rewrite available" and abort, never silently send the original.
    """

    intents: list[Intent] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path = CATALOG) -> "Rephraser":
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except FileNotFoundError:
            return cls()
        intents = []
        for item in data.get("rephrase_intents", []) or []:
            intents.append(
                Intent(
                    id=item["id"],
                    risky_phrasings=item.get("risky_phrasings", []) or [],
                    safe_phrasings=item.get("safe_phrasings", []) or [],
                    description=item.get("description", ""),
                )
            )
        return cls(intents=intents)

    def find_intent(self, prompt: str) -> Intent | None:
        text = prompt.lower()
        for intent in self.intents:
            for phrase in intent.risky_phrasings:
                if phrase.lower() in text:
                    return intent
        return None

    def rephrase(self, prompt: str, variant: int = 0) -> str | None:
        intent = self.find_intent(prompt)
        if intent is None or not intent.safe_phrasings:
            return None
        return intent.safe_phrasings[variant % len(intent.safe_phrasings)]
