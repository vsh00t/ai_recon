from __future__ import annotations

from ai_recon.techniques.evasion.rephraser import Rephraser


def test_rephraser_load_returns_instance():
    r = Rephraser.load()
    assert isinstance(r.intents, list)


def test_rephraser_returns_none_when_no_match():
    r = Rephraser.load()
    # A clearly safe prompt → no matching intent → None.
    assert r.rephrase("What is 2+2?") is None
