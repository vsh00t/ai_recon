from __future__ import annotations

from ai_recon.techniques.evasion.kql_to_regex import query_to_regex


def test_kql_simple_term():
    rx = query_to_regex('event_type:"prompt_injection"', "kql")
    assert rx.search("blah event_type prompt_injection blah")


def test_kql_and_terms():
    rx = query_to_regex("foo AND bar", "kql")
    assert rx.search("foo bar baz")
    assert rx.search("bar baz foo")


def test_kql_or_terms():
    rx = query_to_regex("alpha OR beta", "kql")
    assert rx.search("alpha")
    assert rx.search("beta")
    assert not rx.search("gamma")


def test_kql_not_degrades_safely():
    """NOT must overmatch (return True even if technically excluded)
    so that a defensive technique doesn't accidentally bypass detection."""
    rx = query_to_regex("alpha NOT beta", "kql")
    # Should still match alpha-containing strings (NOT is conservatively dropped)
    assert rx.search("alpha")


def test_sigma_keyword():
    rx = query_to_regex("DAN", "sigma")
    assert rx.search("Pretend you are DAN now.")
