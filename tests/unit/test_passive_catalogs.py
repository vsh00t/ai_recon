from __future__ import annotations

from ai_recon.techniques.passive.header_fingerprint import _load_catalog as _hf_load
from ai_recon.techniques.passive.health_probe import (
    _load_catalog as _hp_load,
    _find_interesting_keys,
)


def test_ai_headers_catalog_has_expected_sections():
    cat = _hf_load()
    assert "ai_backend_hints" in cat
    assert "rag_hints" in cat
    # Sanity: catalog actually contains values
    assert any("X-AI-Backend" == h for h in cat["ai_backend_hints"])
    assert any("X-RAG-Provider" == h for h in cat["rag_hints"])


def test_health_endpoints_catalog_loaded():
    paths, keys = _hp_load()
    assert "/api/health" in paths
    assert "/healthz" in paths
    assert "model" in {k.lower() for k in keys}
    assert "rag_enabled" in {k.lower() for k in keys}


def test_find_interesting_keys_recursive():
    data = {
        "service": "asst",
        "config": {"model": "gpt-x", "rag_enabled": True, "ignore": 1},
    }
    out = _find_interesting_keys(data, {"model", "rag_enabled", "service"})
    assert "service" in out
    assert "config.model" in out
    assert "config.rag_enabled" in out
    assert "config.ignore" not in out
