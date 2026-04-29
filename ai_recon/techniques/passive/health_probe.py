"""Passive health endpoint probing technique.

Paths and "interesting keys" are loaded from
``catalogs/health_endpoints.yaml`` so the technique stays generic and
can be tuned per-engagement without code changes.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import ClassVar

import yaml

from ai_recon.core.models import Finding, RunContext, Target
from ai_recon.techniques.base import Technique

_CATALOG = Path(__file__).parent.parent.parent / "catalogs" / "health_endpoints.yaml"

_FALLBACK_PATHS: list[str] = [
    "/api/health", "/api/status", "/-/health", "/healthz", "/livez",
    "/readyz", "/metrics", "/info", "/status", "/health",
]
_FALLBACK_KEYS: set[str] = {
    "model", "models", "version", "rag_enabled", "mcp_enabled",
    "tools_enabled", "tools", "backend", "provider", "service",
    "vendor", "embedding_model", "vector_db",
}


@lru_cache(maxsize=1)
def _load_catalog() -> tuple[list[str], set[str]]:
    try:
        data = yaml.safe_load(_CATALOG.read_text()) or {}
    except FileNotFoundError:
        return _FALLBACK_PATHS, _FALLBACK_KEYS
    items = data.get("health_endpoints", []) or []
    paths: list[str] = []
    for it in items:
        if isinstance(it, dict) and "path" in it:
            paths.append(str(it["path"]))
        elif isinstance(it, str):
            paths.append(it)
    keys = set(data.get("sensitive_keys", []) or _FALLBACK_KEYS)
    return (paths or _FALLBACK_PATHS), keys


def _find_interesting_keys(
    data: dict,
    sensitive_keys: set[str],
    prefix: str = "",
) -> dict:
    """Recursively find sensitive keys in a nested dict."""
    result: dict = {}
    lower = {k.lower() for k in sensitive_keys}
    for k, v in data.items():
        full = f"{prefix}.{k}" if prefix else k
        if k.lower() in lower:
            result[full] = v
        if isinstance(v, dict):
            result.update(_find_interesting_keys(v, sensitive_keys, full))
    return result


class HealthProbeTechnique(Technique):
    id: ClassVar[str] = "passive.health_probe"
    intrusiveness: ClassVar = "passive"
    produces: ClassVar[set[str]] = {"ai.rag_enabled", "ai.mcp_enabled", "ai.model_hint"}

    # Set stop_at_first=True to stop after first successful probe (default).
    # Set to False in ctx to probe all endpoints.
    stop_at_first: bool = True

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        client = self.ctx.http_client
        base_url = target.base_url
        paths, sensitive_keys = _load_catalog()

        for path in paths:
            url = f"{base_url}{path}"
            try:
                response = await client.get(url)
            except Exception:
                continue

            if response.status_code != 200:
                continue

            body_text = response.text
            body_sample = body_text[:500]

            # Attempt JSON parse
            parsed: dict | None = None
            try:
                parsed = json.loads(body_text)
            except (json.JSONDecodeError, ValueError):
                parsed = None

            if parsed and isinstance(parsed, dict):
                interesting = _find_interesting_keys(parsed, sensitive_keys)
                found_keys = list(interesting.keys())

                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="high",
                        title=f"Health endpoint exposed: {path}",
                        evidence={
                            "path": path,
                            "url": url,
                            "fields": found_keys,
                            "body_sample": body_sample,
                        },
                    )
                )

                # Check for RAG
                rag_val = self._deep_get(parsed, "rag_enabled")
                if rag_val is True or str(rag_val).lower() in ("true", "1", "yes"):
                    findings.append(
                        self._make_finding(
                            target,
                            severity="medium",
                            confidence="high",
                            title="RAG pipeline detected via health endpoint",
                            evidence={"path": path, "url": url, "rag_enabled": rag_val},
                        )
                    )

                # Check for MCP
                mcp_val = self._deep_get(parsed, "mcp_enabled")
                if mcp_val is True or str(mcp_val).lower() in ("true", "1", "yes"):
                    findings.append(
                        self._make_finding(
                            target,
                            severity="medium",
                            confidence="high",
                            title="MCP server detected via health endpoint",
                            evidence={"path": path, "url": url, "mcp_enabled": mcp_val},
                        )
                    )

                # Check for model name
                model_val = self._deep_get(parsed, "model")
                if model_val is not None:
                    findings.append(
                        self._make_finding(
                            target,
                            severity="low",
                            confidence="high",
                            title="Model name exposed in health endpoint",
                            evidence={"path": path, "url": url, "model": model_val},
                        )
                    )
            else:
                # Non-JSON 200 response — still worth noting
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="medium",
                        title=f"Health endpoint exposed: {path}",
                        evidence={
                            "path": path,
                            "url": url,
                            "fields": [],
                            "body_sample": body_sample,
                        },
                    )
                )

            if self.stop_at_first:
                break

        return findings

    @staticmethod
    def _deep_get(data: dict, key: str):
        """Search for a key recursively in a nested dict."""
        if key in data:
            return data[key]
        for v in data.values():
            if isinstance(v, dict):
                result = HealthProbeTechnique._deep_get(v, key)
                if result is not None:
                    return result
        return None
