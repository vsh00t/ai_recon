"""Passive JavaScript config extraction technique."""
from __future__ import annotations

import json
import re
from typing import ClassVar
from urllib.parse import urljoin, urlparse

from ai_recon.core.models import Finding, RunContext, Target
from ai_recon.techniques.base import Technique

# Match window.__SOMETHING_CONFIG__ = {...} or similar global config patterns
_WINDOW_CONFIG_RE = re.compile(
    r"window\.__[A-Z_]+(?:CONFIG|SETTINGS|ENV|DATA)__\s*=\s*(\{[\s\S]*?\});",
    re.MULTILINE,
)

# Match key=value or key: value patterns for specific AI endpoint keys
_ENDPOINT_KEYS_RE = re.compile(
    r"""(?:["']?)
        (?P<key>
            apiBase|assistantEndpoint|apiEndpoint|modelEndpoint|
            ragEndpoint|chatEndpoint|completionEndpoint|embeddingEndpoint|
            inferenceEndpoint|baseUrl|base_url
        )
        (?:["']?)\s*[:=]\s*["'](?P<value>(?:https?://[^"']+|/[^"']+))?["']""",
    re.IGNORECASE | re.VERBOSE,
)

# Feature flags detection
_FEATURE_FLAGS_RE = re.compile(
    r"""(?:window\.|const\s+|var\s+|let\s+)
        (?:featureFlags|feature_flags|FEATURE_FLAGS)\s*=\s*(\{[\s\S]*?\});""",
    re.IGNORECASE | re.VERBOSE,
)

# Keys considered "notable" for AI config exposure
_NOTABLE_PATTERNS = ("endpoint", "api", "model", "url", "backend", "rag", "provider", "key")


def _is_same_origin(page_url: str, script_src: str) -> bool:
    """Return True if script_src is same-origin or relative to page_url."""
    if not script_src:
        return False
    parsed_src = urlparse(script_src)
    # Relative path — always same-origin
    if not parsed_src.scheme:
        return True
    parsed_page = urlparse(page_url)
    return parsed_src.netloc == parsed_page.netloc


def _try_json_parse(text: str) -> dict | None:
    """Attempt to parse a string as JSON, return None on failure."""
    # First try stdlib json
    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
    except (json.JSONDecodeError, ValueError):
        pass

    # Try json5 as fallback (handles trailing commas, comments, etc.)
    try:
        import json5  # type: ignore[import]
        result = json5.loads(text)
        if isinstance(result, dict):
            return result
    except Exception:
        pass

    return None


def _extract_notable(config: dict) -> dict:
    """Return keys whose names suggest AI configuration exposure."""
    return {
        k: v
        for k, v in config.items()
        if any(pat in k.lower() for pat in _NOTABLE_PATTERNS)
    }


def _resolve_endpoint(base_url: str, value: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", value)


def _extract_endpoints_from_config(config: dict, base_url: str) -> dict[str, str]:
    endpoints: dict[str, str] = {}
    for key, value in config.items():
        if not isinstance(value, str):
            continue
        if any(pat in key.lower() for pat in _NOTABLE_PATTERNS):
            if value.startswith("/") or value.startswith("http://") or value.startswith("https://"):
                endpoints[key] = _resolve_endpoint(base_url, value)
    return endpoints


class JSConfigExtractTechnique(Technique):
    id: ClassVar[str] = "passive.js_config_extract"
    intrusiveness: ClassVar = "passive"
    produces: ClassVar[set[str]] = {"ai.endpoints", "ai.feature_flags"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        client = self.ctx.http_client
        base_url = target.base_url
        page_url = base_url + "/"
        discovered_endpoints: set[str] = set()
        script_urls: list[str] = []

        # ── Fetch root page ───────────────────────────────────────────────────
        try:
            resp = await client.get(page_url)
        except Exception:
            return findings

        if resp.status_code != 200:
            return findings

        # ── Parse HTML for script tags ────────────────────────────────────────
        try:
            from bs4 import BeautifulSoup  # type: ignore[import]
        except ImportError:
            # Fallback: use regex to extract script src attributes
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
            soup_scripts = script_srcs
        else:
            soup = BeautifulSoup(resp.text, "html.parser")
            soup_scripts = [
                tag.get("src", "") for tag in soup.find_all("script") if tag.get("src")
            ]

        # ── Also scan inline scripts ──────────────────────────────────────────
        inline_texts: list[str] = []
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            for tag in soup.find_all("script"):
                if not tag.get("src") and tag.string:
                    inline_texts.append(tag.string)
        except Exception:
            pass

        all_js_content: list[tuple[str, str]] = []  # (source_label, content)

        # Add inline scripts
        for idx, inline in enumerate(inline_texts):
            all_js_content.append((f"{page_url}#inline-{idx}", inline))

        # ── Fetch external scripts ────────────────────────────────────────────
        for src in soup_scripts:
            if not _is_same_origin(page_url, src):
                continue
            js_url = urljoin(page_url, src)
            script_urls.append(js_url)
            try:
                js_resp = await client.get(js_url)
                if js_resp.status_code == 200:
                    all_js_content.append((js_url, js_resp.text))
            except Exception:
                continue  # Skip on timeout or error

        # ── Scan all JS content ───────────────────────────────────────────────
        for js_url, js_text in all_js_content:
            scan_findings, scan_endpoints = self._scan_js(target, base_url, js_url, js_text)
            findings.extend(scan_findings)
            discovered_endpoints |= scan_endpoints

        if script_urls:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="high",
                    title=f"Client-side scripts discovered: {len(script_urls)}",
                    evidence={"scripts": script_urls},
                )
            )

        if discovered_endpoints:
            try:
                self.ctx.discovered_js_endpoints = sorted(discovered_endpoints)  # type: ignore[attr-defined]
            except Exception:
                pass

        return findings

    def _scan_js(self, target: Target, base_url: str, js_url: str, js_text: str) -> tuple[list[Finding], set[str]]:
        findings: list[Finding] = []
        discovered_endpoints: set[str] = set()

        # ── Window global config patterns ─────────────────────────────────────
        for match in _WINDOW_CONFIG_RE.finditer(js_text):
            raw_obj = match.group(1)
            config = _try_json_parse(raw_obj)
            if config:
                notable = _extract_notable(config)
                resolved_endpoints = _extract_endpoints_from_config(config, base_url)
                discovered_endpoints |= set(resolved_endpoints.values())
                findings.append(
                    self._make_finding(
                        target,
                        severity="medium",
                        confidence="medium",
                        title="Client-side AI config exposed in JavaScript",
                        evidence={
                            "source": js_url,
                            "config_keys": list(config.keys()),
                            "notable": notable,
                            "resolved_endpoints": resolved_endpoints,
                        },
                    )
                )

        # ── Specific endpoint key patterns ────────────────────────────────────
        endpoint_matches: dict[str, str] = {}
        for match in _ENDPOINT_KEYS_RE.finditer(js_text):
            key = match.group("key")
            value = match.group("value")
            if not value:
                continue
            endpoint_matches[key] = _resolve_endpoint(base_url, value)
            discovered_endpoints.add(endpoint_matches[key])

        if endpoint_matches:
            findings.append(
                self._make_finding(
                    target,
                    severity="medium",
                    confidence="medium",
                    title="AI endpoint URLs exposed in JavaScript",
                    evidence={
                        "source": js_url,
                        "endpoints": endpoint_matches,
                    },
                )
            )

        # ── Feature flags ─────────────────────────────────────────────────────
        for match in _FEATURE_FLAGS_RE.finditer(js_text):
            raw_obj = match.group(1)
            flags = _try_json_parse(raw_obj)
            if flags:
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="medium",
                        title="Feature flags exposed",
                        evidence={
                            "source": js_url,
                            "flags": flags,
                        },
                    )
                )

        return findings, discovered_endpoints
