"""Dependency audit — inspects discoverable package manifests on the target
and matches dependencies against the frameworks/vector-dbs/inference-servers
catalogs to surface AI-stack components.

Operates passively: only fetches well-known manifest URLs (requirements.txt,
pyproject.toml, package.json, go.mod) if served, plus extracts <script
type="module"> imports from the homepage.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import ClassVar

import httpx
import yaml

from ai_recon.core.models import Finding, Target
from ai_recon.techniques.base import Technique


_CAT = Path(__file__).parent.parent.parent / "catalogs"

_MANIFEST_PATHS = [
    "/requirements.txt",
    "/pyproject.toml",
    "/package.json",
    "/go.mod",
    "/Pipfile",
    "/poetry.lock",
    "/yarn.lock",
    "/pnpm-lock.yaml",
    "/Gemfile",
    "/composer.json",
]


def _load_catalog(name: str, key: str) -> list[str]:
    p = _CAT / f"{name}.yaml"
    try:
        data = yaml.safe_load(p.read_text()) or {}
    except FileNotFoundError:
        return []
    items = data.get(key, []) or []
    out: list[str] = []
    for it in items:
        if isinstance(it, dict):
            for k in ("id", "name", "package", "module"):
                if k in it:
                    out.append(str(it[k]).lower())
        else:
            out.append(str(it).lower())
    return out


def _extract_packages(text: str) -> set[str]:
    pkgs: set[str] = set()
    # requirements.txt: "package==1.2", "package>=1.2"
    for m in re.finditer(r"^\s*([A-Za-z0-9_.\-]+)\s*[=<>!~]", text, re.MULTILINE):
        pkgs.add(m.group(1).lower())
    # pyproject.toml dependencies
    for m in re.finditer(r'"([A-Za-z0-9_.\-]+)\s*[=<>!~]', text):
        pkgs.add(m.group(1).lower())
    # package.json deps
    for m in re.finditer(r'"([@A-Za-z0-9_./\-]+)"\s*:\s*"\^?[\dx*.]', text):
        pkgs.add(m.group(1).lower())
    # go.mod
    for m in re.finditer(r"^\s*([\w./\-]+)\s+v\d", text, re.MULTILINE):
        pkgs.add(m.group(1).lower())
    return pkgs


class DependencyAudit(Technique):
    id: ClassVar[str] = "passive.dependency_audit"
    intrusiveness: ClassVar[str] = "passive"
    requires: ClassVar[set[str]] = set()
    produces: ClassVar[set[str]] = {"infra.dependencies"}

    async def run(self, target: Target) -> list[Finding]:
        frameworks  = set(_load_catalog("frameworks", "frameworks"))
        vec_dbs     = set(_load_catalog("vector_dbs", "vector_dbs"))
        inf_servers = set(_load_catalog("inference_servers", "inference_servers"))

        findings: list[Finding] = []
        all_pkgs: set[str] = set()
        manifests_found: list[dict] = []

        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:

            async def fetch(path: str) -> tuple[str, int, str]:
                url = f"{target.base_url.rstrip('/')}{path}"
                try:
                    r = await client.get(url)
                    return path, r.status_code, r.text[:50_000]
                except Exception as exc:
                    return path, -1, str(exc)

            results = await asyncio.gather(*(fetch(p) for p in _MANIFEST_PATHS))

        for path, status, body in results:
            if not (200 <= status < 300) or not body:
                continue
            pkgs = _extract_packages(body)
            all_pkgs |= pkgs
            manifests_found.append({"path": path, "package_count": len(pkgs)})

        # Match against catalogs (substring tolerated)
        def _match(pool: set[str]) -> list[str]:
            return sorted({
                fw for fw in pool
                if any(fw in p or p in fw for p in all_pkgs)
            })

        matched_frameworks = _match(frameworks)
        matched_vecdbs     = _match(vec_dbs)
        matched_inference  = _match(inf_servers)

        if matched_frameworks or matched_vecdbs or matched_inference:
            findings.append(
                self._make_finding(
                    target,
                    severity="low",
                    confidence="medium",
                    title="AI stack dependencies discovered",
                    evidence={
                        "frameworks":       matched_frameworks,
                        "vector_dbs":       matched_vecdbs,
                        "inference_servers": matched_inference,
                        "manifests": manifests_found,
                    },
                )
            )

        findings.append(
            self._make_finding(
                target,
                severity="info",
                confidence="medium",
                title=f"Dependency audit: {len(all_pkgs)} packages from "
                      f"{len(manifests_found)} manifest(s)",
                evidence={
                    "package_count": len(all_pkgs),
                    "packages_sample": sorted(all_pkgs)[:50],
                    "manifests_found": manifests_found,
                },
            )
        )
        return findings
