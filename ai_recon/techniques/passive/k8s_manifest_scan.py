"""Kubernetes manifest scanner — looks for manifests served at common paths
and extracts AI-relevant signals (secrets references, image names, env vars).
"""

from __future__ import annotations

import asyncio
import re
from typing import ClassVar

import httpx
import yaml

from ai_recon.core.models import Finding, Target
from ai_recon.techniques.base import Technique


_PATHS: list[str] = [
    "/k8s.yaml",
    "/kubernetes.yaml",
    "/deployment.yaml",
    "/manifests/deployment.yaml",
    "/manifests/all.yaml",
    "/helm/values.yaml",
    "/charts/values.yaml",
    "/.kube/config",
]

_AI_IMAGE_RE = re.compile(
    r"(?i)\b(?:ollama|vllm|tgi|llama|huggingface|openai|chroma|qdrant|"
    r"weaviate|milvus|pinecone|langchain|llama-index|llama_index)\b"
)


def _scan_manifest(text: str) -> dict:
    docs: list[dict] = []
    try:
        for d in yaml.safe_load_all(text):
            if isinstance(d, dict):
                docs.append(d)
    except Exception:
        return {"parsed": False, "raw_preview": text[:300]}

    images: list[str] = []
    secret_refs: list[str] = []
    env_names: list[str] = []
    for d in docs:
        for ref in _walk_for_keys(d, "image"):
            images.append(str(ref))
        for ref in _walk_for_keys(d, "secretKeyRef"):
            if isinstance(ref, dict):
                secret_refs.append(f"{ref.get('name', '?')}:{ref.get('key', '?')}")
        for ref in _walk_for_keys(d, "name"):
            if isinstance(ref, str) and re.match(r"^[A-Z_][A-Z0-9_]+$", ref):
                env_names.append(ref)

    return {
        "parsed": True,
        "doc_count": len(docs),
        "images": images,
        "ai_relevant_images": [i for i in images if _AI_IMAGE_RE.search(i)],
        "secret_refs": secret_refs,
        "env_names": sorted(set(env_names))[:50],
    }


def _walk_for_keys(obj, key: str):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                yield v
            yield from _walk_for_keys(v, key)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_for_keys(item, key)


class K8sManifestScan(Technique):
    id: ClassVar[str] = "passive.k8s_manifest_scan"
    intrusiveness: ClassVar[str] = "passive"
    produces: ClassVar[set[str]] = {"infra.k8s_manifests"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        found: list[dict] = []

        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:

            async def fetch(p: str) -> tuple[str, int, str]:
                url = f"{target.base_url.rstrip('/')}{p}"
                try:
                    r = await client.get(url)
                    return p, r.status_code, r.text[:50_000]
                except Exception:
                    return p, -1, ""

            results = await asyncio.gather(*(fetch(p) for p in _PATHS))

        for path, status, body in results:
            if not (200 <= status < 300) or "<html" in body[:200].lower():
                continue
            scan = _scan_manifest(body)
            entry = {"path": path, "status": status, **scan}
            found.append(entry)
            sev = "medium" if scan.get("ai_relevant_images") else "low"
            findings.append(
                self._make_finding(
                    target, severity=sev, confidence="medium",
                    title=f"K8s manifest exposed: {path}",
                    evidence=entry,
                )
            )

        findings.append(
            self._make_finding(
                target, severity="info", confidence="high",
                title=f"K8s scan: {len(found)} manifest(s) reachable",
                evidence={"found_count": len(found), "probed": len(_PATHS)},
            )
        )
        return findings
