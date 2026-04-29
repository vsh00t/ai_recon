"""Docker label inspection.

Some web servers expose container metadata at well-known paths
(``/etc.docker``, ``/proc/self/environ`` via reverse-proxy misconfig,
or simply via leaked OCI labels in HTTP headers like ``Docker-Image-*``).
This technique queries those non-destructively and parses any labels
discovered.
"""

from __future__ import annotations

from typing import ClassVar

import httpx

from ai_recon.core.models import Finding, Target
from ai_recon.techniques.base import Technique


_LABEL_HEADERS = [
    "docker-image",
    "docker-image-digest",
    "x-docker-image",
    "x-image",
    "x-build-image",
    "x-build-id",
    "x-source-revision",
    "x-git-commit",
    "x-version",
]


class DockerLabelInspect(Technique):
    id: ClassVar[str] = "passive.docker_label_inspect"
    intrusiveness: ClassVar[str] = "passive"
    produces: ClassVar[set[str]] = {"infra.container_metadata"}

    async def run(self, target: Target) -> list[Finding]:
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
            try:
                r = await client.get(target.base_url)
            except Exception as exc:
                return [self._make_finding(
                    target, severity="info", confidence="low",
                    title="Docker label inspect failed",
                    evidence={"error": str(exc)},
                )]
        labels = {h: r.headers[h] for h in r.headers if h.lower() in _LABEL_HEADERS}
        sev = "low" if labels else "info"
        return [
            self._make_finding(
                target, severity=sev, confidence="high",
                title=f"Container labels via headers: {len(labels)} found",
                evidence={"labels": labels,
                          "all_headers_sample": dict(list(r.headers.items())[:25])},
            )
        ]
