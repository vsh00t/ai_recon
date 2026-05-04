"""Probe AI-related endpoints discovered from client-side JavaScript config."""
from __future__ import annotations

from typing import ClassVar
from urllib.parse import urlparse

from ai_recon.core.models import Finding, Target
from ai_recon.techniques.base import Technique


def _path_hint(url: str) -> str:
    return urlparse(url).path.lower()


def _interesting_metadata(data: dict) -> dict:
    interesting: dict = {}
    for key in ("provider", "model", "metadata", "usage", "latency_ms", "created_at", "done_reason"):
        if key in data:
            interesting[key] = data[key]
    metadata = data.get("metadata")
    if isinstance(metadata, dict):
        for key in ("provider", "model", "latency_ms", "created_at", "prompt_eval_count", "eval_count"):
            if key in metadata:
                interesting[f"metadata.{key}"] = metadata[key]
    return interesting


class ClientJsEndpointProbe(Technique):
    id: ClassVar[str] = "active.client_js_endpoint_probe"
    intrusiveness: ClassVar[str] = "low"
    requires: ClassVar[set[str]] = {"ai.endpoints"}
    produces: ClassVar[set[str]] = {"ai.endpoint_probe"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        client = self.ctx.http_client
        endpoints = list(getattr(self.ctx, "discovered_js_endpoints", []) or [])

        if not endpoints:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="high",
                    title="Client JS endpoint probe skipped: no endpoints discovered",
                    evidence={"discovered_js_endpoints": []},
                )
            )
            return findings

        findings.append(
            self._make_finding(
                target,
                severity="info",
                confidence="high",
                title=f"Client JS endpoint probe: {len(endpoints)} endpoint(s) queued",
                evidence={"discovered_js_endpoints": endpoints},
            )
        )

        for endpoint in endpoints:
            path = _path_hint(endpoint)

            try:
                get_resp = await client.get(endpoint)
                if get_resp.status_code not in (404, 410):
                    content_type = get_resp.headers.get("content-type", "")
                    body_sample = get_resp.text[:300]
                    title = "Discovered client-side endpoint responded"
                    severity = "info"
                    evidence = {
                        "url": endpoint,
                        "status_code": get_resp.status_code,
                        "content_type": content_type,
                        "body_sample": body_sample,
                    }
                    try:
                        data = get_resp.json()
                    except Exception:
                        data = None
                    if isinstance(data, dict):
                        evidence["interesting"] = _interesting_metadata(data)
                        if evidence["interesting"]:
                            title = "Client-discovered endpoint exposed AI backend metadata"
                            severity = "medium"
                    findings.append(
                        self._make_finding(
                            target,
                            severity=severity,
                            confidence="high",
                            title=title,
                            evidence=evidence,
                        )
                    )
            except Exception:
                pass

            if any(token in path for token in ("assistant", "chat", "completion", "generate", "inference")):
                payloads: list[dict] = [{"message": "Hello"}]
                if "chat/completions" in path:
                    payloads.insert(0, {
                        "model": "gpt-3.5-turbo",
                        "messages": [{"role": "user", "content": "Hello"}],
                        "max_tokens": 8,
                    })

                for payload in payloads:
                    try:
                        post_resp = await client.post(endpoint, json_body=payload)
                    except Exception:
                        continue

                    if post_resp.status_code == 401:
                        findings.append(
                            self._make_finding(
                                target,
                                severity="medium",
                                confidence="high",
                                title="Protected AI endpoint discovered via client-side config",
                                evidence={
                                    "url": endpoint,
                                    "status_code": 401,
                                    "payload_shape": sorted(payload.keys()),
                                },
                            )
                        )
                        break

                    if post_resp.status_code == 405:
                        findings.append(
                            self._make_finding(
                                target,
                                severity="info",
                                confidence="high",
                                title="Client-discovered AI endpoint exists but method is not allowed",
                                evidence={
                                    "url": endpoint,
                                    "status_code": 405,
                                    "payload_shape": sorted(payload.keys()),
                                },
                            )
                        )
                        break

                    if post_resp.status_code == 200:
                        try:
                            data = post_resp.json()
                        except Exception:
                            data = {}
                        interesting = _interesting_metadata(data) if isinstance(data, dict) else {}
                        findings.append(
                            self._make_finding(
                                target,
                                severity="medium" if interesting else "info",
                                confidence="high",
                                title="Client-discovered AI endpoint responded to probe",
                                evidence={
                                    "url": endpoint,
                                    "status_code": 200,
                                    "payload_shape": sorted(payload.keys()),
                                    "interesting": interesting,
                                    "body_sample": post_resp.text[:400],
                                },
                            )
                        )
                        break

        return findings