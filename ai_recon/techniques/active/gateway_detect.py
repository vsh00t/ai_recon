"""Gateway detection technique — fingerprints reverse proxies and CDNs from response headers."""
from __future__ import annotations

import re
from typing import ClassVar

import httpx

from ai_recon.core.models import Finding, RunContext, Target
from ai_recon.core.errors import TechniqueAborted
from ai_recon.techniques.base import Technique


def _h(headers: httpx.Headers, name: str) -> str:
    """Case-insensitive header lookup, returns empty string if missing."""
    return headers.get(name, "")


def _has_prefix(headers: httpx.Headers, prefix: str) -> bool:
    """Return True if any header name starts with prefix (case-insensitive)."""
    prefix_lower = prefix.lower()
    return any(k.lower().startswith(prefix_lower) for k in headers.keys())


def _matching_headers(headers: httpx.Headers, prefix: str) -> dict[str, str]:
    prefix_lower = prefix.lower()
    return {k: v for k, v in headers.items() if k.lower().startswith(prefix_lower)}


def _detect_gateways(headers: httpx.Headers) -> list[dict]:
    """Return list of {name, version, evidence_headers} for each detected gateway."""
    detected: list[dict] = []
    server = _h(headers, "server").lower()
    via = _h(headers, "via").lower()

    # Kong
    if re.match(r"kong/", server) or _has_prefix(headers, "x-kong-"):
        version_match = re.search(r"kong/([^\s]+)", server)
        version = version_match.group(1) if version_match else "unknown"
        evidence = {"server": _h(headers, "server")}
        evidence.update(_matching_headers(headers, "x-kong-"))
        rl_headers = {k: v for k, v in headers.items()
                      if re.match(r"ratelimit-", k, re.IGNORECASE)}
        evidence.update(rl_headers)
        detected.append({"name": "Kong", "version": version, "evidence": evidence,
                          "ratelimit_headers": rl_headers})

    # Envoy
    if "envoy" in server or _has_prefix(headers, "x-envoy-"):
        evidence = {"server": _h(headers, "server")}
        evidence.update(_matching_headers(headers, "x-envoy-"))
        upstream_time = _h(headers, "x-envoy-upstream-service-time")
        if upstream_time:
            evidence["x-envoy-upstream-service-time"] = upstream_time
        detected.append({"name": "Envoy", "version": "unknown", "evidence": evidence})

    # nginx
    if re.match(r"nginx/?", server):
        version_match = re.search(r"nginx/([^\s]+)", server)
        version = version_match.group(1) if version_match else "unknown"
        detected.append({"name": "nginx", "version": version,
                          "evidence": {"server": _h(headers, "server")}})

    # Traefik
    xpb = _h(headers, "x-powered-by").lower()
    if "traefik" in xpb or "traefik" in server:
        version_match = re.search(r"traefik/([^\s]+)", server + " " + xpb)
        version = version_match.group(1) if version_match else "unknown"
        detected.append({"name": "Traefik", "version": version,
                          "evidence": {"server": _h(headers, "server"),
                                       "x-powered-by": _h(headers, "x-powered-by")}})

    # Caddy
    if "caddy" in server:
        version_match = re.search(r"caddy/([^\s]+)", server)
        version = version_match.group(1) if version_match else "unknown"
        detected.append({"name": "Caddy", "version": version,
                          "evidence": {"server": _h(headers, "server")}})

    # CloudFront
    if "cloudfront" in via or _has_prefix(headers, "x-amz-cf-"):
        evidence = {"via": _h(headers, "via")}
        evidence.update(_matching_headers(headers, "x-amz-cf-"))
        detected.append({"name": "CloudFront", "version": "unknown", "evidence": evidence})

    # Cloudflare
    if _h(headers, "cf-ray") or "cloudflare" in server:
        evidence = {"server": _h(headers, "server"),
                    "cf-ray": _h(headers, "cf-ray")}
        detected.append({"name": "Cloudflare", "version": "unknown", "evidence": evidence})

    # Fastly
    served_by = _h(headers, "x-served-by")
    cache_hits = _h(headers, "x-cache-hits")
    if served_by or cache_hits:
        detected.append({"name": "Fastly", "version": "unknown",
                          "evidence": {"x-served-by": served_by,
                                       "x-cache-hits": cache_hits}})

    # Azure Front Door
    azure_ref = _h(headers, "x-azure-ref")
    if azure_ref:
        detected.append({"name": "Azure Front Door", "version": "unknown",
                          "evidence": {"x-azure-ref": azure_ref}})

    # AWS ALB
    amzn_trace = _h(headers, "x-amzn-trace-id")
    if amzn_trace:
        detected.append({"name": "AWS ALB", "version": "unknown",
                          "evidence": {"x-amzn-trace-id": amzn_trace}})

    return detected


class GatewayDetect(Technique):
    id: ClassVar[str] = "active.gateway_detect"
    intrusiveness: ClassVar[str] = "passive"
    produces: ClassVar[set[str]] = {"infrastructure.gateway_type"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(f"{target.base_url}/")
                headers = resp.headers
        except Exception as exc:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="low",
                    title="Gateway detection failed — could not reach target",
                    evidence={"error": str(exc)},
                    references=[],
                )
            )
            return findings

        gateways = _detect_gateways(headers)

        if not gateways:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="low",
                    title="No known gateway fingerprints detected",
                    evidence={"server": headers.get("server", ""),
                               "headers_inspected": dict(headers)},
                    references=[],
                )
            )
            return findings

        for gw in gateways:
            name = gw["name"]
            version = gw["version"]
            evidence = gw["evidence"]

            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="high",
                    title=f"Gateway detected: {name} v{version}",
                    evidence={"gateway": name, "version": version, "headers": evidence},
                    references=[],
                )
            )

            # Kong extra finding: rate-limit policy exposed
            if name == "Kong" and gw.get("ratelimit_headers"):
                findings.append(
                    self._make_finding(
                        target,
                        severity="low",
                        confidence="high",
                        title="Kong rate-limit policy exposed",
                        evidence={"ratelimit_headers": gw["ratelimit_headers"]},
                        references=[
                            "https://docs.konghq.com/hub/kong-inc/rate-limiting/",
                        ],
                    )
                )

        return findings
