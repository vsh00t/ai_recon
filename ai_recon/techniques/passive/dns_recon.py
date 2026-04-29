"""Passive DNS reconnaissance technique."""
from __future__ import annotations

import ipaddress
from typing import ClassVar

import dns.asyncresolver
import dns.rdatatype
import dns.resolver

from ai_recon.core.models import Finding, RunContext, Target
from ai_recon.techniques.base import Technique

# Cloud provider CNAME patterns: (substring_pattern, canonical_name)
_CLOUD_CNAME_PATTERNS: list[tuple[str, str]] = [
    (".elb.amazonaws.com", "AWS ELB"),
    (".cloudfront.net", "AWS CloudFront"),
    (".s3.amazonaws.com", "AWS S3"),
    (".azurefd.net", "Azure Front Door"),
    (".azurewebsites.net", "Azure App Service"),
    (".trafficmanager.net", "Azure Traffic Manager"),
    (".fastly.net", "Fastly CDN"),
    (".vercel.app", "Vercel"),
    (".onrender.com", "Render"),
    (".netlify.app", "Netlify"),
    (".pages.dev", "Cloudflare Pages"),
    (".workers.dev", "Cloudflare Workers"),
    (".herokuapp.com", "Heroku"),
    (".fly.dev", "Fly.io"),
    (".railway.app", "Railway"),
]

# TXT record classification patterns
_TXT_PATTERNS: list[tuple[str, str]] = [
    ("v=spf1", "SPF"),
    ("v=dkim1", "DKIM"),
    ("v=dmarc1", "DMARC"),
    ("google-site-verification=", "Google-site-verification"),
    ("ms-", "MS-verify"),
    ("docusign=", "DocuSign-verify"),
    ("apple-domain-verification=", "Apple-domain-verify"),
]

# AI-related subdomain prefixes to brute-force
_AI_SUBDOMAINS: list[str] = [
    "api",
    "chat",
    "llm",
    "ai",
    "model",
    "kb",
    "rag",
    "assistant",
    "bot",
    "agent",
    "embed",
    "vector",
    "ml",
    "inference",
    "search",
]


def _is_private_ip(ip_str: str) -> bool:
    """Return True if the given IP string is an RFC 1918 private address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private
    except ValueError:
        return False


def _extract_domain(host: str) -> str:
    """Strip subdomains to get registrable domain (best-effort, no PSL)."""
    parts = host.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


class DNSReconTechnique(Technique):
    id: ClassVar[str] = "passive.dns_recon"
    intrusiveness: ClassVar = "passive"
    produces: ClassVar[set[str]] = {"infrastructure.dns", "infrastructure.cloud_provider"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        host = target.host
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        # ── A / AAAA records ──────────────────────────────────────────────────
        a_ips: list[str] = []
        aaaa_ips: list[str] = []

        for rdtype, bucket in [("A", a_ips), ("AAAA", aaaa_ips)]:
            try:
                answer = await resolver.resolve(host, rdtype)
                for rr in answer:
                    bucket.append(str(rr))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
                pass

        if a_ips:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="high",
                    title="DNS A records",
                    evidence={"ips": a_ips, "host": host},
                )
            )
            # Private IP check
            private_ips = [ip for ip in a_ips if _is_private_ip(ip)]
            if private_ips:
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="high",
                        title="Target resolves to private IP — internal deployment",
                        evidence={"private_ips": private_ips, "host": host},
                    )
                )

        if aaaa_ips:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="high",
                    title="DNS AAAA records",
                    evidence={"ips": aaaa_ips, "host": host},
                )
            )

        # ── CNAME records ─────────────────────────────────────────────────────
        try:
            cname_answer = await resolver.resolve(host, "CNAME")
            for rr in cname_answer:
                cname_target = str(rr.target).rstrip(".")
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="high",
                        title=f"DNS CNAME: {host} → {cname_target}",
                        evidence={"cname": cname_target, "host": host},
                    )
                )
                # Check for cloud provider
                for pattern, provider in _CLOUD_CNAME_PATTERNS:
                    if cname_target.lower().endswith(pattern):
                        findings.append(
                            self._make_finding(
                                target,
                                severity="medium",
                                confidence="high",
                                title=f"Cloud provider revealed via CNAME: {provider}",
                                evidence={
                                    "cname": cname_target,
                                    "provider": provider,
                                    "host": host,
                                },
                            )
                        )
                        break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
            pass

        # ── MX records ────────────────────────────────────────────────────────
        try:
            mx_answer = await resolver.resolve(host, "MX")
            mx_records = [str(rr.exchange).rstrip(".") for rr in mx_answer]
            if mx_records:
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="high",
                        title="DNS MX records",
                        evidence={"mx": mx_records, "host": host},
                    )
                )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
            pass

        # ── TXT records ───────────────────────────────────────────────────────
        try:
            txt_answer = await resolver.resolve(host, "TXT")
            for rr in txt_answer:
                txt_value = "".join(part.decode("utf-8", errors="replace") for part in rr.strings)
                for pattern, label in _TXT_PATTERNS:
                    if txt_value.lower().startswith(pattern.lower()):
                        findings.append(
                            self._make_finding(
                                target,
                                severity="info",
                                confidence="high",
                                title=f"DNS TXT: {label} record found",
                                evidence={"txt": txt_value[:200], "label": label, "host": host},
                            )
                        )
                        break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
            pass

        # ── NS records ────────────────────────────────────────────────────────
        domain = _extract_domain(host)
        try:
            ns_answer = await resolver.resolve(domain, "NS")
            ns_records = [str(rr.target).rstrip(".") for rr in ns_answer]
            if ns_records:
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="high",
                        title="DNS NS records",
                        evidence={"ns": ns_records, "domain": domain},
                    )
                )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
            pass

        # ── AI-related subdomain brute-force ──────────────────────────────────
        for prefix in _AI_SUBDOMAINS:
            subdomain = f"{prefix}.{domain}"
            if subdomain == host:
                continue  # skip if it's the target itself
            try:
                sub_answer = await resolver.resolve(subdomain, "A")
                sub_ips = [str(rr) for rr in sub_answer]
                if sub_ips:
                    findings.append(
                        self._make_finding(
                            target,
                            severity="medium",
                            confidence="high",
                            title=f"AI-related subdomain discovered: {subdomain}",
                            evidence={"subdomain": subdomain, "ips": sub_ips},
                        )
                    )
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
                pass

        return findings
