"""Honeypot detector — scans previously-collected findings for canary signals.

Loads ``catalogs/honeypot_signals.yaml`` and inspects evidence dictionaries
of all prior findings on the run for honeypot / canary patterns
(substrings, AWS example keys, RFC-reserved domains/IPs, default passwords).

Emits one ``Finding`` per detected canary, plus a summary finding.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, ClassVar

import yaml

from ai_recon.core.models import Finding, Target
from ai_recon.techniques.base import Technique

_CATALOG = Path(__file__).parent.parent.parent / "catalogs" / "honeypot_signals.yaml"


def _load_catalog() -> dict:
    try:
        return yaml.safe_load(_CATALOG.read_text()) or {}
    except FileNotFoundError:
        return {}


def _flatten(obj: Any) -> str:
    """Stringify any evidence object so we can pattern-match against it."""
    try:
        return json.dumps(obj, default=str)
    except Exception:
        return str(obj)


def _scan_substrings(text: str, catalog: dict) -> list[dict]:
    hits: list[dict] = []
    for entry in catalog.get("substring_patterns", []) or []:
        val = entry["value"]
        cs = entry.get("case_sensitive", False)
        haystack = text if cs else text.lower()
        needle = val if cs else val.lower()
        if needle in haystack:
            hits.append({
                "kind": "substring",
                "value": val,
                "severity": entry.get("severity", "medium"),
                "description": entry.get("description", ""),
            })
    return hits


def _scan_aws(text: str, catalog: dict) -> list[dict]:
    hits: list[dict] = []
    for entry in catalog.get("aws_canary_patterns", []) or []:
        if entry["value"] in text:
            hits.append({
                "kind": "aws_canary",
                "value": entry["value"],
                "severity": entry.get("severity", "critical"),
                "description": entry.get("description", ""),
                "reference": entry.get("reference"),
            })
    return hits


def _scan_passwords(text: str, catalog: dict) -> list[dict]:
    hits: list[dict] = []
    for entry in catalog.get("password_patterns", []) or []:
        try:
            pat = re.compile(entry["regex"])
        except re.error:
            continue
        for m in pat.finditer(text):
            hits.append({
                "kind": "password_pattern",
                "value": m.group(0),
                "severity": entry.get("severity", "medium"),
                "description": entry.get("description", ""),
                "pattern_name": entry.get("name"),
            })
    return hits


def _scan_domains(text: str, catalog: dict) -> list[dict]:
    hits: list[dict] = []
    cfg = catalog.get("domain_canary", {}) or {}
    for tld in cfg.get("reserved_tlds", []) or []:
        for m in re.finditer(rf"[\w.-]+{re.escape(tld)}\b", text):
            hits.append({
                "kind": "reserved_tld",
                "value": m.group(0),
                "severity": cfg.get("severity", "low"),
                "description": f"Reserved TLD: {tld}",
            })
    for dom in cfg.get("reserved_domains", []) or []:
        if dom in text:
            hits.append({
                "kind": "reserved_domain",
                "value": dom,
                "severity": cfg.get("severity", "low"),
                "description": "Reserved/example domain",
            })
    return hits


def _scan_ips(text: str, catalog: dict) -> list[dict]:
    hits: list[dict] = []
    cfg = catalog.get("ip_canary", {}) or {}
    nets: list[tuple[str, str]] = []  # (cidr, label)
    for group_key in ("test_networks", "loopback", "link_local"):
        for entry in cfg.get(group_key, []) or []:
            nets.append((entry["cidr"], entry.get("name", group_key)))

    for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        ip = m.group(0)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        for cidr, label in nets:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    hits.append({
                        "kind": "reserved_ip",
                        "value": ip,
                        "severity": cfg.get("severity", "low"),
                        "description": f"{label} ({cidr})",
                    })
                    break
            except ValueError:
                continue
    return hits


class HoneypotDetect(Technique):
    id: ClassVar[str] = "evasion.honeypot_detect"
    intrusiveness: ClassVar[str] = "passive"
    requires: ClassVar[set[str]] = set()
    produces: ClassVar[set[str]] = {"honeypot.signals"}

    async def run(self, target: Target) -> list[Finding]:
        catalog = _load_catalog()
        prior_findings: list[Finding] = list(getattr(self.ctx, "findings", []) or [])
        # Also scan target metadata directly.
        haystacks: list[tuple[str, str]] = [
            (f"target:{target.id}", _flatten({"host": target.host,
                                              "port": target.port,
                                              "notes": target.notes}))
        ]
        for f in prior_findings:
            if f.target_id != target.id:
                continue
            haystacks.append((f"finding:{f.id}", _flatten(f.evidence)))

        findings: list[Finding] = []
        all_hits: list[dict] = []

        for source, text in haystacks:
            hits: list[dict] = []
            hits += _scan_substrings(text, catalog)
            hits += _scan_aws(text, catalog)
            hits += _scan_passwords(text, catalog)
            hits += _scan_domains(text, catalog)
            hits += _scan_ips(text, catalog)
            for h in hits:
                h["source"] = source
                all_hits.append(h)
                findings.append(
                    self._make_finding(
                        target,
                        severity=h["severity"],
                        confidence="high",
                        title=f"Honeypot/canary signal: {h['kind']} ({h['value'][:32]}…)",
                        evidence=h,
                        references=[h.get("reference")] if h.get("reference") else [],
                    )
                )

        # Aggregate
        if all_hits:
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="high",
                    title=f"Honeypot scan: {len(all_hits)} signals across {len(haystacks)} sources",
                    evidence={
                        "total_hits": len(all_hits),
                        "by_kind": {
                            k: sum(1 for h in all_hits if h["kind"] == k)
                            for k in {h["kind"] for h in all_hits}
                        },
                    },
                )
            )
        return findings
