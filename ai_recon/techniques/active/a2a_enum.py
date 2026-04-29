"""A2A enumeration technique — discovers agent cards and OpenAI plugin manifests."""
from __future__ import annotations

from typing import ClassVar

import httpx

from ai_recon.core.models import Finding, RunContext, Target
from ai_recon.core.errors import TechniqueAborted
from ai_recon.techniques.base import Technique


def _parse_auth_schemes(auth: dict | list | None) -> list[str]:
    """Normalise authentication schemes from agent card format."""
    if auth is None:
        return []
    if isinstance(auth, list):
        return [str(s) for s in auth]
    if isinstance(auth, dict):
        schemes = auth.get("schemes") or auth.get("type") or auth.get("kind")
        if isinstance(schemes, list):
            return [str(s) for s in schemes]
        if isinstance(schemes, str):
            return [schemes]
    return []


class A2AEnum(Technique):
    id: ClassVar[str] = "active.a2a_enum"
    intrusiveness: ClassVar[str] = "passive"
    produces: ClassVar[set[str]] = {"a2a.skills", "a2a.auth"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            # ── A2A Agent Card ────────────────────────────────────────────────
            agent_card_url = f"{target.base_url.rstrip('/')}/.well-known/agent.json"
            try:
                resp = await client.get(agent_card_url)
                if resp.status_code == 200:
                    try:
                        card = resp.json()
                    except Exception:
                        card = None

                    if card and isinstance(card, dict):
                        name        = card.get("name", "unknown")
                        description = card.get("description", "")
                        url         = card.get("url", "")
                        version     = card.get("version", "unknown")
                        capabilities = card.get("capabilities", {})
                        skills      = card.get("skills", [])
                        auth        = card.get("authentication", card.get("auth", {}))

                        findings.append(
                            self._make_finding(
                                target,
                                severity="info",
                                confidence="high",
                                title=f"A2A Agent Card discovered: {name}",
                                evidence={
                                    "agent_card": card,
                                    "name": name,
                                    "description": description,
                                    "url": url,
                                    "version": version,
                                    "capabilities": capabilities,
                                    "skill_count": len(skills),
                                },
                                references=[
                                    "https://google.github.io/A2A/",
                                ],
                            )
                        )

                        # Per-skill findings
                        for skill in skills:
                            skill_name  = skill.get("name") or skill.get("id", "unknown")
                            skill_id    = skill.get("id", "")
                            input_modes  = skill.get("inputModes",  skill.get("input_modes",  []))
                            output_modes = skill.get("outputModes", skill.get("output_modes", []))
                            findings.append(
                                self._make_finding(
                                    target,
                                    severity="info",
                                    confidence="high",
                                    title=f"A2A skill: {skill_name}",
                                    evidence={
                                        "skill": skill,
                                        "skill_id": skill_id,
                                        "skill_name": skill_name,
                                        "input_modes": input_modes,
                                        "output_modes": output_modes,
                                        "description": skill.get("description", ""),
                                    },
                                    references=[],
                                )
                            )

                        # Auth check
                        schemes = _parse_auth_schemes(auth)
                        if not schemes or set(schemes) <= {"none", "", "anonymous"}:
                            findings.append(
                                self._make_finding(
                                    target,
                                    severity="high",
                                    confidence="medium",
                                    title="A2A agent accessible without authentication",
                                    evidence={
                                        "authentication": auth,
                                        "schemes": schemes,
                                        "agent_name": name,
                                    },
                                    references=[
                                        "https://google.github.io/A2A/",
                                        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                                    ],
                                )
                            )
            except httpx.HTTPStatusError:
                pass
            except Exception as exc:
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="low",
                        title="A2A agent card probe failed",
                        evidence={"error": str(exc), "url": agent_card_url},
                        references=[],
                    )
                )

            # ── OpenAI plugin manifest ────────────────────────────────────────
            plugin_url = f"{target.base_url.rstrip('/')}/.well-known/ai-plugin.json"
            try:
                plugin_resp = await client.get(plugin_url)
                if plugin_resp.status_code == 200:
                    try:
                        manifest = plugin_resp.json()
                    except Exception:
                        manifest = None

                    if manifest and isinstance(manifest, dict):
                        plugin_name = manifest.get("name_for_human") or manifest.get("name", "unknown")
                        plugin_desc = manifest.get("description_for_human", "")
                        api_spec    = manifest.get("api", {})
                        auth_obj    = manifest.get("auth", {})
                        auth_type   = auth_obj.get("type", "none") if isinstance(auth_obj, dict) else "none"

                        findings.append(
                            self._make_finding(
                                target,
                                severity="info",
                                confidence="high",
                                title=f"OpenAI plugin manifest discovered: {plugin_name}",
                                evidence={
                                    "manifest": manifest,
                                    "plugin_name": plugin_name,
                                    "description": plugin_desc,
                                    "api_spec_url": api_spec.get("url") if isinstance(api_spec, dict) else None,
                                    "auth_type": auth_type,
                                    "logo_url": manifest.get("logo_url"),
                                    "contact_email": manifest.get("contact_email"),
                                },
                                references=[
                                    "https://platform.openai.com/docs/plugins/introduction",
                                ],
                            )
                        )

                        if auth_type in ("none", ""):
                            findings.append(
                                self._make_finding(
                                    target,
                                    severity="high",
                                    confidence="medium",
                                    title=f"OpenAI plugin '{plugin_name}' has no authentication",
                                    evidence={"auth": auth_obj, "plugin_name": plugin_name},
                                    references=[],
                                )
                            )
            except httpx.HTTPStatusError:
                pass
            except Exception as exc:
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="low",
                        title="OpenAI plugin manifest probe failed",
                        evidence={"error": str(exc), "url": plugin_url},
                        references=[],
                    )
                )

        # If neither manifest found
        if not any(
            "Agent Card" in f.title or "plugin manifest" in f.title or "A2A skill" in f.title
            for f in findings
            if "failed" not in f.title.lower() and "not detected" not in f.title.lower()
        ):
            findings.append(
                self._make_finding(
                    target,
                    severity="info",
                    confidence="high",
                    title="No A2A agent card or plugin manifest found",
                    evidence={
                        "checked_urls": [agent_card_url, plugin_url],
                    },
                    references=[],
                )
            )

        return findings
