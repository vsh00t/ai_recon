"""OpenAI-compatible API endpoint probe technique."""
from __future__ import annotations

import json
from typing import ClassVar

from ai_recon.core.models import Finding, RunContext, Target
from ai_recon.techniques.base import Technique

_PROBE_MODEL = "gpt-3.5-turbo"
_PROBE_MESSAGES = [{"role": "user", "content": "Hi"}]
_PROBE_MAX_TOKENS = 5


class OpenAICompatProbeTechnique(Technique):
    id: ClassVar[str] = "passive.openai_compat_probe"
    intrusiveness: ClassVar = "low"
    produces: ClassVar[set[str]] = {"protocol.openai_compat", "ai.model_list"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        client = self.ctx.http_client
        base_url = target.base_url

        # ── Step 1: GET /v1/models ────────────────────────────────────────────
        models_url = f"{base_url}/v1/models"
        openai_compatible = False
        model_ids: list[str] = []

        try:
            resp = await client.get(models_url)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except (json.JSONDecodeError, ValueError):
                    data = {}

                if isinstance(data, dict) and data.get("object") == "list":
                    openai_compatible = True
                    raw_data = data.get("data", [])
                    if isinstance(raw_data, list):
                        for entry in raw_data:
                            if isinstance(entry, dict) and entry.get("id"):
                                model_ids.append(entry["id"])

                    findings.append(
                        self._make_finding(
                            target,
                            severity="info",
                            confidence="high",
                            title="OpenAI-compatible /v1/models endpoint",
                            evidence={
                                "url": models_url,
                                "models": model_ids,
                                "total": len(model_ids),
                            },
                        )
                    )
        except Exception:
            pass

        # ── Step 2: POST /v1/chat/completions ────────────────────────────────
        chat_url = f"{base_url}/v1/chat/completions"
        payload = {
            "model": _PROBE_MODEL,
            "messages": _PROBE_MESSAGES,
            "max_tokens": _PROBE_MAX_TOKENS,
        }

        try:
            resp = await client.post(chat_url, json_body=payload)

            if resp.status_code == 200:
                try:
                    chat_data = resp.json()
                except (json.JSONDecodeError, ValueError):
                    chat_data = {}

                if isinstance(chat_data, dict) and "choices" in chat_data:
                    actual_model = chat_data.get("model")
                    usage = chat_data.get("usage")

                    findings.append(
                        self._make_finding(
                            target,
                            severity="info",
                            confidence="high",
                            title="OpenAI-compatible chat endpoint confirmed",
                            evidence={
                                "url": chat_url,
                                "model_returned": actual_model,
                                "usage": usage,
                            },
                        )
                    )

                    # Detect server-side model override
                    if actual_model and actual_model != _PROBE_MODEL:
                        findings.append(
                            self._make_finding(
                                target,
                                severity="low",
                                confidence="high",
                                title="Server overrides requested model",
                                evidence={
                                    "url": chat_url,
                                    "requested": _PROBE_MODEL,
                                    "returned": actual_model,
                                },
                            )
                        )

            elif resp.status_code == 401:
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="high",
                        title="OpenAI-compat endpoint requires auth",
                        evidence={
                            "url": chat_url,
                            "status_code": 401,
                        },
                    )
                )

        except Exception:
            pass

        return findings
