"""Google Gemini API adapter."""
from __future__ import annotations

import json
from typing import AsyncIterator, Literal

import httpx

from ai_recon.core.errors import ProtocolMismatch
from ai_recon.core.models import ChatResponse, Delta, Message, Usage

_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
_EMBED_MODEL = "text-embedding-004"


class GeminiAdapter:
    """Adapter for the Google Gemini (generativelanguage) API."""

    def __init__(
        self,
        api_key_ref: str,
        model: str = "gemini-2.0-flash",
        secrets: object | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._api_key_ref = api_key_ref
        self._model = model
        self._secrets = secrets
        self._own_client = http_client is None
        self._client = http_client or httpx.AsyncClient(timeout=120.0)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_api_key(self) -> str:
        if self._secrets is not None:
            try:
                key = getattr(self._secrets, "resolve", lambda r: None)(self._api_key_ref)
                if key:
                    return key
            except Exception:
                pass
        return self._api_key_ref

    def _messages_to_contents(self, messages: list[Message]) -> tuple[str | None, list[dict]]:
        """Convert messages to Gemini contents format, extracting system prompt."""
        system: str | None = None
        contents: list[dict] = []
        for m in messages:
            if m.role == "system":
                system = (system + "\n" + m.content) if system else m.content
                continue
            # Gemini uses "user" and "model" roles
            gemini_role = "model" if m.role == "assistant" else "user"
            contents.append({
                "role": gemini_role,
                "parts": [{"text": m.content}],
            })
        return system, contents

    def _build_generate_payload(self, messages: list[Message], **opts) -> dict:
        system, contents = self._messages_to_contents(messages)
        payload: dict = {"contents": contents}
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}
        generation_config: dict = {}
        if "max_tokens" in opts:
            generation_config["maxOutputTokens"] = opts.pop("max_tokens")
        if "temperature" in opts:
            generation_config["temperature"] = opts.pop("temperature")
        if generation_config:
            payload["generationConfig"] = generation_config
        payload.update(opts)
        return payload

    async def _close_own_client(self) -> None:
        if self._own_client:
            await self._client.aclose()

    # ------------------------------------------------------------------
    # Protocol methods
    # ------------------------------------------------------------------

    async def chat(self, messages: list[Message], **opts) -> ChatResponse:
        api_key = self._resolve_api_key()
        url = f"{_BASE_URL}/models/{self._model}:generateContent"
        payload = self._build_generate_payload(messages, **opts)

        try:
            resp = await self._client.post(url, json=payload, params={"key": api_key})
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProtocolMismatch(
                adapter="GeminiAdapter",
                detail=f"HTTP {exc.response.status_code}: {exc.response.text[:400]}",
            ) from exc
        except httpx.RequestError as exc:
            raise ProtocolMismatch(
                adapter="GeminiAdapter", detail=f"Request failed: {exc}"
            ) from exc

        try:
            data = resp.json()
        except Exception as exc:
            raise ProtocolMismatch(
                adapter="GeminiAdapter", detail=f"Non-JSON response: {resp.text[:200]}"
            ) from exc

        candidates = data.get("candidates", [])
        if not candidates:
            raise ProtocolMismatch(
                adapter="GeminiAdapter",
                detail=f"Response missing 'candidates': {list(data.keys())}",
            )

        content = candidates[0].get("content", {})
        parts = content.get("parts", [])
        if not parts:
            raise ProtocolMismatch(
                adapter="GeminiAdapter",
                detail="Candidate content has no 'parts'",
            )

        text = parts[0].get("text", "")
        finish_reason = candidates[0].get("finishReason")

        raw_usage = data.get("usageMetadata", {})
        usage = Usage(
            prompt_tokens=raw_usage.get("promptTokenCount", 0),
            completion_tokens=raw_usage.get("candidatesTokenCount", 0),
            total_tokens=raw_usage.get("totalTokenCount", 0),
        )

        return ChatResponse(
            text=text,
            model=self._model,
            finish_reason=finish_reason,
            usage=usage,
            raw=data,
        )

    async def stream_chat(self, messages: list[Message], **opts) -> AsyncIterator[Delta]:
        api_key = self._resolve_api_key()
        url = f"{_BASE_URL}/models/{self._model}:streamGenerateContent"
        payload = self._build_generate_payload(messages, **opts)

        async with self._client.stream(
            "POST",
            url,
            json=payload,
            params={"key": api_key, "alt": "sse"},
            timeout=120.0,
        ) as resp:
            if resp.status_code >= 400:
                body = await resp.aread()
                raise ProtocolMismatch(
                    adapter="GeminiAdapter",
                    detail=f"HTTP {resp.status_code}: {body[:400].decode(errors='replace')}",
                )
            async for line in resp.aiter_lines():
                line = line.strip()
                if not line or not line.startswith("data:"):
                    continue
                data_str = line[len("data:"):].strip()
                if data_str == "[DONE]":
                    break
                try:
                    chunk = json.loads(data_str)
                except json.JSONDecodeError:
                    continue

                candidates = chunk.get("candidates", [])
                if not candidates:
                    continue
                content = candidates[0].get("content", {})
                parts = content.get("parts", [])
                text_piece = parts[0].get("text", "") if parts else ""
                finish_reason = candidates[0].get("finishReason")
                yield Delta(text=text_piece, finish_reason=finish_reason, raw=chunk)

    async def embed(self, texts: list[str]) -> list[list[float]]:
        api_key = self._resolve_api_key()
        url = f"{_BASE_URL}/models/{_EMBED_MODEL}:embedContent"
        results: list[list[float]] = []

        for text in texts:
            payload = {"content": {"parts": [{"text": text}]}}
            try:
                resp = await self._client.post(url, json=payload, params={"key": api_key})
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise ProtocolMismatch(
                    adapter="GeminiAdapter",
                    detail=f"Embed HTTP {exc.response.status_code}: {exc.response.text[:400]}",
                ) from exc
            except httpx.RequestError as exc:
                raise ProtocolMismatch(
                    adapter="GeminiAdapter", detail=f"Embed request failed: {exc}"
                ) from exc

            try:
                data = resp.json()
            except Exception as exc:
                raise ProtocolMismatch(
                    adapter="GeminiAdapter", detail=f"Non-JSON embed response: {resp.text[:200]}"
                ) from exc

            embedding = data.get("embedding", {}).get("values")
            if embedding is None:
                raise ProtocolMismatch(
                    adapter="GeminiAdapter",
                    detail=f"Embed response missing 'embedding.values': {list(data.keys())}",
                )
            results.append(embedding)

        return results

    def supports(self, capability: Literal["streaming", "tools", "vision", "logprobs"]) -> bool:
        if capability == "streaming":
            return True
        if capability == "tools":
            return True
        if capability == "vision":
            return True
        if capability == "logprobs":
            return False
        return False

    def model_id(self) -> str | None:
        return self._model

    # ------------------------------------------------------------------
    # Async context manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "GeminiAdapter":
        return self

    async def __aexit__(self, *_) -> None:
        await self._close_own_client()
