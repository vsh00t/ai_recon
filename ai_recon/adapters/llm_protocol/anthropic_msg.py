"""Anthropic Messages API adapter."""
from __future__ import annotations

import json
from typing import AsyncIterator, Literal

import httpx

from ai_recon.core.errors import ProtocolMismatch
from ai_recon.core.models import ChatResponse, Delta, Message, Usage

_BASE_URL = "https://api.anthropic.com"
_ANTHROPIC_VERSION = "2023-06-01"
_DEFAULT_MAX_TOKENS = 4096


class AnthropicAdapter:
    """Adapter for the Anthropic Messages API."""

    def __init__(
        self,
        api_key_ref: str,
        model: str = "claude-opus-4-7",
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
        # Treat the ref as a literal key if resolution fails
        return self._api_key_ref

    def _build_headers(self) -> dict[str, str]:
        return {
            "x-api-key": self._resolve_api_key(),
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

    def _split_messages(self, messages: list[Message]) -> tuple[str | None, list[dict]]:
        """Separate the system message and convert the rest to Anthropic format."""
        system: str | None = None
        converted: list[dict] = []
        for m in messages:
            if m.role == "system":
                system = (system + "\n" + m.content) if system else m.content
            else:
                entry: dict = {"role": m.role, "content": m.content}
                converted.append(entry)
        return system, converted

    async def _close_own_client(self) -> None:
        if self._own_client:
            await self._client.aclose()

    # ------------------------------------------------------------------
    # Protocol methods
    # ------------------------------------------------------------------

    async def chat(self, messages: list[Message], **opts) -> ChatResponse:
        system, converted = self._split_messages(messages)
        payload: dict = {
            "model": self._model,
            "max_tokens": opts.pop("max_tokens", _DEFAULT_MAX_TOKENS),
            "messages": converted,
            **opts,
        }
        if system:
            payload["system"] = system

        try:
            resp = await self._client.post(
                f"{_BASE_URL}/v1/messages",
                json=payload,
                headers=self._build_headers(),
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProtocolMismatch(
                adapter="AnthropicAdapter",
                detail=f"HTTP {exc.response.status_code}: {exc.response.text[:400]}",
            ) from exc
        except httpx.RequestError as exc:
            raise ProtocolMismatch(
                adapter="AnthropicAdapter",
                detail=f"Request failed: {exc}",
            ) from exc

        try:
            data = resp.json()
        except Exception as exc:
            raise ProtocolMismatch(
                adapter="AnthropicAdapter",
                detail=f"Non-JSON response: {resp.text[:200]}",
            ) from exc

        if "content" not in data or not data["content"]:
            raise ProtocolMismatch(
                adapter="AnthropicAdapter",
                detail=f"Response missing 'content': {list(data.keys())}",
            )

        text = data["content"][0].get("text", "")
        finish_reason = data.get("stop_reason")

        raw_usage = data.get("usage", {})
        usage = Usage(
            prompt_tokens=raw_usage.get("input_tokens", 0),
            completion_tokens=raw_usage.get("output_tokens", 0),
            total_tokens=raw_usage.get("input_tokens", 0) + raw_usage.get("output_tokens", 0),
        )

        return ChatResponse(
            text=text,
            model=data.get("model", self._model),
            finish_reason=finish_reason,
            usage=usage,
            raw=data,
        )

    async def stream_chat(self, messages: list[Message], **opts) -> AsyncIterator[Delta]:
        system, converted = self._split_messages(messages)
        payload: dict = {
            "model": self._model,
            "max_tokens": opts.pop("max_tokens", _DEFAULT_MAX_TOKENS),
            "messages": converted,
            "stream": True,
            **opts,
        }
        if system:
            payload["system"] = system

        async with self._client.stream(
            "POST",
            f"{_BASE_URL}/v1/messages",
            json=payload,
            headers=self._build_headers(),
            timeout=120.0,
        ) as resp:
            if resp.status_code >= 400:
                body = await resp.aread()
                raise ProtocolMismatch(
                    adapter="AnthropicAdapter",
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

                event_type = chunk.get("type")
                if event_type == "content_block_delta":
                    delta_obj = chunk.get("delta", {})
                    text_piece = delta_obj.get("text", "")
                    yield Delta(text=text_piece, finish_reason=None, raw=chunk)
                elif event_type == "message_delta":
                    finish_reason = chunk.get("delta", {}).get("stop_reason")
                    if finish_reason:
                        yield Delta(text="", finish_reason=finish_reason, raw=chunk)

    async def embed(self, texts: list[str]) -> list[list[float]]:
        raise NotImplementedError("Anthropic does not expose an embeddings endpoint")

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

    async def __aenter__(self) -> "AnthropicAdapter":
        return self

    async def __aexit__(self, *_) -> None:
        await self._close_own_client()
