"""HuggingFace Text Generation Inference (TGI) adapter."""
from __future__ import annotations

import json
from typing import AsyncIterator, Literal

import httpx

from ai_recon.core.errors import ProtocolMismatch
from ai_recon.core.models import ChatResponse, Delta, Message, Usage


class TGIAdapter:
    """
    Adapter for HuggingFace Text Generation Inference.

    Supports both TGI 2.0+ (OpenAI-compatible /v1/chat/completions) and
    older TGI (/generate endpoint). Falls back automatically.
    """

    def __init__(
        self,
        base_url: str,
        model: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._own_client = http_client is None
        self._client = http_client or httpx.AsyncClient(timeout=120.0)
        # Whether the TGI instance supports the OpenAI-compatible endpoint
        self._use_openai_compat: bool | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _messages_to_openai(self, messages: list[Message]) -> list[dict]:
        out = []
        for m in messages:
            entry: dict = {"role": m.role, "content": m.content}
            if m.name:
                entry["name"] = m.name
            out.append(entry)
        return out

    def _messages_to_prompt(self, messages: list[Message]) -> str:
        """Flatten messages to a single prompt string for legacy /generate."""
        parts = []
        for m in messages:
            prefix = {"system": "System", "user": "User", "assistant": "Assistant"}.get(
                m.role, m.role.capitalize()
            )
            parts.append(f"{prefix}: {m.content}")
        parts.append("Assistant:")
        return "\n".join(parts)

    async def _probe_openai_compat(self) -> bool:
        """Check whether this TGI instance has the /v1/chat/completions endpoint."""
        try:
            resp = await self._client.get(f"{self._base_url}/v1/models", timeout=5.0)
            if resp.status_code < 500:
                return True
        except Exception:
            pass
        return False

    async def _ensure_compat_mode(self) -> None:
        if self._use_openai_compat is None:
            self._use_openai_compat = await self._probe_openai_compat()

    async def _close_own_client(self) -> None:
        if self._own_client:
            await self._client.aclose()

    # ------------------------------------------------------------------
    # Protocol methods
    # ------------------------------------------------------------------

    async def chat(self, messages: list[Message], **opts) -> ChatResponse:
        await self._ensure_compat_mode()

        if self._use_openai_compat:
            return await self._chat_openai(messages, **opts)
        return await self._chat_legacy(messages, **opts)

    async def _chat_openai(self, messages: list[Message], **opts) -> ChatResponse:
        payload: dict = {
            "messages": self._messages_to_openai(messages),
            **opts,
        }
        if self._model:
            payload["model"] = self._model

        try:
            resp = await self._client.post(
                f"{self._base_url}/v1/chat/completions",
                json=payload,
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProtocolMismatch(
                adapter="TGIAdapter",
                detail=f"OpenAI-compat HTTP {exc.response.status_code}: {exc.response.text[:400]}",
            ) from exc
        except httpx.RequestError as exc:
            raise ProtocolMismatch(adapter="TGIAdapter", detail=f"Request failed: {exc}") from exc

        try:
            data = resp.json()
        except Exception as exc:
            raise ProtocolMismatch(
                adapter="TGIAdapter", detail=f"Non-JSON response: {resp.text[:200]}"
            ) from exc

        if "choices" not in data or not data["choices"]:
            raise ProtocolMismatch(
                adapter="TGIAdapter",
                detail=f"OpenAI-compat response missing 'choices': {list(data.keys())}",
            )

        choice = data["choices"][0]
        text = choice.get("message", {}).get("content", "")
        finish_reason = choice.get("finish_reason")
        raw_usage = data.get("usage", {})
        usage = Usage(
            prompt_tokens=raw_usage.get("prompt_tokens", 0),
            completion_tokens=raw_usage.get("completion_tokens", 0),
            total_tokens=raw_usage.get("total_tokens", 0),
        )
        return ChatResponse(
            text=text,
            model=data.get("model", self._model or ""),
            finish_reason=finish_reason,
            usage=usage,
            raw=data,
        )

    async def _chat_legacy(self, messages: list[Message], **opts) -> ChatResponse:
        prompt = self._messages_to_prompt(messages)
        parameters = {
            "max_new_tokens": opts.pop("max_tokens", 512),
            "temperature": opts.pop("temperature", 0.7),
            **opts,
        }
        payload = {"inputs": prompt, "parameters": parameters}

        try:
            resp = await self._client.post(f"{self._base_url}/generate", json=payload)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProtocolMismatch(
                adapter="TGIAdapter",
                detail=f"Legacy /generate HTTP {exc.response.status_code}: {exc.response.text[:400]}",
            ) from exc
        except httpx.RequestError as exc:
            raise ProtocolMismatch(adapter="TGIAdapter", detail=f"Request failed: {exc}") from exc

        try:
            data = resp.json()
        except Exception as exc:
            raise ProtocolMismatch(
                adapter="TGIAdapter", detail=f"Non-JSON legacy response: {resp.text[:200]}"
            ) from exc

        if "generated_text" not in data:
            raise ProtocolMismatch(
                adapter="TGIAdapter",
                detail=f"Legacy response missing 'generated_text': {list(data.keys())}",
            )

        return ChatResponse(
            text=data["generated_text"],
            model=self._model or "",
            finish_reason=data.get("details", {}).get("finish_reason"),
            usage=Usage(
                prompt_tokens=data.get("details", {}).get("prefill_tokens", 0),
                completion_tokens=data.get("details", {}).get("generated_tokens", 0),
                total_tokens=(
                    data.get("details", {}).get("prefill_tokens", 0)
                    + data.get("details", {}).get("generated_tokens", 0)
                ),
            ),
            raw=data,
        )

    async def stream_chat(self, messages: list[Message], **opts) -> AsyncIterator[Delta]:
        await self._ensure_compat_mode()

        if not self._use_openai_compat:
            raise ProtocolMismatch(
                adapter="TGIAdapter",
                detail="Streaming requires TGI 2.0+ with /v1/chat/completions support",
            )

        payload: dict = {
            "messages": self._messages_to_openai(messages),
            "stream": True,
            **opts,
        }
        if self._model:
            payload["model"] = self._model

        async with self._client.stream(
            "POST",
            f"{self._base_url}/v1/chat/completions",
            json=payload,
            timeout=120.0,
        ) as resp:
            if resp.status_code >= 400:
                body = await resp.aread()
                raise ProtocolMismatch(
                    adapter="TGIAdapter",
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
                choices = chunk.get("choices", [])
                if not choices:
                    continue
                delta_obj = choices[0].get("delta", {})
                text_piece = delta_obj.get("content") or ""
                finish_reason = choices[0].get("finish_reason")
                yield Delta(text=text_piece, finish_reason=finish_reason, raw=chunk)

    async def embed(self, texts: list[str]) -> list[list[float]]:
        try:
            resp = await self._client.post(
                f"{self._base_url}/embed",
                json={"inputs": texts},
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProtocolMismatch(
                adapter="TGIAdapter",
                detail=f"Embed HTTP {exc.response.status_code}: {exc.response.text[:400]}",
            ) from exc
        except httpx.RequestError as exc:
            raise ProtocolMismatch(adapter="TGIAdapter", detail=f"Embed request failed: {exc}") from exc

        try:
            data = resp.json()
        except Exception as exc:
            raise ProtocolMismatch(
                adapter="TGIAdapter", detail=f"Non-JSON embed response: {resp.text[:200]}"
            ) from exc

        # TGI /embed returns a list of float arrays directly
        if not isinstance(data, list):
            raise ProtocolMismatch(
                adapter="TGIAdapter",
                detail=f"Embed response is not a list: {type(data).__name__}",
            )
        return data

    def supports(self, capability: Literal["streaming", "tools", "vision", "logprobs"]) -> bool:
        if capability == "streaming":
            return True
        if capability == "tools":
            return False
        if capability == "vision":
            return False
        if capability == "logprobs":
            return True
        return False

    def model_id(self) -> str | None:
        return self._model

    # ------------------------------------------------------------------
    # Auto-detect
    # ------------------------------------------------------------------

    @staticmethod
    async def detect(
        base_url: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> bool:
        """Return True if base_url is a TGI instance (GET /info returns TGI shape)."""
        own = http_client is None
        client = http_client or httpx.AsyncClient(timeout=5.0)
        try:
            resp = await client.get(f"{base_url.rstrip('/')}/info")
            if resp.status_code == 200:
                data = resp.json()
                return "model_id" in data and "docker_label" in data
            return False
        except Exception:
            return False
        finally:
            if own:
                await client.aclose()

    # ------------------------------------------------------------------
    # Async context manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "TGIAdapter":
        return self

    async def __aexit__(self, *_) -> None:
        await self._close_own_client()
