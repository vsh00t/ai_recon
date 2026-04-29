"""OpenAI-compatible LLM protocol adapter."""
from __future__ import annotations

import json
from typing import AsyncIterator, Literal

import httpx

from ai_recon.core.errors import ProtocolMismatch
from ai_recon.core.models import ChatResponse, Delta, Message, Usage


class OpenAICompatAdapter:
    """Adapter for any OpenAI-compatible API (OpenAI, Together, Fireworks, etc.)."""

    def __init__(
        self,
        base_url: str,
        model: str = "gpt-4o",
        auth_strategy: str | None = None,
        secrets: object | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._auth_strategy = auth_strategy
        self._secrets = secrets
        self._own_client = http_client is None
        self._client = http_client or httpx.AsyncClient(timeout=120.0)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self._auth_strategy and self._secrets:
            try:
                key = getattr(self._secrets, "resolve", lambda r: None)(self._auth_strategy)
                if key:
                    headers["Authorization"] = f"Bearer {key}"
            except Exception:
                pass
        return headers

    def _messages_to_payload(self, messages: list[Message]) -> list[dict]:
        out = []
        for m in messages:
            entry: dict = {"role": m.role, "content": m.content}
            if m.name:
                entry["name"] = m.name
            if m.tool_call_id:
                entry["tool_call_id"] = m.tool_call_id
            out.append(entry)
        return out

    async def _close_own_client(self) -> None:
        if self._own_client:
            await self._client.aclose()

    # ------------------------------------------------------------------
    # Protocol methods
    # ------------------------------------------------------------------

    async def chat(self, messages: list[Message], **opts) -> ChatResponse:
        payload: dict = {
            "model": self._model,
            "messages": self._messages_to_payload(messages),
            **opts,
        }
        headers = self._auth_headers()
        try:
            resp = await self._client.post(
                f"{self._base_url}/v1/chat/completions",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProtocolMismatch(
                adapter="OpenAICompatAdapter",
                detail=f"HTTP {exc.response.status_code}: {exc.response.text[:400]}",
            ) from exc
        except httpx.RequestError as exc:
            raise ProtocolMismatch(
                adapter="OpenAICompatAdapter",
                detail=f"Request failed: {exc}",
            ) from exc

        try:
            data = resp.json()
        except Exception as exc:
            raise ProtocolMismatch(
                adapter="OpenAICompatAdapter",
                detail=f"Non-JSON response: {resp.text[:200]}",
            ) from exc

        if "choices" not in data or not data["choices"]:
            raise ProtocolMismatch(
                adapter="OpenAICompatAdapter",
                detail=f"Response missing 'choices': {list(data.keys())}",
            )

        choice = data["choices"][0]
        message = choice.get("message", {})
        text = message.get("content") or ""
        finish_reason = choice.get("finish_reason")

        raw_usage = data.get("usage", {})
        usage = Usage(
            prompt_tokens=raw_usage.get("prompt_tokens", 0),
            completion_tokens=raw_usage.get("completion_tokens", 0),
            total_tokens=raw_usage.get("total_tokens", 0),
        )

        return ChatResponse(
            text=text,
            model=data.get("model", self._model),
            finish_reason=finish_reason,
            usage=usage,
            raw=data,
        )

    async def stream_chat(self, messages: list[Message], **opts) -> AsyncIterator[Delta]:
        payload: dict = {
            "model": self._model,
            "messages": self._messages_to_payload(messages),
            "stream": True,
            **opts,
        }
        headers = self._auth_headers()

        async with self._client.stream(
            "POST",
            f"{self._base_url}/v1/chat/completions",
            json=payload,
            headers=headers,
            timeout=120.0,
        ) as resp:
            if resp.status_code >= 400:
                body = await resp.aread()
                raise ProtocolMismatch(
                    adapter="OpenAICompatAdapter",
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
        payload = {"input": texts, "model": self._model}
        headers = self._auth_headers()
        try:
            resp = await self._client.post(
                f"{self._base_url}/v1/embeddings",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProtocolMismatch(
                adapter="OpenAICompatAdapter",
                detail=f"Embed HTTP {exc.response.status_code}: {exc.response.text[:400]}",
            ) from exc

        try:
            data = resp.json()
        except Exception as exc:
            raise ProtocolMismatch(
                adapter="OpenAICompatAdapter",
                detail=f"Non-JSON embed response: {resp.text[:200]}",
            ) from exc

        if "data" not in data:
            raise ProtocolMismatch(
                adapter="OpenAICompatAdapter",
                detail=f"Embed response missing 'data': {list(data.keys())}",
            )

        return [item["embedding"] for item in data["data"]]

    def supports(self, capability: Literal["streaming", "tools", "vision", "logprobs"]) -> bool:
        if capability == "streaming":
            return True
        if capability == "tools":
            return True
        if capability == "vision":
            model_lower = self._model.lower()
            return "vision" in model_lower or "gpt-4" in model_lower or "gpt-4o" in model_lower
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
        """Return True if base_url appears to be an OpenAI-compatible endpoint."""
        own = http_client is None
        client = http_client or httpx.AsyncClient(timeout=10.0)
        try:
            try:
                resp = await client.get(f"{base_url.rstrip('/')}/v1/models")
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("object") == "list":
                        return True
            except Exception:
                pass

            # Fallback: probe with a minimal chat completion
            try:
                resp = await client.post(
                    f"{base_url.rstrip('/')}/v1/chat/completions",
                    json={
                        "model": "gpt-3.5-turbo",
                        "messages": [{"role": "user", "content": "hi"}],
                        "max_tokens": 1,
                    },
                    timeout=10.0,
                )
                if resp.status_code < 500:
                    data = resp.json()
                    if "choices" in data or "error" in data:
                        return True
            except Exception:
                pass

            return False
        finally:
            if own:
                await client.aclose()

    # ------------------------------------------------------------------
    # Async context manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "OpenAICompatAdapter":
        return self

    async def __aexit__(self, *_) -> None:
        await self._close_own_client()
