"""Ollama local LLM adapter."""
from __future__ import annotations

import json
from typing import AsyncIterator, Literal

import httpx

from ai_recon.core.errors import ProtocolMismatch
from ai_recon.core.models import ChatResponse, Delta, Message, Usage


class OllamaAdapter:
    """Adapter for Ollama's local API (http://localhost:11434)."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3",
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._own_client = http_client is None
        self._client = http_client or httpx.AsyncClient(timeout=120.0)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _messages_to_payload(self, messages: list[Message]) -> list[dict]:
        out = []
        for m in messages:
            entry: dict = {"role": m.role, "content": m.content}
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
            "stream": False,
            **opts,
        }
        try:
            resp = await self._client.post(
                f"{self._base_url}/api/chat",
                json=payload,
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProtocolMismatch(
                adapter="OllamaAdapter",
                detail=f"HTTP {exc.response.status_code}: {exc.response.text[:400]}",
            ) from exc
        except httpx.RequestError as exc:
            raise ProtocolMismatch(
                adapter="OllamaAdapter",
                detail=f"Request failed: {exc}",
            ) from exc

        try:
            data = resp.json()
        except Exception as exc:
            raise ProtocolMismatch(
                adapter="OllamaAdapter",
                detail=f"Non-JSON response: {resp.text[:200]}",
            ) from exc

        if "message" not in data:
            raise ProtocolMismatch(
                adapter="OllamaAdapter",
                detail=f"Response missing 'message': {list(data.keys())}",
            )

        text = data["message"].get("content", "")
        finish_reason = "stop" if data.get("done") else None

        # Ollama provides token counts in a flat structure
        usage = Usage(
            prompt_tokens=data.get("prompt_eval_count", 0),
            completion_tokens=data.get("eval_count", 0),
            total_tokens=data.get("prompt_eval_count", 0) + data.get("eval_count", 0),
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

        async with self._client.stream(
            "POST",
            f"{self._base_url}/api/chat",
            json=payload,
            timeout=120.0,
        ) as resp:
            if resp.status_code >= 400:
                body = await resp.aread()
                raise ProtocolMismatch(
                    adapter="OllamaAdapter",
                    detail=f"HTTP {resp.status_code}: {body[:400].decode(errors='replace')}",
                )
            async for line in resp.aiter_lines():
                line = line.strip()
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                except json.JSONDecodeError:
                    continue

                done = chunk.get("done", False)
                message_obj = chunk.get("message", {})
                text_piece = message_obj.get("content", "")
                finish_reason = "stop" if done else None

                yield Delta(text=text_piece, finish_reason=finish_reason, raw=chunk)

                if done:
                    break

    async def embed(self, texts: list[str]) -> list[list[float]]:
        results: list[list[float]] = []
        for text in texts:
            payload = {"model": self._model, "prompt": text}
            try:
                resp = await self._client.post(
                    f"{self._base_url}/api/embeddings",
                    json=payload,
                )
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise ProtocolMismatch(
                    adapter="OllamaAdapter",
                    detail=f"Embed HTTP {exc.response.status_code}: {exc.response.text[:400]}",
                ) from exc

            try:
                data = resp.json()
            except Exception as exc:
                raise ProtocolMismatch(
                    adapter="OllamaAdapter",
                    detail=f"Non-JSON embed response: {resp.text[:200]}",
                ) from exc

            if "embedding" not in data:
                raise ProtocolMismatch(
                    adapter="OllamaAdapter",
                    detail=f"Embed response missing 'embedding': {list(data.keys())}",
                )
            results.append(data["embedding"])
        return results

    def supports(self, capability: Literal["streaming", "tools", "vision", "logprobs"]) -> bool:
        if capability == "streaming":
            return True
        if capability == "tools":
            return False
        if capability == "vision":
            return "llava" in self._model.lower()
        if capability == "logprobs":
            return False
        return False

    def model_id(self) -> str | None:
        return self._model

    # ------------------------------------------------------------------
    # Auto-detect
    # ------------------------------------------------------------------

    @staticmethod
    async def detect(
        base_url: str = "http://localhost:11434",
        http_client: httpx.AsyncClient | None = None,
    ) -> bool:
        """Return True if base_url is an Ollama instance."""
        own = http_client is None
        client = http_client or httpx.AsyncClient(timeout=5.0)
        try:
            resp = await client.get(f"{base_url.rstrip('/')}/api/version")
            if resp.status_code == 200:
                data = resp.json()
                return "version" in data
            return False
        except Exception:
            return False
        finally:
            if own:
                await client.aclose()

    # ------------------------------------------------------------------
    # Async context manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "OllamaAdapter":
        return self

    async def __aexit__(self, *_) -> None:
        await self._close_own_client()
