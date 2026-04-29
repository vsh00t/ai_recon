"""vLLM native adapter — delegates to OpenAICompatAdapter, adds vLLM-specific features."""
from __future__ import annotations

import re
from typing import AsyncIterator, Literal

import httpx

from ai_recon.core.errors import ProtocolMismatch
from ai_recon.core.models import ChatResponse, Delta, Message

from .openai_compat import OpenAICompatAdapter


class VLLMAdapter:
    """
    Adapter for vLLM's OpenAI-compatible API.

    Delegates all LLM calls to OpenAICompatAdapter and adds vLLM-specific
    introspection: model discovery via GET /v1/models and Prometheus metrics
    via GET /metrics.
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._own_client = http_client is None
        self._http_client = http_client or httpx.AsyncClient(timeout=120.0)
        self._delegate = OpenAICompatAdapter(
            base_url=base_url,
            model=model,
            http_client=self._http_client,
        )
        # Cache the resolved model id after first lookup
        self._resolved_model_id: str | None = None

    # ------------------------------------------------------------------
    # Protocol methods (delegated)
    # ------------------------------------------------------------------

    async def chat(self, messages: list[Message], **opts) -> ChatResponse:
        return await self._delegate.chat(messages, **opts)

    async def stream_chat(self, messages: list[Message], **opts) -> AsyncIterator[Delta]:
        async for delta in self._delegate.stream_chat(messages, **opts):
            yield delta

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return await self._delegate.embed(texts)

    def supports(self, capability: Literal["streaming", "tools", "vision", "logprobs"]) -> bool:
        if capability == "streaming":
            return True
        if capability == "tools":
            return True  # vLLM 0.4+
        if capability == "vision":
            return False
        if capability == "logprobs":
            return True
        return False

    def model_id(self) -> str | None:
        """Return cached resolved model id (populated lazily by fetch_model_id)."""
        return self._resolved_model_id or self._model

    # ------------------------------------------------------------------
    # vLLM-specific
    # ------------------------------------------------------------------

    async def fetch_model_id(self) -> str | None:
        """Fetch the first model id from GET /v1/models and cache it."""
        try:
            resp = await self._http_client.get(f"{self._base_url}/v1/models")
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as exc:
            raise ProtocolMismatch(
                adapter="VLLMAdapter",
                detail=f"GET /v1/models HTTP {exc.response.status_code}: {exc.response.text[:400]}",
            ) from exc
        except httpx.RequestError as exc:
            raise ProtocolMismatch(
                adapter="VLLMAdapter",
                detail=f"GET /v1/models request failed: {exc}",
            ) from exc

        models = data.get("data", [])
        if not models:
            raise ProtocolMismatch(
                adapter="VLLMAdapter",
                detail="GET /v1/models returned empty data list",
            )

        self._resolved_model_id = models[0].get("id", self._model)
        return self._resolved_model_id

    async def running_requests(self) -> int:
        """
        Parse Prometheus metrics from GET /metrics and return
        the current value of vllm_num_requests_running.
        Returns 0 if the metric is not present.
        """
        try:
            resp = await self._http_client.get(f"{self._base_url}/metrics")
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProtocolMismatch(
                adapter="VLLMAdapter",
                detail=f"GET /metrics HTTP {exc.response.status_code}",
            ) from exc
        except httpx.RequestError as exc:
            raise ProtocolMismatch(
                adapter="VLLMAdapter",
                detail=f"GET /metrics request failed: {exc}",
            ) from exc

        text = resp.text
        # Match: vllm_num_requests_running{...} <value> or plain vllm_num_requests_running <value>
        pattern = re.compile(
            r"^vllm_num_requests_running(?:\{[^}]*\})?\s+([\d.]+)",
            re.MULTILINE,
        )
        match = pattern.search(text)
        if match:
            return int(float(match.group(1)))
        return 0

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    async def _close_own_client(self) -> None:
        if self._own_client:
            await self._http_client.aclose()

    async def __aenter__(self) -> "VLLMAdapter":
        return self

    async def __aexit__(self, *_) -> None:
        await self._close_own_client()
