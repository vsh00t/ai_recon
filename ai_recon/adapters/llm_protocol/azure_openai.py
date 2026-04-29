"""Azure OpenAI Service adapter."""
from __future__ import annotations

import json
from typing import AsyncIterator, Literal

import httpx

from ai_recon.core.errors import ProtocolMismatch
from ai_recon.core.models import ChatResponse, Delta, Message, Usage


class AzureOpenAIAdapter:
    """
    Adapter for Azure OpenAI Service.

    Endpoint format: https://{resource}.openai.azure.com
    Auth: api-key header (not Bearer).
    URL pattern: {endpoint}/openai/deployments/{deployment}/{operation}?api-version={api_version}
    """

    def __init__(
        self,
        endpoint: str,
        deployment: str,
        api_version: str = "2024-02-01",
        api_key_ref: str | None = None,
        secrets: object | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._deployment = deployment
        self._api_version = api_version
        self._api_key_ref = api_key_ref
        self._secrets = secrets
        self._own_client = http_client is None
        self._client = http_client or httpx.AsyncClient(timeout=120.0)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_api_key(self) -> str | None:
        if self._api_key_ref is None:
            return None
        if self._secrets is not None:
            try:
                key = getattr(self._secrets, "resolve", lambda r: None)(self._api_key_ref)
                if key:
                    return key
            except Exception:
                pass
        return self._api_key_ref

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"content-type": "application/json"}
        key = self._resolve_api_key()
        if key:
            headers["api-key"] = key
        return headers

    def _deployment_url(self, operation: str) -> str:
        return (
            f"{self._endpoint}/openai/deployments/{self._deployment}"
            f"/{operation}?api-version={self._api_version}"
        )

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
            "messages": self._messages_to_payload(messages),
            **opts,
        }
        url = self._deployment_url("chat/completions")

        try:
            resp = await self._client.post(url, json=payload, headers=self._build_headers())
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProtocolMismatch(
                adapter="AzureOpenAIAdapter",
                detail=f"HTTP {exc.response.status_code}: {exc.response.text[:400]}",
            ) from exc
        except httpx.RequestError as exc:
            raise ProtocolMismatch(
                adapter="AzureOpenAIAdapter", detail=f"Request failed: {exc}"
            ) from exc

        try:
            data = resp.json()
        except Exception as exc:
            raise ProtocolMismatch(
                adapter="AzureOpenAIAdapter", detail=f"Non-JSON response: {resp.text[:200]}"
            ) from exc

        if "choices" not in data or not data["choices"]:
            raise ProtocolMismatch(
                adapter="AzureOpenAIAdapter",
                detail=f"Response missing 'choices': {list(data.keys())}",
            )

        choice = data["choices"][0]
        text = choice.get("message", {}).get("content") or ""
        finish_reason = choice.get("finish_reason")

        raw_usage = data.get("usage", {})
        usage = Usage(
            prompt_tokens=raw_usage.get("prompt_tokens", 0),
            completion_tokens=raw_usage.get("completion_tokens", 0),
            total_tokens=raw_usage.get("total_tokens", 0),
        )

        return ChatResponse(
            text=text,
            model=data.get("model", self._deployment),
            finish_reason=finish_reason,
            usage=usage,
            raw=data,
        )

    async def stream_chat(self, messages: list[Message], **opts) -> AsyncIterator[Delta]:
        payload: dict = {
            "messages": self._messages_to_payload(messages),
            "stream": True,
            **opts,
        }
        url = self._deployment_url("chat/completions")

        async with self._client.stream(
            "POST",
            url,
            json=payload,
            headers=self._build_headers(),
            timeout=120.0,
        ) as resp:
            if resp.status_code >= 400:
                body = await resp.aread()
                raise ProtocolMismatch(
                    adapter="AzureOpenAIAdapter",
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
        payload = {"input": texts}
        url = self._deployment_url("embeddings")

        try:
            resp = await self._client.post(url, json=payload, headers=self._build_headers())
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProtocolMismatch(
                adapter="AzureOpenAIAdapter",
                detail=f"Embed HTTP {exc.response.status_code}: {exc.response.text[:400]}",
            ) from exc
        except httpx.RequestError as exc:
            raise ProtocolMismatch(
                adapter="AzureOpenAIAdapter", detail=f"Embed request failed: {exc}"
            ) from exc

        try:
            data = resp.json()
        except Exception as exc:
            raise ProtocolMismatch(
                adapter="AzureOpenAIAdapter", detail=f"Non-JSON embed response: {resp.text[:200]}"
            ) from exc

        if "data" not in data:
            raise ProtocolMismatch(
                adapter="AzureOpenAIAdapter",
                detail=f"Embed response missing 'data': {list(data.keys())}",
            )

        return [item["embedding"] for item in data["data"]]

    def supports(self, capability: Literal["streaming", "tools", "vision", "logprobs"]) -> bool:
        if capability == "streaming":
            return True
        if capability == "tools":
            return True
        if capability == "vision":
            # gpt-4o and gpt-4-vision deployments support vision
            dep_lower = self._deployment.lower()
            return "gpt-4o" in dep_lower or "vision" in dep_lower
        if capability == "logprobs":
            return True
        return False

    def model_id(self) -> str | None:
        return self._deployment

    # ------------------------------------------------------------------
    # Async context manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "AzureOpenAIAdapter":
        return self

    async def __aexit__(self, *_) -> None:
        await self._close_own_client()
