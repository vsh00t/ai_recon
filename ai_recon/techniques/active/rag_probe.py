"""Helpers for probing native RAG chat endpoints and OpenAI-compatible fallbacks."""
from __future__ import annotations

from typing import Any

from ai_recon.adapters.llm_protocol.openai_compat import OpenAICompatAdapter
from ai_recon.core.errors import ProtocolMismatch
from ai_recon.core.models import ChatResponse, Message, Target, Usage

_NATIVE_RAG_ENDPOINTS: list[str] = [
    "/api/chat",
    "/chat",
    "/query",
    "/api/query",
    "/rag/chat",
    "/api/rag/chat",
]

_NATIVE_PAYLOADS = (
    lambda query: {"query": query},
    lambda query: {"message": query},
    lambda query: {"prompt": query},
    lambda query: {"question": query},
)


def _extract_text(data: dict[str, Any]) -> str:
    if isinstance(data.get("answer"), str):
        return data["answer"]
    if isinstance(data.get("response"), str):
        return data["response"]
    if isinstance(data.get("output"), str):
        return data["output"]
    message = data.get("message")
    if isinstance(message, dict) and isinstance(message.get("content"), str):
        return message["content"]
    if isinstance(message, str):
        return message
    choices = data.get("choices")
    if isinstance(choices, list) and choices:
        choice = choices[0] or {}
        msg = choice.get("message", {})
        if isinstance(msg, dict) and isinstance(msg.get("content"), str):
            return msg["content"]
    return ""


async def rag_chat(ctx: Any, target: Target, query: str) -> ChatResponse:
    """Send a query to either a native RAG endpoint or OpenAI-compatible chat."""
    http_client = getattr(ctx, "http_client", None)
    if http_client is not None:
        for path in _NATIVE_RAG_ENDPOINTS:
            for build_payload in _NATIVE_PAYLOADS:
                try:
                    resp = await http_client.post(
                        f"{target.base_url}{path}",
                        headers={"Content-Type": "application/json"},
                        json_body=build_payload(query),
                    )
                except Exception:
                    continue
                if resp.status_code in (404, 405, 501):
                    continue
                if resp.status_code >= 400:
                    continue
                try:
                    data = resp.json()
                except Exception:
                    continue
                text = _extract_text(data)
                if text or any(k in data for k in ("sources", "retrieval_info", "answer", "response")):
                    return ChatResponse(
                        text=text,
                        model=data.get("model"),
                        finish_reason=data.get("finish_reason"),
                        usage=Usage(
                            prompt_tokens=(data.get("usage") or {}).get("prompt_tokens"),
                            completion_tokens=(data.get("usage") or {}).get("completion_tokens"),
                            total_tokens=(data.get("usage") or {}).get("total_tokens"),
                        ),
                        raw=data,
                    )

    adapter = getattr(ctx, "llm_adapter", None)
    if adapter is None:
        adapter = OpenAICompatAdapter(base_url=target.base_url)
    return await adapter.chat([Message(role="user", content=query)])
