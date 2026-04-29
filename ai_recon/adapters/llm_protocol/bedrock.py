"""AWS Bedrock LLM adapter."""
from __future__ import annotations

import json
from typing import AsyncIterator, Literal

from ai_recon.core.errors import ProtocolMismatch
from ai_recon.core.models import ChatResponse, Delta, Message, Usage

_DEFAULT_MAX_TOKENS = 512
_ANTHROPIC_MAX_TOKENS = 4096


def _require_boto3():
    try:
        import boto3  # noqa: F401
        import botocore  # noqa: F401
        return boto3
    except ImportError as exc:
        raise ImportError(
            "boto3 is required for BedrockAdapter. Install it with: pip install boto3"
        ) from exc


class BedrockAdapter:
    """
    Adapter for AWS Bedrock foundation models.

    Handles multiple model families: Anthropic Claude, Amazon Titan,
    Meta Llama, and Mistral — each with their own request/response shapes.
    """

    def __init__(
        self,
        model_id: str,
        region: str = "us-east-1",
        access_key_ref: str | None = None,
        secret_key_ref: str | None = None,
        secrets: object | None = None,
    ) -> None:
        self._model_id = model_id
        self._region = region
        self._access_key_ref = access_key_ref
        self._secret_key_ref = secret_key_ref
        self._secrets = secrets
        self._runtime_client = None  # lazily created

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_secret(self, ref: str | None) -> str | None:
        if ref is None:
            return None
        if self._secrets is not None:
            try:
                val = getattr(self._secrets, "resolve", lambda r: None)(ref)
                if val:
                    return val
            except Exception:
                pass
        return ref  # treat as literal

    def _get_runtime(self):
        if self._runtime_client is not None:
            return self._runtime_client
        boto3 = _require_boto3()
        kwargs: dict = {"region_name": self._region}
        access_key = self._resolve_secret(self._access_key_ref)
        secret_key = self._resolve_secret(self._secret_key_ref)
        if access_key:
            kwargs["aws_access_key_id"] = access_key
        if secret_key:
            kwargs["aws_secret_access_key"] = secret_key
        self._runtime_client = boto3.client("bedrock-runtime", **kwargs)
        return self._runtime_client

    # ------------------------------------------------------------------
    # Payload builders per model family
    # ------------------------------------------------------------------

    def _build_invoke_body(self, messages: list[Message], **opts) -> bytes:
        mid = self._model_id.lower()

        if mid.startswith("anthropic.claude"):
            system_parts = [m.content for m in messages if m.role == "system"]
            chat_msgs = [
                {"role": m.role, "content": m.content}
                for m in messages
                if m.role != "system"
            ]
            body: dict = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": opts.pop("max_tokens", _ANTHROPIC_MAX_TOKENS),
                "messages": chat_msgs,
            }
            if system_parts:
                body["system"] = "\n".join(system_parts)
            body.update(opts)
            return json.dumps(body).encode()

        if mid.startswith("amazon.titan"):
            prompt = "\n".join(
                f"{m.role.capitalize()}: {m.content}" for m in messages
            )
            body = {
                "inputText": prompt,
                "textGenerationConfig": {
                    "maxTokenCount": opts.pop("max_tokens", _DEFAULT_MAX_TOKENS),
                    "temperature": opts.pop("temperature", 0.7),
                    **opts,
                },
            }
            return json.dumps(body).encode()

        if mid.startswith("meta.llama"):
            prompt = "\n".join(
                f"{m.role.capitalize()}: {m.content}" for m in messages
            )
            body = {
                "prompt": prompt,
                "max_gen_len": opts.pop("max_tokens", _DEFAULT_MAX_TOKENS),
                "temperature": opts.pop("temperature", 0.7),
                **opts,
            }
            return json.dumps(body).encode()

        if "mistral" in mid:
            prompt = "\n".join(
                f"{m.role.capitalize()}: {m.content}" for m in messages
            )
            body = {
                "prompt": prompt,
                "max_tokens": opts.pop("max_tokens", _DEFAULT_MAX_TOKENS),
                "temperature": opts.pop("temperature", 0.7),
                **opts,
            }
            return json.dumps(body).encode()

        raise ProtocolMismatch(
            adapter="BedrockAdapter",
            detail=f"Unsupported model family: {self._model_id}",
        )

    def _parse_invoke_response(self, body_bytes: bytes) -> ChatResponse:
        try:
            data = json.loads(body_bytes)
        except Exception as exc:
            raise ProtocolMismatch(
                adapter="BedrockAdapter",
                detail=f"Non-JSON response body: {body_bytes[:200]}",
            ) from exc

        mid = self._model_id.lower()

        if mid.startswith("anthropic.claude"):
            content = data.get("content", [])
            if not content:
                raise ProtocolMismatch(
                    adapter="BedrockAdapter",
                    detail=f"Anthropic Claude response missing 'content': {list(data.keys())}",
                )
            text = content[0].get("text", "")
            raw_usage = data.get("usage", {})
            usage = Usage(
                prompt_tokens=raw_usage.get("input_tokens", 0),
                completion_tokens=raw_usage.get("output_tokens", 0),
                total_tokens=(
                    raw_usage.get("input_tokens", 0) + raw_usage.get("output_tokens", 0)
                ),
            )
            return ChatResponse(
                text=text,
                model=self._model_id,
                finish_reason=data.get("stop_reason"),
                usage=usage,
                raw=data,
            )

        if mid.startswith("amazon.titan"):
            results = data.get("results", [])
            if not results:
                raise ProtocolMismatch(
                    adapter="BedrockAdapter",
                    detail=f"Titan response missing 'results': {list(data.keys())}",
                )
            text = results[0].get("outputText", "")
            return ChatResponse(
                text=text,
                model=self._model_id,
                finish_reason=results[0].get("completionReason"),
                usage=Usage(
                    prompt_tokens=data.get("inputTextTokenCount", 0),
                    completion_tokens=results[0].get("tokenCount", 0),
                    total_tokens=(
                        data.get("inputTextTokenCount", 0)
                        + results[0].get("tokenCount", 0)
                    ),
                ),
                raw=data,
            )

        if mid.startswith("meta.llama"):
            if "generation" not in data:
                raise ProtocolMismatch(
                    adapter="BedrockAdapter",
                    detail=f"Llama response missing 'generation': {list(data.keys())}",
                )
            return ChatResponse(
                text=data["generation"],
                model=self._model_id,
                finish_reason=data.get("stop_reason"),
                usage=Usage(
                    prompt_tokens=data.get("prompt_token_count", 0),
                    completion_tokens=data.get("generation_token_count", 0),
                    total_tokens=(
                        data.get("prompt_token_count", 0)
                        + data.get("generation_token_count", 0)
                    ),
                ),
                raw=data,
            )

        if "mistral" in mid:
            outputs = data.get("outputs", [])
            if not outputs:
                raise ProtocolMismatch(
                    adapter="BedrockAdapter",
                    detail=f"Mistral response missing 'outputs': {list(data.keys())}",
                )
            text = outputs[0].get("text", "")
            return ChatResponse(
                text=text,
                model=self._model_id,
                finish_reason=outputs[0].get("stop_reason"),
                usage=Usage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
                raw=data,
            )

        raise ProtocolMismatch(
            adapter="BedrockAdapter",
            detail=f"Cannot parse response for model family: {self._model_id}",
        )

    # ------------------------------------------------------------------
    # Protocol methods
    # ------------------------------------------------------------------

    async def chat(self, messages: list[Message], **opts) -> ChatResponse:
        import asyncio

        runtime = self._get_runtime()
        body_bytes = self._build_invoke_body(messages, **opts)

        try:
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: runtime.invoke_model(
                    modelId=self._model_id,
                    body=body_bytes,
                    contentType="application/json",
                    accept="application/json",
                ),
            )
        except Exception as exc:
            raise ProtocolMismatch(
                adapter="BedrockAdapter",
                detail=f"invoke_model failed: {exc}",
            ) from exc

        response_body = response["body"].read()
        return self._parse_invoke_response(response_body)

    async def stream_chat(self, messages: list[Message], **opts) -> AsyncIterator[Delta]:
        import asyncio

        runtime = self._get_runtime()
        body_bytes = self._build_invoke_body(messages, **opts)

        try:
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: runtime.invoke_model_with_response_stream(
                    modelId=self._model_id,
                    body=body_bytes,
                    contentType="application/json",
                    accept="application/json",
                ),
            )
        except Exception as exc:
            raise ProtocolMismatch(
                adapter="BedrockAdapter",
                detail=f"invoke_model_with_response_stream failed: {exc}",
            ) from exc

        mid = self._model_id.lower()
        event_stream = response.get("body")
        if event_stream is None:
            raise ProtocolMismatch(
                adapter="BedrockAdapter",
                detail="Stream response missing 'body'",
            )

        for event in event_stream:
            chunk_data = event.get("chunk", {})
            raw_bytes = chunk_data.get("bytes", b"")
            if not raw_bytes:
                continue
            try:
                chunk = json.loads(raw_bytes)
            except Exception:
                continue

            if mid.startswith("anthropic.claude"):
                event_type = chunk.get("type")
                if event_type == "content_block_delta":
                    text_piece = chunk.get("delta", {}).get("text", "")
                    yield Delta(text=text_piece, finish_reason=None, raw=chunk)
                elif event_type == "message_delta":
                    finish_reason = chunk.get("delta", {}).get("stop_reason")
                    if finish_reason:
                        yield Delta(text="", finish_reason=finish_reason, raw=chunk)

            elif mid.startswith("amazon.titan"):
                text_piece = chunk.get("outputText", "")
                yield Delta(text=text_piece, finish_reason=None, raw=chunk)

            elif mid.startswith("meta.llama"):
                text_piece = chunk.get("generation", "")
                stop_reason = chunk.get("stop_reason")
                yield Delta(text=text_piece, finish_reason=stop_reason, raw=chunk)

            elif "mistral" in mid:
                outputs = chunk.get("outputs", [])
                if outputs:
                    text_piece = outputs[0].get("text", "")
                    stop_reason = outputs[0].get("stop_reason")
                    yield Delta(text=text_piece, finish_reason=stop_reason, raw=chunk)

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """
        Embed texts using Amazon Titan Embeddings or Cohere Embed via Bedrock.
        Model must be an embedding model (e.g. amazon.titan-embed-text-v1,
        cohere.embed-english-v3).
        """
        import asyncio

        runtime = self._get_runtime()
        results: list[list[float]] = []
        mid = self._model_id.lower()

        for text in texts:
            if "titan" in mid:
                body_bytes = json.dumps({"inputText": text}).encode()
            elif "cohere" in mid:
                body_bytes = json.dumps({"texts": [text], "input_type": "search_document"}).encode()
            else:
                body_bytes = json.dumps({"inputText": text}).encode()

            try:
                loop = asyncio.get_running_loop()
                response = await loop.run_in_executor(
                    None,
                    lambda b=body_bytes: runtime.invoke_model(
                        modelId=self._model_id,
                        body=b,
                        contentType="application/json",
                        accept="application/json",
                    ),
                )
            except Exception as exc:
                raise ProtocolMismatch(
                    adapter="BedrockAdapter",
                    detail=f"Embed invoke_model failed: {exc}",
                ) from exc

            try:
                data = json.loads(response["body"].read())
            except Exception as exc:
                raise ProtocolMismatch(
                    adapter="BedrockAdapter", detail=f"Non-JSON embed response: {exc}"
                ) from exc

            if "titan" in mid:
                embedding = data.get("embedding")
            elif "cohere" in mid:
                embedding = (data.get("embeddings") or [[]])[0]
            else:
                embedding = data.get("embedding")

            if embedding is None:
                raise ProtocolMismatch(
                    adapter="BedrockAdapter",
                    detail=f"Embed response missing embedding: {list(data.keys())}",
                )
            results.append(embedding)

        return results

    def supports(self, capability: Literal["streaming", "tools", "vision", "logprobs"]) -> bool:
        if capability == "streaming":
            return True
        if capability == "tools":
            return "anthropic.claude" in self._model_id.lower()
        if capability == "vision":
            return "claude-3" in self._model_id.lower()
        if capability == "logprobs":
            return False
        return False

    def model_id(self) -> str | None:
        return self._model_id
