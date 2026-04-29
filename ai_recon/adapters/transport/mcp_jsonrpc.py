"""MCPJsonRpcTransport — JSON-RPC 2.0 over HTTP POST transport."""
from __future__ import annotations

import json
import logging
from typing import Any, AsyncIterator

import httpx

from ai_recon.adapters.transport.base import TransportResponse

logger = logging.getLogger(__name__)


class MCPJsonRpcTransport:
    """TransportAdapter implementing JSON-RPC 2.0 over HTTP POST.

    All JSON-RPC requests are sent as ``POST`` to *base_url*.  The transport
    auto-increments a monotonic ``id`` counter per request.

    Args:
        base_url:    The HTTP endpoint that accepts JSON-RPC 2.0 requests.
        http_client: An ``httpx.AsyncClient`` (or any object with a compatible
                     ``.post()`` coroutine).  A new ``httpx.AsyncClient`` is
                     created if not provided.
    """

    def __init__(self, base_url: str, http_client: Any | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._http_client = http_client
        self._owns_client = http_client is None
        self._id_counter = 0

    def _client(self) -> Any:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    def _next_id(self) -> int:
        self._id_counter += 1
        return self._id_counter

    # ------------------------------------------------------------------
    # Public helper
    # ------------------------------------------------------------------

    async def rpc_call(self, method: str, params: dict | None = None) -> dict:
        """Build and send a JSON-RPC 2.0 request; return the ``result`` field.

        Raises:
            ValueError: if the server returns a JSON-RPC error object.
            httpx.HTTPStatusError: on non-2xx HTTP responses.
        """
        request_id = self._next_id()
        body = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }
        client = self._client()
        response = await client.post(
            self._base_url,
            json=body,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
        envelope: dict = response.json()

        if "error" in envelope:
            err = envelope["error"]
            code = err.get("code", -1)
            message = err.get("message", "unknown error")
            raise ValueError(
                f"JSON-RPC error {code}: {message}"
            )

        return envelope.get("result", {})

    # ------------------------------------------------------------------
    # TransportAdapter interface
    # ------------------------------------------------------------------

    async def request(self, method: str, url: str, **kw: Any) -> TransportResponse:
        """Send a JSON-RPC 2.0 call and wrap the result in a TransportResponse.

        The ``method`` field in the RPC envelope is taken from ``kw["method"]``
        if present, otherwise from the *method* argument.  ``kw["params"]``
        is forwarded as the RPC ``params`` dict.

        The *url* argument is ignored; all calls go to *base_url*.
        """
        rpc_method: str = kw.pop("method", method)
        params: dict = kw.pop("params", {})

        try:
            result = await self.rpc_call(rpc_method, params)
        except ValueError as exc:
            # JSON-RPC application error — encode as 400.
            error_body = json.dumps({"error": str(exc)}).encode()
            return TransportResponse(status=400, headers={}, body=error_body)

        result_body = json.dumps(result).encode()
        return TransportResponse(status=200, headers={}, body=result_body)

    async def stream(self, method: str, url: str, **kw: Any) -> AsyncIterator[bytes]:
        """Streaming is not supported by JSON-RPC over HTTP POST.

        Raises:
            NotImplementedError: always.
        """
        raise NotImplementedError(
            "MCPJsonRpcTransport does not support streaming. "
            "Use a WebSocket or SSE transport for streaming JSON-RPC."
        )

    async def aclose(self) -> None:
        if self._owns_client and self._http_client is not None:
            await self._http_client.aclose()

    async def __aenter__(self) -> "MCPJsonRpcTransport":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()
