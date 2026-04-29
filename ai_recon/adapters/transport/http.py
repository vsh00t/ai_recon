"""HttpTransport — TransportAdapter backed by AIReconClient."""
from __future__ import annotations

from typing import Any, AsyncIterator

from ai_recon.adapters.transport.base import TransportResponse
from ai_recon.core.http import AIReconClient


class HttpTransport:
    """TransportAdapter that delegates to an ``AIReconClient``.

    All scope enforcement, auth injection, rate limiting, and stealth UA
    rotation provided by ``AIReconClient`` are automatically applied.

    Args:
        http_client: A configured :class:`~ai_recon.core.http.AIReconClient` instance.
    """

    def __init__(self, http_client: AIReconClient) -> None:
        self._client = http_client

    async def request(self, method: str, url: str, **kw: Any) -> TransportResponse:
        """Issue an HTTP request through AIReconClient and return a TransportResponse.

        All keyword arguments (``json``, ``headers``, ``params``, etc.) are
        forwarded verbatim to ``AIReconClient.request()``.
        """
        response = await self._client.request(method=method, url=url, **kw)
        return TransportResponse(
            status=response.status_code,
            headers=dict(response.headers),
            body=response.content,
        )

    async def stream(self, method: str, url: str, **kw: Any) -> AsyncIterator[bytes]:
        """Stream response lines through AIReconClient.stream_lines().

        Yields one ``bytes`` object per newline-delimited chunk (SSE / NDJSON).
        """
        return self._stream_inner(method=method, url=url, **kw)

    async def _stream_inner(
        self, method: str, url: str, **kw: Any
    ) -> AsyncIterator[bytes]:
        async for line in self._client.stream_lines(method=method, url=url, **kw):
            yield line
