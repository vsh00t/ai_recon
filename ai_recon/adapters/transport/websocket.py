"""WebsocketTransport — TransportAdapter backed by a WebSocket connection."""
from __future__ import annotations

import json
import logging
from typing import Any, AsyncIterator
from urllib.parse import urlparse

from ai_recon.adapters.transport.base import TransportResponse
from ai_recon.core.scope import ScopeGuard

try:
    import websockets
    import websockets.exceptions
    from websockets.legacy.client import connect as ws_connect
except ImportError as _exc:  # pragma: no cover
    raise ImportError(
        "websockets is required for WebsocketTransport. "
        "Install it with: pip install websockets"
    ) from _exc

logger = logging.getLogger(__name__)


def _http_url_to_ws(url: str) -> str:
    """Convert an http(s) URL to ws(s) if needed; pass through ws(s) unchanged."""
    if url.startswith("http://"):
        return "ws://" + url[len("http://"):]
    if url.startswith("https://"):
        return "wss://" + url[len("https://"):]
    return url  # already ws:// or wss://


class WebsocketTransport:
    """TransportAdapter that communicates over a WebSocket connection.

    Before opening any connection the target host is validated against the
    provided :class:`~ai_recon.core.scope.ScopeGuard`.

    Args:
        guard:  A ``ScopeGuard`` instance.  ``check()`` is called with the
                target host and port before every connection attempt.
    """

    def __init__(self, guard: ScopeGuard) -> None:
        self._guard = guard

    def _validate_and_convert(self, url: str) -> tuple[str, str, int | None]:
        """Return *(ws_url, host, port)* after scope validation.

        Raises:
            ScopeViolation: if the host is outside the configured scope.
        """
        ws_url = _http_url_to_ws(url)
        parsed = urlparse(ws_url)
        host = parsed.hostname or ""
        port: int | None = parsed.port
        self._guard.check(host, port)
        return ws_url, host, port

    # ------------------------------------------------------------------
    # TransportAdapter interface
    # ------------------------------------------------------------------

    async def request(self, method: str, url: str, **kw: Any) -> TransportResponse:
        """Open a WebSocket connection, send *method* as a JSON command, receive one message.

        The command sent is ``{"method": method, **kw}``.  The first message
        received is returned as the response body.

        Args:
            method: Logical method / command name to send.
            url:    WebSocket URL (``ws://`` or ``wss://``).  ``http://`` and
                    ``https://`` are transparently converted.
            **kw:   Additional fields included in the JSON command payload.
        """
        ws_url, _host, _port = self._validate_and_convert(url)
        payload = json.dumps({"method": method, **kw})

        async with ws_connect(ws_url) as ws:
            await ws.send(payload)
            raw: str | bytes = await ws.recv()

        body = raw if isinstance(raw, bytes) else raw.encode("utf-8")
        # Attempt to sniff a status code from a JSON envelope.
        status = 200
        try:
            parsed_body = json.loads(body)
            if isinstance(parsed_body, dict):
                status = int(parsed_body.get("status", 200))
        except (json.JSONDecodeError, ValueError):
            pass

        return TransportResponse(status=status, headers={}, body=body)

    async def stream(self, method: str, url: str, **kw: Any) -> AsyncIterator[bytes]:
        """Open a WebSocket and yield bytes for each message until the connection closes.

        The initial command ``{"method": method, **kw}`` is sent once; then
        every incoming message is yielded until the server closes the connection.
        """
        return self._stream_inner(method=method, url=url, **kw)

    async def _stream_inner(
        self, method: str, url: str, **kw: Any
    ) -> AsyncIterator[bytes]:
        ws_url, _host, _port = self._validate_and_convert(url)
        payload = json.dumps({"method": method, **kw})

        async with ws_connect(ws_url) as ws:
            await ws.send(payload)
            try:
                async for message in ws:
                    if isinstance(message, bytes):
                        yield message
                    else:
                        yield message.encode("utf-8")
            except websockets.exceptions.ConnectionClosedOK:
                pass
            except websockets.exceptions.ConnectionClosedError as exc:
                logger.warning("WebSocket connection closed with error: %s", exc)
