"""TransportAdapter protocol."""
from __future__ import annotations

import json
from typing import Any, AsyncIterator, Protocol


class TransportResponse:
    def __init__(self, status: int, headers: dict, body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body

    def json(self) -> Any:
        return json.loads(self.body)

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class TransportAdapter(Protocol):
    async def request(self, method: str, url: str, **kw: Any) -> TransportResponse: ...
    async def stream(self, method: str, url: str, **kw: Any) -> AsyncIterator[bytes]: ...
