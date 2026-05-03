"""In-process pub/sub for run events with bounded replay buffer."""

from __future__ import annotations

import asyncio
from collections import deque
from typing import Any


class _RunChannel:
    def __init__(self, max_buffer: int = 1000) -> None:
        self._subs: set[asyncio.Queue[dict[str, Any]]] = set()
        self._buffer: deque[dict[str, Any]] = deque(maxlen=max_buffer)
        self._seq = 0
        self._closed = False

    async def publish(self, evt: dict[str, Any]) -> None:
        self._seq += 1
        evt = {**evt, "seq": self._seq}
        self._buffer.append(evt)
        for q in list(self._subs):
            try:
                q.put_nowait(evt)
            except asyncio.QueueFull:
                pass

    def replay_since(self, since: int = 0) -> list[dict[str, Any]]:
        return [e for e in self._buffer if e["seq"] > since]

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=4096)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        self._subs.discard(q)

    def close(self) -> None:
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed


class EventBus:
    def __init__(self) -> None:
        self._channels: dict[str, _RunChannel] = {}
        self._lock = asyncio.Lock()

    async def channel(self, run_id: str) -> _RunChannel:
        async with self._lock:
            ch = self._channels.get(run_id)
            if ch is None:
                ch = _RunChannel()
                self._channels[run_id] = ch
            return ch

    async def publish(self, run_id: str, evt: dict[str, Any]) -> None:
        ch = await self.channel(run_id)
        await ch.publish(evt)

    async def close(self, run_id: str) -> None:
        ch = self._channels.get(run_id)
        if ch:
            ch.close()


bus = EventBus()
