"""In-process pub/sub event bus for plugins and observability."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Coroutine


@dataclass
class Event:
    name: str
    payload: dict[str, Any] = field(default_factory=dict)
    ts: datetime = field(default_factory=datetime.utcnow)


Handler = Callable[[Event], Coroutine[Any, Any, None]]


class EventBus:
    """Lightweight asyncio-based event bus.

    Usage::

        bus = EventBus()
        bus.subscribe("finding.emitted", my_async_handler)
        await bus.publish(Event("finding.emitted", {"finding_id": "..."}))
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = defaultdict(list)
        self._queue: asyncio.Queue[Event] = asyncio.Queue()
        self._running = False

    def subscribe(self, event_name: str, handler: Handler) -> None:
        self._handlers[event_name].append(handler)

    def unsubscribe(self, event_name: str, handler: Handler) -> None:
        self._handlers[event_name] = [
            h for h in self._handlers[event_name] if h is not handler
        ]

    async def publish(self, event: Event) -> None:
        """Deliver event to all handlers (fire-and-forget per handler)."""
        handlers = self._handlers.get(event.name, []) + self._handlers.get("*", [])
        for h in handlers:
            try:
                await h(event)
            except Exception:
                pass  # handlers must not crash the framework

    async def emit(self, name: str, **payload: Any) -> None:
        await self.publish(Event(name=name, payload=payload))
