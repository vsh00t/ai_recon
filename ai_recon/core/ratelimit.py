"""Token-bucket rate limiter with configurable jitter."""

from __future__ import annotations

import asyncio
import random
import time


class TokenBucket:
    """Async token bucket with optional random jitter between requests.

    Args:
        rps:            Maximum requests per second.
        jitter_seconds: (min, max) seconds of extra random delay per acquire.
    """

    def __init__(
        self,
        rps: float = 2.0,
        jitter_seconds: tuple[float, float] = (0.5, 2.0),
        seed: int | None = None,
    ) -> None:
        self._rate = rps
        self._min_jitter, self._max_jitter = jitter_seconds
        self._tokens = rps
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self._rng = random.Random(seed)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
        self._last_refill = now

    async def acquire(self) -> None:
        async with self._lock:
            self._refill()
            if self._tokens < 1:
                wait = (1 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                self._refill()
            self._tokens -= 1

        jitter = self._rng.uniform(self._min_jitter, self._max_jitter)
        if jitter > 0:
            await asyncio.sleep(jitter)

    async def __aenter__(self) -> "TokenBucket":
        await self.acquire()
        return self

    async def __aexit__(self, *_: object) -> None:
        pass
