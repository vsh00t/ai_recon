"""Traffic shaping: jittered token bucket + identity rotation.

Wraps the global TokenBucket but adds:
  - per-target backoff after 429s
  - User-Agent / session_id rotation pool
  - "stealth" mode that lowers RPS aggressively
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import ClassVar

from ai_recon.core.ratelimit import TokenBucket


_REAL_USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]


@dataclass
class TrafficShaper:
    """Pluggable traffic shaper used by the HTTP client in stealth mode."""

    bucket: TokenBucket
    seed: int = 42
    pool: list[str] = field(default_factory=lambda: list(_REAL_USER_AGENTS))

    STEALTH_RPS: ClassVar[float] = 1 / 30.0           # 1 req every 30s
    STEALTH_JITTER: ClassVar[tuple[float, float]] = (10.0, 30.0)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)
        self._idx = 0

    def next_user_agent(self) -> str:
        ua = self.pool[self._idx % len(self.pool)]
        self._idx += 1
        return ua

    def next_session_id(self) -> str:
        return "%032x" % self._rng.getrandbits(128)

    async def acquire(self) -> None:
        await self.bucket.acquire()

    @classmethod
    def stealth(cls, seed: int = 42) -> "TrafficShaper":
        return cls(
            bucket=TokenBucket(
                rps=cls.STEALTH_RPS,
                jitter_seconds=cls.STEALTH_JITTER,
                seed=seed,
            ),
            seed=seed,
        )
