"""Async HTTP client with scope enforcement, auth injection, and rate-limiting."""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from ai_recon.core.errors import RateLimited, ScopeViolation
from ai_recon.core.ratelimit import TokenBucket
from ai_recon.core.scope import ScopeGuard, ScopeGuardTransport


# User-Agent pool for stealth rotation
_USER_AGENTS = [
    "Mozilla/5.0 (compatible; bot/1.0)",
    "curl/8.7.1",
    "python-httpx/0.27",
    "Wget/1.21.4",
    "Go-http-client/2.0",
]


class AIReconClient:
    """Central async HTTP client used by all adapters and techniques.

    Enforces scope, applies auth, respects rate-limit, and optionally
    rotates User-Agent for stealth mode.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        bucket: TokenBucket,
        secrets: Any | None = None,
        stealth: bool = False,
        seed: int = 42,
        timeout: float = 30.0,
    ) -> None:
        self._guard = guard
        self._bucket = bucket
        self._secrets = secrets
        self._stealth = stealth
        self._ua_index = 0
        self._seed = seed

        transport = ScopeGuardTransport(guard)
        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            http2=True,
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        auth_strategy: Any | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        json_body: Any | None = None,
        content: bytes | None = None,
        skip_rate_limit: bool = False,
    ) -> httpx.Response:
        if not skip_rate_limit:
            await self._bucket.acquire()

        req_headers: dict[str, str] = {}
        if self._stealth:
            req_headers["User-Agent"] = _USER_AGENTS[self._ua_index % len(_USER_AGENTS)]
            self._ua_index += 1
        if headers:
            req_headers.update(headers)

        req = self._client.build_request(
            method,
            url,
            headers=req_headers,
            params=params,
            json=json_body,
            content=content,
        )
        if auth_strategy and self._secrets:
            await auth_strategy.apply(req, self._secrets)

        resp = await self._client.send(req)

        if resp.status_code == 429:
            retry_after: float | None = None
            ra = resp.headers.get("Retry-After")
            if ra and ra.isdigit():
                retry_after = float(ra)
            raise RateLimited(url, retry_after)

        return resp

    async def get(self, url: str, **kw: Any) -> httpx.Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw: Any) -> httpx.Response:
        return await self.request("POST", url, **kw)

    async def head(self, url: str, **kw: Any) -> httpx.Response:
        return await self.request("HEAD", url, **kw)

    async def stream_lines(
        self, method: str, url: str, **kw: Any
    ) -> AsyncIterator[str]:
        await self._bucket.acquire()
        async with self._client.stream(method, url, **kw) as resp:
            async for line in resp.aiter_lines():
                if line:
                    yield line

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AIReconClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()
