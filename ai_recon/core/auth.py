"""Auth strategies applied to outgoing httpx requests."""

from __future__ import annotations

import base64
import time
from typing import TYPE_CHECKING, Protocol

import httpx

from ai_recon.core.models import AuthSpec, AuthKind

if TYPE_CHECKING:
    from ai_recon.adapters.secrets.base import SecretsAdapter


class AuthStrategy(Protocol):
    async def apply(self, request: httpx.Request, secrets: "SecretsAdapter") -> None: ...


class NoAuth:
    async def apply(self, request: httpx.Request, secrets: "SecretsAdapter") -> None:
        pass


class BearerAuth:
    def __init__(self, secret_ref: str) -> None:
        self._ref = secret_ref

    async def apply(self, request: httpx.Request, secrets: "SecretsAdapter") -> None:
        token = secrets.resolve(self._ref)
        request.headers["Authorization"] = f"Bearer {token}"


class ApiKeyHeaderAuth:
    def __init__(self, secret_ref: str, header_name: str = "X-API-Key") -> None:
        self._ref = secret_ref
        self._header = header_name

    async def apply(self, request: httpx.Request, secrets: "SecretsAdapter") -> None:
        key = secrets.resolve(self._ref)
        request.headers[self._header] = key


class ApiKeyQueryAuth:
    def __init__(self, secret_ref: str, param_name: str = "api_key") -> None:
        self._ref = secret_ref
        self._param = param_name

    async def apply(self, request: httpx.Request, secrets: "SecretsAdapter") -> None:
        key = secrets.resolve(self._ref)
        url = httpx.URL(str(request.url)).copy_add_param(self._param, key)
        request.url = url


class BasicAuth:
    def __init__(self, secret_ref: str) -> None:
        # secret_ref must resolve to "user:password"
        self._ref = secret_ref

    async def apply(self, request: httpx.Request, secrets: "SecretsAdapter") -> None:
        value = secrets.resolve(self._ref)
        encoded = base64.b64encode(value.encode()).decode()
        request.headers["Authorization"] = f"Basic {encoded}"


class OAuth2CCAuth:
    """OAuth 2.0 Client Credentials with token caching."""

    def __init__(
        self,
        token_url: str,
        client_id_ref: str,
        client_secret_ref: str,
        scope: str = "",
    ) -> None:
        self._token_url = token_url
        self._client_id_ref = client_id_ref
        self._client_secret_ref = client_secret_ref
        self._scope = scope
        self._cached_token: str | None = None
        self._expires_at: float = 0.0

    async def apply(self, request: httpx.Request, secrets: "SecretsAdapter") -> None:
        if self._cached_token is None or time.time() >= self._expires_at - 30:
            await self._refresh(secrets)
        request.headers["Authorization"] = f"Bearer {self._cached_token}"

    async def _refresh(self, secrets: "SecretsAdapter") -> None:
        client_id = secrets.resolve(self._client_id_ref)
        client_secret = secrets.resolve(self._client_secret_ref)
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self._token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": self._scope,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            self._cached_token = data["access_token"]
            self._expires_at = time.time() + int(data.get("expires_in", 3600))


class CookieAuth:
    def __init__(self, secret_ref: str, cookie_name: str = "session") -> None:
        self._ref = secret_ref
        self._name = cookie_name

    async def apply(self, request: httpx.Request, secrets: "SecretsAdapter") -> None:
        value = secrets.resolve(self._ref)
        request.headers["Cookie"] = f"{self._name}={value}"


def build_auth_strategy(spec: AuthSpec) -> AuthStrategy:
    """Factory: build AuthStrategy from AuthSpec."""
    kind: AuthKind = spec.kind
    ref = spec.secret_ref or ""
    header = spec.header_name or "X-API-Key"

    if kind == "none":
        return NoAuth()
    if kind == "bearer":
        return BearerAuth(ref)
    if kind == "apikey_header":
        return ApiKeyHeaderAuth(ref, header)
    if kind == "apikey_query":
        return ApiKeyQueryAuth(ref, spec.extra.get("param_name", "api_key"))
    if kind == "basic":
        return BasicAuth(ref)
    if kind == "oauth2_cc":
        return OAuth2CCAuth(
            token_url=spec.extra["token_url"],
            client_id_ref=spec.extra["client_id_ref"],
            client_secret_ref=spec.extra["client_secret_ref"],
            scope=spec.extra.get("scope", ""),
        )
    if kind == "cookie":
        return CookieAuth(ref, spec.extra.get("cookie_name", "session"))
    if kind == "mtls":
        return NoAuth()  # mTLS is configured at transport level; no header needed
    raise ValueError(f"Unknown auth kind: {kind!r}")
