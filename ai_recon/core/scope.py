"""Scope validation and ScopeGuard transport.

ScopeGuard is an httpx.AsyncBaseTransport that rejects any request whose
resolved host/IP falls outside the configured scope.allow entries.
No global monkey-patching is used — isolation is enforced by construction:
all network access goes through adapters that receive this transport.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import AsyncIterator

import httpx

from ai_recon.core.errors import ScopeViolation
from ai_recon.core.models import ScopeAllowEntry, ScopeDocument


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_cidr(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(cidr, strict=False)


def _resolve_host(host: str) -> list[str]:
    try:
        results = socket.getaddrinfo(host, None)
        return [r[4][0] for r in results]
    except OSError:
        return []


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        net = _parse_cidr(cidr)
        return addr in net
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Scope checker
# ---------------------------------------------------------------------------

class ScopeGuard:
    """Validates hostnames/IPs against allow/deny lists.

    Call ``check(host, port)`` before any network operation.
    Raises ``ScopeViolation`` if the target is not in scope.
    """

    def __init__(self, scope: ScopeDocument) -> None:
        self._scope = scope

    def check(self, host: str, port: int | None = None) -> None:
        if self._is_denied(host, port):
            raise ScopeViolation(host, "explicitly denied")
        if not self._is_allowed(host, port):
            raise ScopeViolation(host, "not in scope.allow")

    def _matches_entry(
        self,
        entry: ScopeAllowEntry,
        host: str,
        port: int | None,
    ) -> bool:
        # Port check
        if port is not None and entry.ports and port not in entry.ports:
            return False

        # Host literal match
        if entry.host is not None:
            if entry.host == host:
                return True
            # Wildcard subdomain: *.example.com
            if entry.host.startswith("*."):
                domain = entry.host[2:]
                if host.endswith("." + domain) or host == domain:
                    return True
            return False

        # CIDR match
        if entry.cidr is not None:
            ips = _resolve_host(host)
            if not ips:
                # Try treating host itself as IP
                ips = [host]
            return any(_ip_in_cidr(ip, entry.cidr) for ip in ips)

        return False

    def _is_allowed(self, host: str, port: int | None) -> bool:
        return any(
            self._matches_entry(e, host, port) for e in self._scope.scope.allow
        )

    def _is_denied(self, host: str, port: int | None) -> bool:
        return any(
            self._matches_entry(e, host, port) for e in self._scope.scope.deny
        )


# ---------------------------------------------------------------------------
# httpx transport with scope enforcement
# ---------------------------------------------------------------------------

class ScopeGuardTransport(httpx.AsyncBaseTransport):
    """httpx transport wrapper that enforces scope before each request."""

    def __init__(
        self,
        guard: ScopeGuard,
        inner: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._guard = guard
        self._inner = inner or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        self._guard.check(host, port)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()
