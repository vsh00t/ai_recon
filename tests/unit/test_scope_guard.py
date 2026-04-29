from __future__ import annotations

import pytest

from ai_recon.core.errors import ScopeViolation
from ai_recon.core.models import (
    EngagementSpec,
    ScopeAllowEntry,
    ScopeDocument,
    ScopeSpec,
)
from ai_recon.core.scope import ScopeGuard


def _doc(allow, deny=None):
    return ScopeDocument(
        engagement=EngagementSpec(name="t"),
        scope=ScopeSpec(allow=allow, deny=deny or []),
    )


def test_host_literal_allow():
    g = ScopeGuard(_doc([ScopeAllowEntry(host="example.com")]))
    g.check("example.com", 443)
    with pytest.raises(ScopeViolation):
        g.check("evil.com", 443)


def test_wildcard_subdomain():
    g = ScopeGuard(_doc([ScopeAllowEntry(host="*.example.com")]))
    g.check("api.example.com", 443)
    g.check("example.com", 443)  # apex domain matches per impl
    with pytest.raises(ScopeViolation):
        g.check("badexample.com", 443)


def test_explicit_deny_takes_precedence():
    g = ScopeGuard(_doc(
        allow=[ScopeAllowEntry(host="*.example.com")],
        deny=[ScopeAllowEntry(host="prod.example.com")],
    ))
    g.check("api.example.com", 443)
    with pytest.raises(ScopeViolation):
        g.check("prod.example.com", 443)


def test_port_filter():
    g = ScopeGuard(_doc([ScopeAllowEntry(host="example.com", ports=[443])]))
    g.check("example.com", 443)
    with pytest.raises(ScopeViolation):
        g.check("example.com", 8080)


def test_cidr_allow_literal_ip():
    g = ScopeGuard(_doc([ScopeAllowEntry(cidr="10.0.0.0/8")]))
    g.check("10.1.2.3", 443)
    with pytest.raises(ScopeViolation):
        g.check("11.1.2.3", 443)
