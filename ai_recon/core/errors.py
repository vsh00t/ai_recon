"""Taxonomy of errors raised by ai-recon."""

from __future__ import annotations


class AIReconError(Exception):
    """Base class for all ai-recon errors."""


class ScopeViolation(AIReconError):
    """Attempt to contact a host/IP outside scope.allow."""

    def __init__(self, target: str, reason: str = "") -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"Scope violation: {target}" + (f" — {reason}" if reason else ""))


class AuthorizationMissing(AIReconError):
    """engagement.authorization_ref is absent but technique requires >= medium intrusiveness."""

    def __init__(self, technique: str) -> None:
        super().__init__(
            f"Technique '{technique}' requires intrusiveness >= medium but "
            "engagement.authorization_ref is not set in scope.yaml"
        )


class IntrusivenessExceeded(AIReconError):
    """Technique intrusiveness exceeds configured intrusiveness_max."""

    def __init__(self, technique: str, required: str, maximum: str) -> None:
        super().__init__(
            f"Technique '{technique}' requires intrusiveness='{required}' "
            f"but intrusiveness_max='{maximum}'. Pass --allow-intrusive {required} to override."
        )


class AdapterNotFound(AIReconError):
    """Requested adapter kind is not registered."""

    def __init__(self, kind: str, adapter_type: str) -> None:
        super().__init__(f"No adapter of type '{adapter_type}' with kind='{kind}' is registered.")


class AdapterError(AIReconError):
    """A remote adapter returned an error."""

    def __init__(self, adapter: str, msg: str) -> None:
        self.adapter = adapter
        super().__init__(f"[{adapter}] {msg}")


class TechniqueAborted(AIReconError):
    """Pre-flight blocked the execution (SIEM rule match, no safe rephrase, etc.)."""

    def __init__(self, technique: str, reason: str) -> None:
        super().__init__(f"Technique '{technique}' aborted: {reason}")


class RateLimited(AIReconError):
    """Server returned 429 Too Many Requests."""

    def __init__(self, url: str, retry_after: float | None = None) -> None:
        self.url = url
        self.retry_after = retry_after
        msg = f"Rate-limited on {url}"
        if retry_after is not None:
            msg += f" (retry after {retry_after}s)"
        super().__init__(msg)


class ProtocolMismatch(AIReconError):
    """LLM adapter does not match the server response format."""

    def __init__(self, adapter: str, detail: str) -> None:
        super().__init__(f"Protocol mismatch for adapter '{adapter}': {detail}")


class HoneypotDetected(AIReconError):
    """A credential or resource has been flagged as a canary/honeypot."""

    def __init__(self, value: str, signal: str) -> None:
        self.value = value
        self.signal = signal
        super().__init__(f"Honeypot detected in value '{value[:20]}...' — signal: {signal}")


class CacheCorruption(AIReconError):
    """The on-disk cache is in an inconsistent state."""


class SecretResolutionError(AIReconError):
    """A secret reference could not be resolved."""

    def __init__(self, ref: str, reason: str) -> None:
        super().__init__(f"Cannot resolve secret ref '{ref}': {reason}")
