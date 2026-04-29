"""NoopAdapter — no-op SIEM implementation used when no SIEM is configured."""
from __future__ import annotations

from datetime import datetime

from ai_recon.adapters.siem.base import DetectionRule, LogEvent


class NoopAdapter:
    """Returns empty lists for all SIEM operations.

    Used as a safe default when no SIEM backend is configured so that
    callers do not need to guard against ``None``.
    """

    async def list_detection_rules(self) -> list[DetectionRule]:
        return []

    async def search(self, query: str, since: datetime) -> list[LogEvent]:
        return []

    async def index_patterns(self) -> list[str]:
        return []
