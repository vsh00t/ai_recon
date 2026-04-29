"""Base class for all techniques."""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import ClassVar

from ulid import ULID

from ai_recon.core.models import Finding, IntrusivenessLevel, RunContext, Target


class Technique(ABC):
    id: ClassVar[str]
    intrusiveness: ClassVar[IntrusivenessLevel]
    requires: ClassVar[set[str]] = set()   # capability tags the target must have
    produces: ClassVar[set[str]] = set()   # tags this technique populates

    def __init__(self, ctx: RunContext) -> None:
        self.ctx = ctx

    async def applicable(self, target: Target) -> bool:
        """Return True if this technique makes sense for this target."""
        return True

    @abstractmethod
    async def run(self, target: Target) -> list[Finding]: ...

    def _make_finding(self, target: Target, **kwargs) -> Finding:
        return Finding(
            id=str(ULID()),
            technique=self.id,
            target_id=target.id,
            intrusiveness=self.intrusiveness,
            detected_at=datetime.utcnow(),
            **kwargs,
        )
