"""SIEMAdapter protocol and shared data types."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol


@dataclass
class DetectionRule:
    id: str
    name: str
    query_language: Literal["kql", "spl", "kusto", "lucene", "sigma"]
    query: str
    severity: str
    enabled: bool = True
    tags: list[str] = field(default_factory=list)


@dataclass
class LogEvent:
    index: str
    timestamp: datetime
    fields: dict


class SIEMAdapter(Protocol):
    async def list_detection_rules(self) -> list[DetectionRule]: ...
    async def search(self, query: str, since: datetime) -> list[LogEvent]: ...
    async def index_patterns(self) -> list[str]: ...
