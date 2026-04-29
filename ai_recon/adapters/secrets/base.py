"""SecretsAdapter protocol."""
from __future__ import annotations

from typing import Protocol


class SecretsAdapter(Protocol):
    def resolve(self, ref: str) -> str: ...  # "env:NAME" | "vault:path#key" | "1p:item/field"
    def list_refs(self) -> list[str]: ...
