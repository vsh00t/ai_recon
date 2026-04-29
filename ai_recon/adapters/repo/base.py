"""RepoAdapter protocol and shared types."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass
class RepoRef:
    id: str
    name: str
    url: str
    default_branch: str = "main"
    description: str = ""


@dataclass
class CodeMatch:
    repo_id: str
    file_path: str
    line_number: int
    line_content: str


class RepoAdapter(Protocol):
    async def search_repos(self, keywords: list[str]) -> list[RepoRef]: ...
    async def clone(self, repo: RepoRef, dest: Path) -> Path: ...
    async def search_code(self, query: str) -> list[CodeMatch]: ...
