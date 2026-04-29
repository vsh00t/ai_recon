"""LocalAdapter — repository adapter for locally-checked-out git repositories."""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Union

from ai_recon.adapters.repo.base import CodeMatch, RepoRef

logger = logging.getLogger(__name__)


class LocalAdapter:
    """Repository adapter that operates against a local directory of git repos.

    Args:
        base_path: Root directory whose immediate subdirectories are scanned for
                   ``.git`` directories.  May be a ``str`` or ``Path``.
    """

    def __init__(self, base_path: Union[str, Path]) -> None:
        self._base_path = Path(base_path).expanduser().resolve()

    # ------------------------------------------------------------------
    # RepoAdapter interface
    # ------------------------------------------------------------------

    async def search_repos(self, keywords: list[str]) -> list[RepoRef]:
        """Return subdirectories of *base_path* that contain a ``.git`` directory.

        If *keywords* is non-empty, only repos whose names contain at least one
        keyword (case-insensitive) are returned.
        """
        repos: list[RepoRef] = []
        if not self._base_path.is_dir():
            logger.warning("LocalAdapter base_path '%s' does not exist.", self._base_path)
            return repos

        for entry in self._base_path.iterdir():
            if not entry.is_dir():
                continue
            git_dir = entry / ".git"
            if not git_dir.exists():
                continue

            name = entry.name
            # Filter by keyword if any were supplied.
            if keywords:
                lower_name = name.lower()
                if not any(kw.lower() in lower_name for kw in keywords):
                    continue

            repos.append(
                RepoRef(
                    id=str(entry),
                    name=name,
                    url=str(entry),
                    default_branch="main",
                    description="",
                )
            )
        return repos

    async def clone(self, repo: RepoRef, dest: Path) -> Path:
        """Clone *repo* into *dest*.

        If *repo.url* is an existing local path, return it directly without
        cloning.  Otherwise run ``git clone --depth=1 <url> <dest>``.
        """
        url_path = Path(repo.url)
        if url_path.exists() and url_path.is_dir():
            return url_path

        dest = dest.expanduser().resolve()
        dest.mkdir(parents=True, exist_ok=True)
        cmd = ["git", "clone", "--depth=1", repo.url, str(dest)]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(
                f"git clone failed (exit {proc.returncode}): "
                f"{stderr.decode('utf-8', errors='replace').strip()}"
            )
        return dest

    async def search_code(self, query: str) -> list[CodeMatch]:
        """Run ``git grep -n`` in every local git repo under *base_path*."""
        matches: list[CodeMatch] = []
        if not self._base_path.is_dir():
            return matches

        for entry in self._base_path.iterdir():
            if not entry.is_dir() or not (entry / ".git").exists():
                continue
            repo_matches = await self._grep_repo(entry, query)
            matches.extend(repo_matches)
        return matches

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _grep_repo(self, repo_dir: Path, query: str) -> list[CodeMatch]:
        """Run ``git grep -n <query>`` inside *repo_dir* and parse the output."""
        repo_id = str(repo_dir)
        cmd = ["git", "grep", "-n", "--", query]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(repo_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        # Exit code 1 means no matches; not an error.
        if proc.returncode not in (0, 1):
            return []

        matches: list[CodeMatch] = []
        for raw_line in stdout.decode("utf-8", errors="replace").splitlines():
            # Format: <file>:<line_number>:<content>
            parts = raw_line.split(":", 2)
            if len(parts) < 3:
                continue
            file_path, lineno_str, content = parts
            try:
                line_number = int(lineno_str)
            except ValueError:
                continue
            matches.append(
                CodeMatch(
                    repo_id=repo_id,
                    file_path=file_path,
                    line_number=line_number,
                    line_content=content,
                )
            )
        return matches
