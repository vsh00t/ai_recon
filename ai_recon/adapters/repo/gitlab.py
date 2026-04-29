"""GitLabAdapter — GitLab API v4 repository and code-search adapter."""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import httpx

from ai_recon.adapters.repo.base import CodeMatch, RepoRef

logger = logging.getLogger(__name__)

try:
    import git as gitpython  # GitPython
    _HAS_GITPYTHON = True
except ImportError:  # pragma: no cover
    _HAS_GITPYTHON = False


class GitLabAdapter:
    """GitLab repository adapter using the GitLab API v4.

    Args:
        base_url:          GitLab instance URL, e.g. ``https://gitlab.example.com``.
        token_ref:         Secret ref for a GitLab personal or project access token.
        secrets:           SecretsAdapter used to resolve *token_ref*.
        scope_namespaces:  Optional list of group paths to restrict results to.
    """

    def __init__(
        self,
        base_url: str,
        token_ref: str,
        secrets: Any,
        scope_namespaces: list[str] | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_base = f"{self._base_url}/api/v4"
        self._token = secrets.resolve(token_ref)
        self._scope_namespaces = scope_namespaces or []
        self._http_client: httpx.AsyncClient | None = None

    def _client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                headers={"PRIVATE-TOKEN": self._token},
                timeout=30.0,
            )
        return self._http_client

    def _matches_namespace(self, project: dict) -> bool:
        if not self._scope_namespaces:
            return True
        ns_path: str = project.get("namespace", {}).get("full_path", "")
        return any(ns_path == ns or ns_path.startswith(f"{ns}/") for ns in self._scope_namespaces)

    # ------------------------------------------------------------------
    # RepoAdapter interface
    # ------------------------------------------------------------------

    async def search_repos(self, keywords: list[str]) -> list[RepoRef]:
        """Search GitLab for projects matching each keyword, deduplicate, and filter by namespace."""
        client = self._client()
        seen: set[str] = set()
        repos: list[RepoRef] = []

        for keyword in keywords:
            page = 1
            while True:
                response = await client.get(
                    f"{self._api_base}/search",
                    params={
                        "scope": "projects",
                        "search": keyword,
                        "per_page": 100,
                        "page": page,
                    },
                )
                response.raise_for_status()
                items: list[dict] = response.json()
                if not items:
                    break

                for project in items:
                    pid = str(project.get("id", ""))
                    if pid in seen:
                        continue
                    if not self._matches_namespace(project):
                        continue
                    seen.add(pid)
                    repos.append(
                        RepoRef(
                            id=pid,
                            name=project.get("path_with_namespace", project.get("name", "")),
                            url=project.get("http_url_to_repo", project.get("web_url", "")),
                            default_branch=project.get("default_branch", "main"),
                            description=project.get("description", "") or "",
                        )
                    )
                # Check X-Total-Pages header for more pages.
                total_pages = int(response.headers.get("X-Total-Pages", "1"))
                if page >= total_pages:
                    break
                page += 1

        return repos

    async def clone(self, repo: RepoRef, dest: Path) -> Path:
        """Clone *repo* using GitPython, injecting the token into the HTTP URL."""
        if not _HAS_GITPYTHON:
            raise RuntimeError(
                "GitPython is required for GitLabAdapter.clone(). "
                "Install it with: pip install gitpython"
            )
        dest = dest.expanduser().resolve()
        dest.mkdir(parents=True, exist_ok=True)

        # Inject token into the URL: https://<token>@host/path.git
        url = repo.url
        if url.startswith("https://"):
            url = f"https://oauth2:{self._token}@{url[len('https://'):]}"

        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        gitpython.Repo.clone_from(url, str(dest), env=env, depth=1)
        return dest

    async def search_code(self, query: str) -> list[CodeMatch]:
        """Search code blobs across all accessible projects via the GitLab Search API."""
        client = self._client()
        matches: list[CodeMatch] = []
        page = 1

        while True:
            response = await client.get(
                f"{self._api_base}/search",
                params={
                    "scope": "blobs",
                    "search": query,
                    "per_page": 100,
                    "page": page,
                },
            )
            response.raise_for_status()
            items: list[dict] = response.json()
            if not items:
                break

            for blob in items:
                data = blob.get("data", "")
                filename = blob.get("filename", "")
                project_id = str(blob.get("project_id", ""))
                # GitLab blobs don't include line numbers; use startline if present.
                startline: int = blob.get("startline", 1)
                for idx, line in enumerate(data.splitlines(), start=startline):
                    if query.lower() in line.lower():
                        matches.append(
                            CodeMatch(
                                repo_id=project_id,
                                file_path=filename,
                                line_number=idx,
                                line_content=line,
                            )
                        )
                        break  # one match per blob is sufficient

            total_pages = int(response.headers.get("X-Total-Pages", "1"))
            if page >= total_pages:
                break
            page += 1

        return matches

    async def aclose(self) -> None:
        if self._http_client is not None:
            await self._http_client.aclose()

    async def __aenter__(self) -> "GitLabAdapter":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()
