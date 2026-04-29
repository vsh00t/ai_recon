"""GitHubAdapter — GitHub API v3 repository and code-search adapter."""
from __future__ import annotations

import asyncio
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

_GITHUB_API = "https://api.github.com"
_SEARCH_RETRY_DEFAULT = 60.0  # seconds to wait when Retry-After is absent


class GitHubAdapter:
    """GitHub repository and code-search adapter using the GitHub REST API v3.

    Args:
        token_ref:  Secret ref for a GitHub personal access token.
        secrets:    SecretsAdapter used to resolve *token_ref*.
        org:        Optional organisation or user login to scope searches to.
    """

    def __init__(
        self,
        token_ref: str,
        secrets: Any,
        org: str | None = None,
    ) -> None:
        self._token = secrets.resolve(token_ref)
        self._org = org
        self._http_client: httpx.AsyncClient | None = None

    def _client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                base_url=_GITHUB_API,
                headers={
                    "Authorization": f"token {self._token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=30.0,
            )
        return self._http_client

    def _org_qualifier(self) -> str:
        return f"+org:{self._org}" if self._org else ""

    async def _get_with_rate_limit_retry(
        self,
        path: str,
        params: dict | None = None,
    ) -> httpx.Response:
        """GET helper that honours GitHub 403 rate-limit responses."""
        client = self._client()
        for attempt in range(3):
            response = await client.get(path, params=params)
            if response.status_code == 403:
                retry_after_str = response.headers.get("Retry-After", "")
                try:
                    retry_after = float(retry_after_str)
                except (ValueError, TypeError):
                    retry_after = _SEARCH_RETRY_DEFAULT
                logger.warning(
                    "GitHub rate-limited (403). Waiting %.0fs before retry %d/3.",
                    retry_after,
                    attempt + 1,
                )
                await asyncio.sleep(retry_after)
                continue
            response.raise_for_status()
            return response
        # Final attempt — raise whatever we get.
        response = await client.get(path, params=params)
        response.raise_for_status()
        return response

    # ------------------------------------------------------------------
    # RepoAdapter interface
    # ------------------------------------------------------------------

    async def search_repos(self, keywords: list[str]) -> list[RepoRef]:
        """Search GitHub for repositories matching each keyword."""
        seen: set[str] = set()
        repos: list[RepoRef] = []

        for keyword in keywords:
            q = f"{keyword}{self._org_qualifier()}"
            page = 1
            while True:
                response = await self._get_with_rate_limit_retry(
                    "/search/repositories",
                    params={"q": q, "per_page": 100, "page": page},
                )
                data = response.json()
                items: list[dict] = data.get("items", [])
                if not items:
                    break

                for repo in items:
                    rid = str(repo.get("id", ""))
                    if rid in seen:
                        continue
                    seen.add(rid)
                    repos.append(
                        RepoRef(
                            id=rid,
                            name=repo.get("full_name", repo.get("name", "")),
                            url=repo.get("clone_url", repo.get("html_url", "")),
                            default_branch=repo.get("default_branch", "main"),
                            description=repo.get("description", "") or "",
                        )
                    )

                total_count: int = data.get("total_count", 0)
                if page * 100 >= total_count or len(items) < 100:
                    break
                page += 1

        return repos

    async def clone(self, repo: RepoRef, dest: Path) -> Path:
        """Clone *repo* using GitPython with the token injected as Authorization header."""
        if not _HAS_GITPYTHON:
            raise RuntimeError(
                "GitPython is required for GitHubAdapter.clone(). "
                "Install it with: pip install gitpython"
            )
        dest = dest.expanduser().resolve()
        dest.mkdir(parents=True, exist_ok=True)

        # Inject token into the HTTPS URL.
        url = repo.url
        if url.startswith("https://"):
            url = f"https://{self._token}@{url[len('https://'):]}"

        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        gitpython.Repo.clone_from(url, str(dest), env=env, depth=1)
        return dest

    async def search_code(self, query: str) -> list[CodeMatch]:
        """Search code on GitHub, respecting rate-limit responses."""
        q = f"{query}{self._org_qualifier()}"
        page = 1
        matches: list[CodeMatch] = []

        while True:
            response = await self._get_with_rate_limit_retry(
                "/search/code",
                params={"q": q, "per_page": 100, "page": page},
            )
            data = response.json()
            items: list[dict] = data.get("items", [])
            if not items:
                break

            for item in items:
                repo_name: str = item.get("repository", {}).get("full_name", "")
                file_path: str = item.get("path", "")
                # GitHub code search does not return line numbers; default to 1.
                text_matches: list[dict] = item.get("text_matches", [])
                for tm in text_matches:
                    fragment: str = tm.get("fragment", "")
                    for line in fragment.splitlines():
                        if query.lower() in line.lower():
                            matches.append(
                                CodeMatch(
                                    repo_id=repo_name,
                                    file_path=file_path,
                                    line_number=1,
                                    line_content=line.strip(),
                                )
                            )
                            break
                else:
                    # No text_matches available (requires Accept: application/vnd.github.text-match+json)
                    matches.append(
                        CodeMatch(
                            repo_id=repo_name,
                            file_path=file_path,
                            line_number=1,
                            line_content="",
                        )
                    )

            total_count: int = data.get("total_count", 0)
            if page * 100 >= total_count or len(items) < 100:
                break
            page += 1

        return matches

    async def aclose(self) -> None:
        if self._http_client is not None:
            await self._http_client.aclose()

    async def __aenter__(self) -> "GitHubAdapter":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()
