"""BitbucketAdapter — Bitbucket Cloud API 2.0 repository adapter."""
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

_BITBUCKET_API = "https://api.bitbucket.org/2.0"


class BitbucketAdapter:
    """Bitbucket Cloud repository adapter using Bitbucket API 2.0.

    Args:
        workspace:     Bitbucket workspace slug.
        username_ref:  Secret ref for the Bitbucket username / OAuth consumer key.
        password_ref:  Secret ref for the Bitbucket app password.
        secrets:       SecretsAdapter used to resolve credential refs.
    """

    def __init__(
        self,
        workspace: str,
        username_ref: str,
        password_ref: str,
        secrets: Any,
    ) -> None:
        self._workspace = workspace
        username = secrets.resolve(username_ref)
        password = secrets.resolve(password_ref)
        self._auth = (username, password)
        self._http_client: httpx.AsyncClient | None = None

    def _client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                auth=self._auth,
                headers={"Accept": "application/json"},
                timeout=30.0,
            )
        return self._http_client

    def _clone_url_with_auth(self, repo: RepoRef) -> str:
        """Inject app-password credentials into the HTTPS clone URL."""
        url = repo.url
        username, password = self._auth
        if url.startswith("https://"):
            return f"https://{username}:{password}@{url[len('https://'):]}"
        return url

    # ------------------------------------------------------------------
    # RepoAdapter interface
    # ------------------------------------------------------------------

    async def search_repos(self, keywords: list[str]) -> list[RepoRef]:
        """Search repositories in *workspace* whose names contain each keyword."""
        client = self._client()
        seen: set[str] = set()
        repos: list[RepoRef] = []

        for keyword in keywords:
            url = f"{_BITBUCKET_API}/repositories/{self._workspace}"
            params: dict[str, Any] = {"q": f'name~"{keyword}"', "pagelen": 100}

            while url:
                response = await client.get(url, params=params)
                response.raise_for_status()
                data = response.json()

                for repo in data.get("values", []):
                    slug: str = repo.get("slug", "")
                    if slug in seen:
                        continue
                    seen.add(slug)

                    # Pick the HTTPS clone link.
                    clone_links: list[dict] = (
                        repo.get("links", {}).get("clone", [])
                    )
                    clone_url = next(
                        (lnk["href"] for lnk in clone_links if lnk.get("name") == "https"),
                        repo.get("links", {}).get("html", {}).get("href", ""),
                    )
                    main_branch: str = (
                        repo.get("mainbranch", {}).get("name", "main")
                        if isinstance(repo.get("mainbranch"), dict)
                        else "main"
                    )
                    repos.append(
                        RepoRef(
                            id=slug,
                            name=repo.get("full_name", slug),
                            url=clone_url,
                            default_branch=main_branch,
                            description=repo.get("description", "") or "",
                        )
                    )

                # Follow pagination; next page URL may include all params already.
                url = data.get("next", "")  # type: ignore[assignment]
                params = {}  # params are embedded in the 'next' URL

        return repos

    async def clone(self, repo: RepoRef, dest: Path) -> Path:
        """Clone *repo* using GitPython with app-password credentials in the URL."""
        if not _HAS_GITPYTHON:
            raise RuntimeError(
                "GitPython is required for BitbucketAdapter.clone(). "
                "Install it with: pip install gitpython"
            )
        dest = dest.expanduser().resolve()
        dest.mkdir(parents=True, exist_ok=True)
        url = self._clone_url_with_auth(repo)
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        gitpython.Repo.clone_from(url, str(dest), env=env, depth=1)
        return dest

    async def search_code(self, query: str) -> list[CodeMatch]:
        """Search code blobs across the workspace using the Bitbucket Code Search API."""
        client = self._client()
        matches: list[CodeMatch] = []
        url: str | None = (
            f"{_BITBUCKET_API}/search/code"
            f"?search_query={query}&workspace={self._workspace}"
        )

        while url:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

            for result in data.get("values", []):
                file_info: dict = result.get("file", {})
                file_path: str = file_info.get("path", "")
                repo_slug: str = (
                    result.get("repository", {}).get("slug", "")
                )
                for match in result.get("content_matches", []):
                    for line_info in match.get("lines", []):
                        line_num: int = line_info.get("line", 1)
                        segments: list[dict] = line_info.get("segments", [])
                        line_content = "".join(seg.get("text", "") for seg in segments)
                        if query.lower() in line_content.lower():
                            matches.append(
                                CodeMatch(
                                    repo_id=repo_slug,
                                    file_path=file_path,
                                    line_number=line_num,
                                    line_content=line_content,
                                )
                            )

            url = data.get("next")  # type: ignore[assignment]

        return matches

    async def aclose(self) -> None:
        if self._http_client is not None:
            await self._http_client.aclose()

    async def __aenter__(self) -> "BitbucketAdapter":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()
