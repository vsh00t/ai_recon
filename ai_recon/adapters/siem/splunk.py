"""SplunkAdapter — Splunk Enterprise REST API backend."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from ai_recon.adapters.siem.base import DetectionRule, LogEvent

logger = logging.getLogger(__name__)

_POLL_INTERVAL = 2.0  # seconds between job status polls
_MAX_POLL_ATTEMPTS = 60


class SplunkAdapter:
    """Splunk Enterprise REST API adapter.

    Args:
        base_url:      Splunk management URL, e.g. ``https://splunk.example.com:8089``.
        username_ref:  Secret ref for the Splunk username.
        password_ref:  Secret ref for the Splunk password.
        secrets:       SecretsAdapter used to resolve credential refs.
    """

    def __init__(
        self,
        base_url: str,
        username_ref: str,
        password_ref: str,
        secrets: Any,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        username = secrets.resolve(username_ref)
        password = secrets.resolve(password_ref)
        self._auth = (username, password)
        self._http_client: httpx.AsyncClient | None = None

    def _client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                base_url=self._base_url,
                auth=self._auth,
                verify=True,
                timeout=30.0,
            )
        return self._http_client

    # ------------------------------------------------------------------
    # SIEMAdapter interface
    # ------------------------------------------------------------------

    async def list_detection_rules(self) -> list[DetectionRule]:
        """Fetch saved searches tagged 'security_detection'."""
        client = self._client()
        response = await client.get(
            "/services/saved/searches",
            params={"output_mode": "json", "count": 0},
        )
        response.raise_for_status()
        data = response.json()

        rules: list[DetectionRule] = []
        for entry in data.get("entry", []):
            content: dict = entry.get("content", {})
            tags: list[str] = []

            # Tags may be stored in metadata or content fields.
            tag_str: str = content.get("tags", "") or ""
            if tag_str:
                tags = [t.strip() for t in tag_str.split(",") if t.strip()]

            # Filter by the security_detection tag.
            if "security_detection" not in tags:
                continue

            severity = content.get("severity", "low") or "low"
            rules.append(
                DetectionRule(
                    id=entry.get("name", ""),
                    name=entry.get("name", ""),
                    query_language="spl",
                    query=content.get("search", ""),
                    severity=severity.lower(),
                    enabled=not content.get("disabled", False),
                    tags=tags,
                )
            )
        return rules

    async def search(self, query: str, since: datetime) -> list[LogEvent]:
        """Submit a search job, poll until complete, and return results."""
        since_epoch = since.astimezone(timezone.utc).timestamp()
        client = self._client()

        # Create the search job.
        create_response = await client.post(
            "/services/search/jobs",
            data={
                "search": f"search {query}" if not query.strip().startswith("search") else query,
                "earliest_time": str(since_epoch),
                "latest_time": "now",
                "output_mode": "json",
            },
        )
        create_response.raise_for_status()
        job_data = create_response.json()
        sid: str = job_data.get("sid", "")
        if not sid:
            logger.warning("Splunk search job creation returned no SID.")
            return []

        # Poll until the job is done.
        for attempt in range(_MAX_POLL_ATTEMPTS):
            status_response = await client.get(
                f"/services/search/jobs/{sid}",
                params={"output_mode": "json"},
            )
            status_response.raise_for_status()
            status = status_response.json()
            dispatch_state: str = (
                status.get("entry", [{}])[0]
                .get("content", {})
                .get("dispatchState", "UNKNOWN")
            )
            if dispatch_state in ("DONE", "FAILED"):
                break
            await asyncio.sleep(_POLL_INTERVAL)
        else:
            logger.warning("Splunk search job %s timed out after polling.", sid)
            return []

        if dispatch_state == "FAILED":
            logger.warning("Splunk search job %s failed.", sid)
            return []

        # Fetch results.
        results_response = await client.get(
            f"/services/search/jobs/{sid}/results",
            params={"output_mode": "json", "count": 0},
        )
        results_response.raise_for_status()
        results_data = results_response.json()

        events: list[LogEvent] = []
        for result in results_data.get("results", []):
            ts_raw: str = result.get("_time", "")
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                ts = datetime.now(tz=timezone.utc)
            index: str = result.get("index", result.get("_index", ""))
            events.append(LogEvent(index=index, timestamp=ts, fields=result))
        return events

    async def index_patterns(self) -> list[str]:
        """Return the list of Splunk indexes."""
        client = self._client()
        response = await client.get(
            "/services/data/indexes",
            params={"output_mode": "json", "count": 0},
        )
        response.raise_for_status()
        data = response.json()
        return [
            entry["name"]
            for entry in data.get("entry", [])
            if "name" in entry
        ]

    async def aclose(self) -> None:
        if self._http_client is not None:
            await self._http_client.aclose()

    async def __aenter__(self) -> "SplunkAdapter":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()
