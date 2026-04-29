"""ElasticAdapter — direct Elasticsearch SIEM backend."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from ai_recon.adapters.siem.base import DetectionRule, LogEvent

logger = logging.getLogger(__name__)


class ElasticAdapter:
    """Elasticsearch SIEM adapter (7.x+ Detection Engine).

    Args:
        base_url:       Elasticsearch base URL, e.g. ``https://es.example.com:9200``.
        index_pattern:  Index pattern used for search (default ``*``).
        auth_strategy:  Optional auth strategy.
        secrets:        Optional secrets adapter.
    """

    def __init__(
        self,
        base_url: str,
        index_pattern: str = "*",
        auth_strategy: Any | None = None,
        secrets: Any | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._index_pattern = index_pattern
        self._auth_strategy = auth_strategy
        self._secrets = secrets
        self._http_client: httpx.AsyncClient | None = None

    def _client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                base_url=self._base_url,
                headers={"Content-Type": "application/json"},
                timeout=30.0,
            )
        return self._http_client

    async def _get(self, path: str, **params: Any) -> Any:
        client = self._client()
        response = await client.get(
            path,
            params={k: v for k, v in params.items() if v is not None},
        )
        response.raise_for_status()
        return response.json()

    async def _post(self, path: str, json_body: dict) -> Any:
        client = self._client()
        response = await client.post(path, json=json_body)
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # SIEMAdapter interface
    # ------------------------------------------------------------------

    async def list_detection_rules(self) -> list[DetectionRule]:
        """Fetch detection rules from the Elasticsearch Detection Engine (7.x+).

        Falls back to an empty list with a warning if the endpoint is not available
        (e.g. on a cluster without Security / SIEM features enabled).
        """
        try:
            data = await self._get(
                "/_security/detection_engine/rules/_find",
                per_page=100,
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (404, 501):
                logger.warning(
                    "Elasticsearch Detection Engine endpoint not available "
                    "(status %d); returning empty rule list.",
                    exc.response.status_code,
                )
                return []
            raise

        rules: list[DetectionRule] = []
        for hit in data.get("data", []):
            severity_raw = hit.get("severity", "low").lower()
            lang_raw = hit.get("language", "kuery").lower()
            lang_map = {"kuery": "kql", "kql": "kql", "lucene": "lucene"}
            rules.append(
                DetectionRule(
                    id=hit.get("id", ""),
                    name=hit.get("name", ""),
                    query_language=lang_map.get(lang_raw, "kql"),  # type: ignore[arg-type]
                    query=hit.get("query", ""),
                    severity=severity_raw,
                    enabled=hit.get("enabled", True),
                    tags=hit.get("tags", []),
                )
            )
        return rules

    async def search(self, query: str, since: datetime) -> list[LogEvent]:
        """Search documents in *index_pattern* using a query_string query."""
        since_iso = since.astimezone(timezone.utc).isoformat()
        body = {
            "query": {
                "bool": {
                    "must": [
                        {"query_string": {"query": query}},
                        {"range": {"@timestamp": {"gte": since_iso}}},
                    ]
                }
            },
            "size": 500,
        }
        data = await self._post(
            f"/{self._index_pattern}/_search",
            json_body=body,
        )
        events: list[LogEvent] = []
        for hit in data.get("hits", {}).get("hits", []):
            source: dict = hit.get("_source", {})
            ts_raw = source.get("@timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                ts = datetime.now(tz=timezone.utc)
            events.append(
                LogEvent(
                    index=hit.get("_index", self._index_pattern),
                    timestamp=ts,
                    fields=source,
                )
            )
        return events

    async def index_patterns(self) -> list[str]:
        """Return index names via _cat/indices."""
        data = await self._get("/_cat/indices", h="index", format="json")
        return [item["index"] for item in data if "index" in item]

    async def aclose(self) -> None:
        if self._http_client is not None:
            await self._http_client.aclose()

    async def __aenter__(self) -> "ElasticAdapter":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()
