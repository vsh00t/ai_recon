"""KibanaAdapter — Elastic/Kibana SIEM backend."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from ai_recon.adapters.siem.base import DetectionRule, LogEvent

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


class KibanaAdapter:
    """Kibana Detection Engine and Elasticsearch search adapter.

    Args:
        base_url:        Kibana base URL, e.g. ``https://kibana.example.com``.
        auth_strategy:   Optional auth strategy with an ``apply(request)`` method.
        secrets:         Optional secrets adapter used to resolve credentials.
        http_client:     Optional pre-configured ``httpx.AsyncClient``.  If not
                         provided, a new client is created on first use.
    """

    _KBN_XSRF = {"kbn-xsrf": "true"}

    def __init__(
        self,
        base_url: str,
        auth_strategy: Any | None = None,
        secrets: Any | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth_strategy = auth_strategy
        self._secrets = secrets
        self._http_client = http_client
        self._owns_client = http_client is None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                base_url=self._base_url,
                headers=self._KBN_XSRF,
                timeout=30.0,
            )
        return self._http_client

    async def _get(self, path: str, **params: Any) -> Any:
        client = self._client()
        response = await client.get(
            path,
            params={k: v for k, v in params.items() if v is not None},
            headers=self._KBN_XSRF,
        )
        response.raise_for_status()
        return response.json()

    async def _post(self, path: str, json_body: dict) -> Any:
        client = self._client()
        response = await client.post(
            path,
            json=json_body,
            headers=self._KBN_XSRF,
        )
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # SIEMAdapter interface
    # ------------------------------------------------------------------

    async def list_detection_rules(self) -> list[DetectionRule]:
        """Fetch all detection rules via paginated GET /api/detection_engine/rules/_find."""
        rules: list[DetectionRule] = []
        page = 1
        per_page = 100

        while True:
            data = await self._get(
                "/api/detection_engine/rules/_find",
                page=page,
                per_page=per_page,
            )
            hits: list[dict] = data.get("data", [])
            for hit in hits:
                rules.append(self._parse_rule(hit))

            total: int = data.get("total", 0)
            if page * per_page >= total or not hits:
                break
            page += 1

        return rules

    def _parse_rule(self, hit: dict) -> DetectionRule:
        severity_raw = hit.get("severity", "low").lower()
        severity = _SEVERITY_MAP.get(severity_raw, severity_raw)

        # Kibana rules can be eql, query (KQL/Lucene), threshold, etc.
        # Map language field; default to "kql".
        lang_map = {
            "kuery": "kql",
            "kql": "kql",
            "lucene": "lucene",
            "eql": "kql",  # closest approximation
        }
        raw_lang = hit.get("language", "kuery").lower()
        query_language = lang_map.get(raw_lang, "kql")  # type: ignore[assignment]

        return DetectionRule(
            id=hit.get("id", ""),
            name=hit.get("name", ""),
            query_language=query_language,  # type: ignore[arg-type]
            query=hit.get("query", ""),
            severity=severity,
            enabled=hit.get("enabled", True),
            tags=hit.get("tags", []),
        )

    async def search(self, query: str, since: datetime) -> list[LogEvent]:
        """Run a KQL search via Kibana console proxy."""
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
            "/api/console/proxy?path=*/_search&method=POST",
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
                    index=hit.get("_index", ""),
                    timestamp=ts,
                    fields=source,
                )
            )
        return events

    async def index_patterns(self) -> list[str]:
        """Return all Kibana index pattern titles."""
        data = await self._get("/api/index_patterns")
        patterns = data.get("index_pattern", data) if isinstance(data, dict) else data
        if isinstance(patterns, dict):
            # Some Kibana versions wrap in {"index_pattern": [...]}
            patterns = patterns.get("index_pattern", [])
        titles: list[str] = []
        for item in patterns:
            if isinstance(item, dict):
                title = item.get("title") or item.get("name") or item.get("id", "")
                if title:
                    titles.append(title)
            elif isinstance(item, str):
                titles.append(item)
        return titles

    async def aclose(self) -> None:
        if self._owns_client and self._http_client is not None:
            await self._http_client.aclose()

    async def __aenter__(self) -> "KibanaAdapter":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()
