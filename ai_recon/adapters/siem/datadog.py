"""DatadogAdapter — Datadog Security Monitoring backend."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from ai_recon.adapters.siem.base import DetectionRule, LogEvent

logger = logging.getLogger(__name__)


class DatadogAdapter:
    """Datadog Security Monitoring adapter.

    Args:
        api_key_ref:  Secret ref for the Datadog API key (DD-API-KEY header).
        app_key_ref:  Secret ref for the Datadog application key (DD-APPLICATION-KEY header).
        site:         Datadog site, e.g. ``datadoghq.com`` (default) or ``datadoghq.eu``.
        secrets:      SecretsAdapter used to resolve credential refs.
    """

    def __init__(
        self,
        api_key_ref: str,
        app_key_ref: str,
        site: str = "datadoghq.com",
        secrets: Any | None = None,
    ) -> None:
        self._site = site.rstrip("/")
        self._api_base = f"https://api.{self._site}"
        api_key = secrets.resolve(api_key_ref) if secrets else ""
        app_key = secrets.resolve(app_key_ref) if secrets else ""
        self._headers = {
            "DD-API-KEY": api_key,
            "DD-APPLICATION-KEY": app_key,
            "Content-Type": "application/json",
        }
        self._http_client: httpx.AsyncClient | None = None

    def _client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                headers=self._headers,
                timeout=30.0,
            )
        return self._http_client

    # ------------------------------------------------------------------
    # SIEMAdapter interface
    # ------------------------------------------------------------------

    async def list_detection_rules(self) -> list[DetectionRule]:
        """List Datadog Security Monitoring detection rules (paginated)."""
        client = self._client()
        rules: list[DetectionRule] = []
        page_number = 0
        page_size = 100

        while True:
            response = await client.get(
                f"{self._api_base}/api/v2/security_monitoring/rules",
                params={"page[size]": page_size, "page[number]": page_number},
            )
            response.raise_for_status()
            data = response.json()
            items: list[dict] = data.get("data", [])
            for item in items:
                attrs: dict = item.get("attributes", {})
                cases: list[dict] = attrs.get("cases", [])
                severity = "low"
                if cases:
                    severity = cases[0].get("status", "low").lower()
                # Datadog uses CSPM/log detection; treat query language as kql-like.
                queries: list[dict] = attrs.get("queries", [])
                query_str = " ".join(q.get("query", "") for q in queries).strip()
                tags: list[str] = attrs.get("tags", [])
                rules.append(
                    DetectionRule(
                        id=item.get("id", ""),
                        name=attrs.get("name", ""),
                        query_language="kql",
                        query=query_str,
                        severity=severity,
                        enabled=attrs.get("isEnabled", True),
                        tags=tags,
                    )
                )
            # Datadog paginates with meta.page.total_count or simply stops when empty.
            meta = data.get("meta", {})
            total = meta.get("page", {}).get("totalCount", len(items))
            page_number += 1
            if page_number * page_size >= total or not items:
                break

        return rules

    async def search(self, query: str, since: datetime) -> list[LogEvent]:
        """Search Datadog logs using the Logs Search API v2."""
        since_iso = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        now_iso = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        body = {
            "filter": {
                "query": query,
                "from": since_iso,
                "to": now_iso,
            },
            "page": {"limit": 500},
            "sort": "timestamp",
        }
        client = self._client()
        response = await client.post(
            f"{self._api_base}/api/v2/logs/events/search",
            json=body,
        )
        response.raise_for_status()
        data = response.json()

        events: list[LogEvent] = []
        for item in data.get("data", []):
            attrs: dict = item.get("attributes", {})
            ts_raw: str = attrs.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                ts = datetime.now(tz=timezone.utc)
            events.append(
                LogEvent(
                    index=attrs.get("service", item.get("id", "")),
                    timestamp=ts,
                    fields=attrs,
                )
            )
        return events

    async def index_patterns(self) -> list[str]:
        """Datadog has no index concept; return the universal wildcard."""
        return ["*"]

    async def aclose(self) -> None:
        if self._http_client is not None:
            await self._http_client.aclose()

    async def __aenter__(self) -> "DatadogAdapter":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()
