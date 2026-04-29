"""SentinelAdapter — Microsoft Azure Sentinel / Microsoft Defender for Cloud backend."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from ai_recon.adapters.siem.base import DetectionRule, LogEvent

logger = logging.getLogger(__name__)

_ARM_BASE = "https://management.azure.com"
_LA_BASE = "https://api.loganalytics.io/v1"
_API_VERSION = "2023-02-01"


class SentinelAdapter:
    """Microsoft Sentinel adapter using the Azure REST API.

    Args:
        workspace_id:      Log Analytics workspace GUID.
        subscription_id:   Azure subscription ID.
        resource_group:    Resource group name.
        auth_strategy:     Auth strategy whose ``apply()`` method injects the Bearer
                           token into request headers.
        secrets:           Optional secrets adapter (used by auth_strategy).
    """

    def __init__(
        self,
        workspace_id: str,
        subscription_id: str,
        resource_group: str,
        auth_strategy: Any,
        secrets: Any | None = None,
    ) -> None:
        self._workspace_id = workspace_id
        self._subscription_id = subscription_id
        self._resource_group = resource_group
        self._auth_strategy = auth_strategy
        self._secrets = secrets
        self._http_client: httpx.AsyncClient | None = None

    def _client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    def _arm_rules_url(self) -> str:
        ws = self._workspace_id
        sub = self._subscription_id
        rg = self._resource_group
        return (
            f"{_ARM_BASE}/subscriptions/{sub}/resourceGroups/{rg}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
            f"/providers/Microsoft.SecurityInsights/alertRules"
            f"?api-version={_API_VERSION}"
        )

    async def _get_json(self, url: str, **params: Any) -> Any:
        client = self._client()
        request = client.build_request("GET", url, params=params)
        if self._auth_strategy is not None:
            request = self._auth_strategy.apply(request)
        response = await client.send(request)
        response.raise_for_status()
        return response.json()

    async def _post_json(self, url: str, json_body: dict) -> Any:
        client = self._client()
        request = client.build_request("POST", url, json=json_body)
        if self._auth_strategy is not None:
            request = self._auth_strategy.apply(request)
        response = await client.send(request)
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # SIEMAdapter interface
    # ------------------------------------------------------------------

    async def list_detection_rules(self) -> list[DetectionRule]:
        """List Sentinel alert rules and map them to DetectionRule objects."""
        data = await self._get_json(self._arm_rules_url())
        rules: list[DetectionRule] = []
        for item in data.get("value", []):
            props: dict = item.get("properties", {})
            rule_id: str = item.get("name", "")
            display_name: str = props.get("displayName", rule_id)
            query: str = props.get("query", "")
            severity: str = props.get("severity", "medium").lower()
            enabled: bool = props.get("enabled", True)
            tactics: list[str] = props.get("tactics", [])
            rules.append(
                DetectionRule(
                    id=rule_id,
                    name=display_name,
                    query_language="kusto",
                    query=query,
                    severity=severity,
                    enabled=enabled,
                    tags=tactics,
                )
            )
        return rules

    async def search(self, query: str, since: datetime) -> list[LogEvent]:
        """Execute a KQL query against the Log Analytics workspace."""
        since_iso = since.astimezone(timezone.utc).isoformat()
        url = f"{_LA_BASE}/workspaces/{self._workspace_id}/query"
        # Append time filter to the KQL query.
        kql = f"{query}\n| where TimeGenerated >= datetime('{since_iso}')"
        body = {"query": kql}
        data = await self._post_json(url, json_body=body)

        events: list[LogEvent] = []
        for table in data.get("tables", []):
            columns: list[dict] = table.get("columns", [])
            col_names = [c.get("name", "") for c in columns]
            for row in table.get("rows", []):
                fields = dict(zip(col_names, row))
                ts_raw = fields.get("TimeGenerated", "")
                try:
                    ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    ts = datetime.now(tz=timezone.utc)
                events.append(
                    LogEvent(
                        index=table.get("name", ""),
                        timestamp=ts,
                        fields=fields,
                    )
                )
        return events

    async def index_patterns(self) -> list[str]:
        """Return the well-known Sentinel table names."""
        return ["SecurityAlert", "SecurityEvent", "Syslog"]

    async def aclose(self) -> None:
        if self._http_client is not None:
            await self._http_client.aclose()

    async def __aenter__(self) -> "SentinelAdapter":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()
