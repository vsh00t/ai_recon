"""MCP enumeration technique — detects MCP servers and enumerates tools/resources/prompts."""
from __future__ import annotations

import re
from typing import Any, ClassVar

import httpx

from ai_recon.core.models import Finding, RunContext, Target
from ai_recon.core.errors import TechniqueAborted
from ai_recon.techniques.base import Technique

_DANGEROUS_KEYWORDS: list[str] = [
    "exec", "run", "shell", "filesystem", "write", "delete",
    "http_request", "browse", "bash", "command", "subprocess",
    "os_", "file_", "create_file", "read_file", "send_email",
]

_MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}


def _is_dangerous(tool: dict) -> bool:
    """Return True if tool name or description contains dangerous capability keywords."""
    name = (tool.get("name") or "").lower()
    description = (tool.get("description") or "").lower()
    combined = name + " " + description
    return any(kw in combined for kw in _DANGEROUS_KEYWORDS)


async def _jsonrpc(
    client: httpx.AsyncClient,
    url: str,
    method: str,
    request_id: int,
    params: dict | None = None,
) -> dict:
    payload: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params or {},
    }
    resp = await client.post(url, json=payload, headers=_MCP_HEADERS, timeout=10.0)
    resp.raise_for_status()
    return resp.json()


class MCPEnum(Technique):
    id: ClassVar[str] = "active.mcp_enum"
    intrusiveness: ClassVar[str] = "low"
    produces: ClassVar[set[str]] = {"mcp.tools", "mcp.resources"}

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        mcp_url = target.base_url.rstrip("/")

        async with httpx.AsyncClient(timeout=15.0) as client:
            # ── Step 1: MCP initialize ───────────────────────────────────────
            try:
                init_resp = await _jsonrpc(
                    client,
                    mcp_url,
                    "initialize",
                    1,
                    {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "ai-recon", "version": "0.1.0"},
                    },
                )
            except Exception as exc:
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="low",
                        title="MCP server not detected (initialize failed)",
                        evidence={"error": str(exc)},
                        references=[],
                    )
                )
                return findings

            result = init_resp.get("result", {})
            if "protocolVersion" not in result:
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="low",
                        title="MCP server not detected (no protocolVersion in response)",
                        evidence={"response": init_resp},
                        references=[],
                    )
                )
                return findings

            protocol_version = result.get("protocolVersion", "unknown")
            server_info = result.get("serverInfo", {})
            capabilities = result.get("capabilities", {})

            # ── Step 2: tools/list ───────────────────────────────────────────
            tools: list[dict] = []
            try:
                tools_resp = await _jsonrpc(client, mcp_url, "tools/list", 2)
                tools = tools_resp.get("result", {}).get("tools", [])
            except Exception:
                pass

            # ── Step 3: resources/list ───────────────────────────────────────
            resources: list[dict] = []
            try:
                res_resp = await _jsonrpc(client, mcp_url, "resources/list", 3)
                resources = res_resp.get("result", {}).get("resources", [])
            except Exception:
                pass

            # ── Step 4: prompts/list ─────────────────────────────────────────
            prompts: list[dict] = []
            try:
                prompts_resp = await _jsonrpc(client, mcp_url, "prompts/list", 4)
                prompts = prompts_resp.get("result", {}).get("prompts", [])
            except Exception:
                pass

        # ── Main detection finding ───────────────────────────────────────────
        findings.append(
            self._make_finding(
                target,
                severity="medium",
                confidence="high",
                title=f"MCP server detected: {len(tools)} tools, {len(resources)} resources",
                evidence={
                    "protocol_version": protocol_version,
                    "server_info": server_info,
                    "capabilities": capabilities,
                    "tools": tools,
                    "resources": resources,
                    "prompts": prompts,
                    "tool_count": len(tools),
                    "resource_count": len(resources),
                    "prompt_count": len(prompts),
                },
                references=[
                    "https://modelcontextprotocol.io/specification",
                ],
            )
        )

        # ── Dangerous tool findings ──────────────────────────────────────────
        for tool in tools:
            if _is_dangerous(tool):
                tool_name = tool.get("name", "unknown")
                findings.append(
                    self._make_finding(
                        target,
                        severity="high",
                        confidence="medium",
                        title=f"Dangerous MCP tool: {tool_name}",
                        evidence={
                            "tool": tool,
                            "tool_name": tool_name,
                            "matched_keywords": [
                                kw for kw in _DANGEROUS_KEYWORDS
                                if kw in (tool.get("name", "") + " " + tool.get("description", "")).lower()
                            ],
                        },
                        references=[
                            "https://modelcontextprotocol.io/specification",
                            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                        ],
                    )
                )

        return findings
