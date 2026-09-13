"""Parsers for VS Code-family MCP hosts: native MCP, Cline, Continue, Copilot.

- VS Code native / Copilot: ``mcp.json`` or ``settings.json`` → ``servers`` (or
  ``mcp.servers``), entries may carry ``type: stdio|http|sse``.
- Cline: ``cline_mcp_settings.json`` → ``mcpServers`` plus ``disabled`` and
  ``autoApprove``.
- Continue: ``config.json`` → ``experimental.modelContextProtocolServers`` (a
  list, each entry ``{transport: {type, command, args}}``).
"""

from __future__ import annotations

from typing import Any

from ..schema import MCPServer
from .base import normalize_server, servers_from_map

CLIENTS = ("vscode", "copilot", "cline", "continue", "jetbrains")


def _parse_continue(block: dict[str, Any], raw: dict[str, Any]) -> list[MCPServer]:
    experimental = raw.get("experimental") or {}
    entries = experimental.get("modelContextProtocolServers")
    if not isinstance(entries, list):
        return []
    out: list[MCPServer] = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        transport = entry.get("transport") if isinstance(entry.get("transport"), dict) else {}
        merged = {**transport, **{k: v for k, v in entry.items() if k != "transport"}}
        name = str(entry.get("name") or merged.get("command") or f"continue_server_{i}")
        out.append(
            normalize_server(
                name,
                merged,
                client="continue",
                config_path=block.get("path", ""),
                user=block.get("user", ""),
                elevated_scope=bool(block.get("elevated_scope")),
                command_index=block.get("command_index") or {},
            )
        )
    return out


def parse(block: dict[str, Any]) -> list[MCPServer]:
    raw = block.get("raw") or {}
    client = block.get("client", "vscode")
    common = {
        "client": client,
        "config_path": block.get("path", ""),
        "user": block.get("user", ""),
        "elevated_scope": bool(block.get("elevated_scope")),
        "command_index": block.get("command_index") or {},
    }

    servers: list[MCPServer] = []
    servers.extend(servers_from_map(raw.get("mcpServers"), **common))
    servers.extend(servers_from_map(raw.get("servers"), **common))

    # settings.json nests the same map under the "mcp" setting namespace.
    mcp_setting = raw.get("mcp")
    if isinstance(mcp_setting, dict):
        servers.extend(servers_from_map(mcp_setting.get("servers"), **common))
    flat = raw.get("mcp.servers")
    if flat is not None:
        servers.extend(servers_from_map(flat, **common))

    servers.extend(_parse_continue(block, raw))
    return servers
