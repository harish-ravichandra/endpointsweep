"""Parser for Cursor and Windsurf ``mcp.json`` files.

Both use ``{"mcpServers": {...}}``; Windsurf additionally allows a
``serverUrl`` key for remote servers, which ``base.normalize_server`` handles.
"""

from __future__ import annotations

from typing import Any

from ..schema import MCPServer
from .base import servers_from_map

CLIENTS = ("cursor", "windsurf")


def parse(block: dict[str, Any]) -> list[MCPServer]:
    raw = block.get("raw") or {}
    return servers_from_map(
        raw.get("mcpServers") or raw.get("servers"),
        client=block.get("client", "cursor"),
        config_path=block.get("path", ""),
        user=block.get("user", ""),
        elevated_scope=bool(block.get("elevated_scope")),
        command_index=block.get("command_index") or {},
    )
