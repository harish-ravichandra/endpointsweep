"""Fallback parser for unknown or ad-hoc MCP config files.

Covers the ``~/.config/**/mcp*.json`` long tail: any JSON document that
contains something shaped like a server map, at any reasonable nesting depth.
"""

from __future__ import annotations

from typing import Any

from ..schema import MCPServer
from .base import find_server_maps, servers_from_map

CLIENTS = ("generic",)


def parse(block: dict[str, Any]) -> list[MCPServer]:
    raw = block.get("raw") or {}
    if not isinstance(raw, dict):
        return []
    common = {
        "client": block.get("client", "generic"),
        "config_path": block.get("path", ""),
        "user": block.get("user", ""),
        "elevated_scope": bool(block.get("elevated_scope")),
        "command_index": block.get("command_index") or {},
    }
    servers: list[MCPServer] = []
    for server_map in find_server_maps(raw):
        servers.extend(servers_from_map(server_map, **common))
    return servers
