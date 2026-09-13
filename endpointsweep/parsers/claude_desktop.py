"""Parser for Claude Desktop and Claude Code config files.

Claude Desktop: ``claude_desktop_config.json`` with a top-level ``mcpServers``.
Claude Code: ``~/.claude.json`` / ``.mcp.json`` — same ``mcpServers`` shape, but
``~/.claude.json`` nests per-project server maps under ``projects``.
"""

from __future__ import annotations

from typing import Any

from ..schema import MCPServer
from .base import servers_from_map

CLIENTS = ("claude_desktop", "claude_code")


def parse(block: dict[str, Any]) -> list[MCPServer]:
    raw = block.get("raw") or {}
    common = {
        "client": block.get("client", "claude_desktop"),
        "config_path": block.get("path", ""),
        "user": block.get("user", ""),
        "elevated_scope": bool(block.get("elevated_scope")),
        "command_index": block.get("command_index") or {},
    }
    servers = servers_from_map(raw.get("mcpServers"), **common)

    # Claude Code keeps a per-project map; those servers are just as real.
    projects = raw.get("projects")
    if isinstance(projects, dict):
        for project_path, project in projects.items():
            if not isinstance(project, dict):
                continue
            scoped = dict(common)
            scoped["config_path"] = f"{common['config_path']}#projects/{project_path}"
            servers.extend(servers_from_map(project.get("mcpServers"), **scoped))
    return servers
