"""Collector output → :class:`~endpointsweep.schema.HostInventory`.

Dispatches each client-config block to the parser that knows that client's
shape, falling back to :mod:`generic_mcp` for anything unrecognised.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..schema import (
    OS,
    AgenticTool,
    CollectorError,
    EnvKeySignal,
    HostInventory,
    HostMeta,
    IDEExtension,
    MCPServer,
    ModelRuntime,
    PackageManifest,
    _build,
    _enum_from,
)
from . import claude_desktop, cursor, generic_mcp, vscode

ParserFn = Callable[[dict[str, Any]], list[MCPServer]]

_REGISTRY: dict[str, ParserFn] = {}
for _module in (claude_desktop, cursor, vscode, generic_mcp):
    for _client in _module.CLIENTS:
        _REGISTRY[_client] = _module.parse


def parser_for(client: str) -> ParserFn:
    return _REGISTRY.get(str(client).lower(), generic_mcp.parse)


def parse_client_config(block: dict[str, Any]) -> list[MCPServer]:
    """Parse one ``client_configs`` entry from collector output."""
    if not block.get("raw"):
        return []
    servers = parser_for(block.get("client", ""))(block)
    if not servers and block.get("client") != "generic":
        # A known client whose config moved: try the shape-agnostic path
        # before deciding there is nothing there.
        servers = generic_mcp.parse(block)
    return servers


def _as_list(raw: Any) -> list[Any]:
    """Tolerate a single object where an array is expected.

    PowerShell 5.1's ``ConvertTo-Json`` can collapse a one-element collection
    into a bare object; the analyzer must not lose a host's only MCP server to
    a serialiser quirk.
    """
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return [raw]
    return []


def _dedupe(servers: list[MCPServer]) -> list[MCPServer]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[MCPServer] = []
    for s in servers:
        key = (s.user, s.client, s.config_path, s.name)
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def parse_collector_output(data: dict[str, Any], *, source_path: str = "") -> HostInventory:
    """Build a :class:`HostInventory` from one collector's JSON document."""
    raw_host = dict(data.get("host") or {})
    raw_host["os"] = _enum_from(OS, raw_host.get("os"), OS.UNKNOWN)
    if raw_host.get("collector_uid") is not None:
        raw_host["elevated"] = bool(raw_host.get("elevated") or raw_host["collector_uid"] == 0)
    host = _build(HostMeta, raw_host)

    servers: list[MCPServer] = []
    for block in _as_list(data.get("client_configs")):
        if isinstance(block, dict):
            servers.extend(parse_client_config(block))

    return HostInventory(
        host=host,
        mcp_servers=_dedupe(servers),
        agentic_tools=[_build(AgenticTool, r) for r in _as_list(data.get("agentic_tools"))],
        model_runtimes=[_build(ModelRuntime, r) for r in _as_list(data.get("model_runtimes"))],
        ide_extensions=[_build(IDEExtension, r) for r in _as_list(data.get("ide_extensions"))],
        package_manifests=[_build(PackageManifest, r) for r in _as_list(data.get("package_manifests"))],
        env_key_signals=[_build(EnvKeySignal, r) for r in _as_list(data.get("env_key_signals"))],
        errors=[_build(CollectorError, r) for r in _as_list(data.get("errors"))],
        source_path=source_path,
    )


__all__ = [
    "parse_client_config",
    "parse_collector_output",
    "parser_for",
]
