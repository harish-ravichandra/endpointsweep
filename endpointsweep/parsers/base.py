"""Shared normalisation helpers for client-config parsers.

Every parser turns a client-specific config blob into ``list[MCPServer]``.
The blob arrives from a collector as *raw JSON already on disk in the client's
own shape* — normalisation lives here, in Python, where it is testable, rather
than in the constrained shell collectors.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ..schema import MCPServer, MCPTool, Transport

#: Variable NAMES whose shape suggests they carry a credential.
#: Used against names only — EndpointSweep never sees values.
KEY_SHAPED_NAME = re.compile(
    r"(API[_-]?KEY|ACCESS[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?"
    r"|PRIVATE[_-]?KEY|AUTH|BEARER|SESSION[_-]?KEY|CLIENT[_-]?SECRET|_PAT$|^PAT$"
    r"|_KEY$|^KEY$)",
    re.IGNORECASE,
)

#: Keys a client config may use to hold the server map.
SERVER_MAP_KEYS = ("mcpServers", "mcp_servers", "servers", "modelContextProtocolServers")

#: Keys a client config may use to hold auto-approved tool names.
AUTO_APPROVE_KEYS = ("autoApprove", "alwaysAllow", "auto_approve", "autoApproveTools")

#: A URL path segment this shape is a bearer token, not a route. Remote MCP
#: endpoints routinely embed the session secret in the path, so the same red
#: line that covers env values has to cover URLs (brief §4.3).
_SECRET_SEGMENT = re.compile(r"^(?:[A-Fa-f0-9]{16,}|[A-Za-z0-9_-]{24,})$")
_SECRET_QUERY_KEY = re.compile(r"(key|token|secret|auth|sig|signature|password|access)", re.I)


def redact_url_secrets(url: str) -> tuple[str, bool]:
    """Strip credential-shaped material from a URL, keeping its shape.

    Returns the sanitised URL and whether anything was removed — the fact that
    a server authenticates via a URL secret is itself a finding-worthy signal.
    """
    if not url:
        return "", False
    parsed = urlsplit(url)
    redacted = False

    netloc = parsed.netloc
    if "@" in netloc:  # user:password@host
        netloc = netloc.rsplit("@", 1)[1]
        redacted = True

    segments = []
    for segment in parsed.path.split("/"):
        if segment and _SECRET_SEGMENT.match(segment):
            segments.append("<redacted>")
            redacted = True
        else:
            segments.append(segment)

    query_parts = []
    for pair in parsed.query.split("&"):
        if not pair:
            continue
        name, sep, _value = pair.partition("=")
        if sep and _SECRET_QUERY_KEY.search(name):
            query_parts.append(f"{name}=<redacted>")
            redacted = True
        else:
            query_parts.append(pair)

    return urlunsplit(
        (parsed.scheme, netloc, "/".join(segments), "&".join(query_parts), "")
    ), redacted


def key_shaped_names(names: list[str]) -> list[str]:
    """Filter variable names down to the credential-shaped ones."""
    return [n for n in names if KEY_SHAPED_NAME.search(n)]


def detect_transport(entry: dict[str, Any]) -> Transport:
    declared = str(entry.get("type") or entry.get("transport") or "").lower()
    if declared in ("stdio", "http", "sse"):
        return Transport(declared)
    if declared in ("streamable-http", "streamablehttp", "http-stream"):
        return Transport.HTTP
    url = str(entry.get("url") or entry.get("serverUrl") or "")
    if url:
        return Transport.SSE if "sse" in url.lower() else Transport.HTTP
    if entry.get("command"):
        return Transport.STDIO
    return Transport.UNKNOWN


def _tool_list(entry: dict[str, Any], server_name: str) -> list[MCPTool]:
    """Pick up a client's cached tool list, if the config carries one."""
    tools: list[MCPTool] = []
    raw = entry.get("tools") or entry.get("cachedTools") or []
    if isinstance(raw, dict):
        raw = [{"name": k, **(v if isinstance(v, dict) else {})} for k, v in raw.items()]
    if not isinstance(raw, list):
        return tools
    for item in raw:
        if isinstance(item, str):
            tools.append(MCPTool(name=item, server=server_name))
        elif isinstance(item, dict):
            tools.append(
                MCPTool(
                    name=str(item.get("name", "")),
                    description=str(item.get("description", "") or ""),
                    server=server_name,
                )
            )
    return tools


def _str_list(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(x) for x in raw]
    if isinstance(raw, str):
        return [raw]
    return []


def normalize_server(
    name: str,
    entry: Any,
    *,
    client: str,
    config_path: str,
    user: str = "",
    elevated_scope: bool = False,
    command_index: dict[str, dict[str, str]] | None = None,
) -> MCPServer:
    """Normalise one server entry into the canonical :class:`MCPServer`.

    ``command_index`` is the collector's ``command_index`` map: resolved path
    and mode for binaries it was able to stat, keyed by the command string.
    """
    if not isinstance(entry, dict):
        entry = {}

    command = str(entry.get("command") or "")
    args = _str_list(entry.get("args"))

    # env is the one place a client config holds real secrets. We read the
    # KEYS of the mapping and drop the mapping itself on the floor, here, at
    # the boundary — nothing downstream ever sees it.
    env_block = entry.get("env")
    env_var_names = sorted(str(k) for k in env_block) if isinstance(env_block, dict) else []

    auto: list[str] = []
    for key in AUTO_APPROVE_KEYS:
        auto.extend(_str_list(entry.get(key)))

    resolved = (command_index or {}).get(command, {})
    url, url_had_secret = redact_url_secrets(str(entry.get("url") or entry.get("serverUrl") or ""))

    return MCPServer(
        name=str(name),
        client=client,
        config_path=config_path,
        user=user,
        transport=detect_transport(entry),
        command=command,
        args=args,
        env_var_names=env_var_names,
        url=url,
        url_carries_secret=url_had_secret,
        disabled=bool(entry.get("disabled") or entry.get("enabled") is False),
        elevated_scope=elevated_scope,
        command_path=str(resolved.get("path", "") or entry.get("commandPath", "")),
        command_mode=str(resolved.get("mode", "") or entry.get("commandMode", "")),
        tools=_tool_list(entry, str(name)),
        auto_approved_tools=sorted(set(auto)),
    )


def servers_from_map(
    server_map: Any,
    *,
    client: str,
    config_path: str,
    user: str = "",
    elevated_scope: bool = False,
    command_index: dict[str, dict[str, str]] | None = None,
) -> list[MCPServer]:
    """Normalise either ``{name: entry}`` or ``[{name: ..., ...}]`` shapes."""
    out: list[MCPServer] = []
    if isinstance(server_map, dict):
        items = list(server_map.items())
    elif isinstance(server_map, list):
        items = [(str(e.get("name", f"server_{i}")), e) for i, e in enumerate(server_map) if isinstance(e, dict)]
    else:
        return out
    for name, entry in items:
        out.append(
            normalize_server(
                name,
                entry,
                client=client,
                config_path=config_path,
                user=user,
                elevated_scope=elevated_scope,
                command_index=command_index,
            )
        )
    return out


def find_server_maps(node: Any, depth: int = 0) -> list[Any]:
    """Depth-first search for anything that looks like an MCP server map."""
    found: list[Any] = []
    if depth > 6 or not isinstance(node, dict):
        return found
    for key in SERVER_MAP_KEYS:
        if key in node:
            found.append(node[key])
    for key, val in node.items():
        if key in SERVER_MAP_KEYS:
            continue
        if isinstance(val, dict):
            found.extend(find_server_maps(val, depth + 1))
    return found
