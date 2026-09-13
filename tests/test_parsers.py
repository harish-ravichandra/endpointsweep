"""Each client config shape must normalise into the same MCPServer model."""

from __future__ import annotations

import json

from endpointsweep.parsers import parse_client_config, parse_collector_output
from endpointsweep.parsers.base import redact_url_secrets
from endpointsweep.schema import Transport

from helpers import CONFIGS, config_block


def servers_by_name(servers):
    return {s.name: s for s in servers}


def test_claude_desktop_clean_config():
    servers = servers_by_name(
        parse_client_config(config_block("claude_desktop_config.clean.json", client="claude_desktop"))
    )
    assert set(servers) == {"filesystem", "time"}
    assert servers["filesystem"].command == "npx"
    assert servers["filesystem"].transport is Transport.STDIO
    assert servers["time"].args == ["mcp-server-time==0.4.1"]


def test_claude_code_includes_per_project_servers():
    servers = servers_by_name(
        parse_client_config(config_block("claude_code_projects.json", client="claude_code"))
    )
    assert set(servers) == {"memory", "project-db"}
    assert "#projects/" in servers["project-db"].config_path


def test_env_values_are_dropped_at_the_parser_boundary():
    block = config_block("claude_desktop_config.dirty.json", client="claude_desktop")
    block["raw"]["mcpServers"]["github"]["env"]["GITHUB_PERSONAL_ACCESS_TOKEN"] = "ghp_realsecret"
    servers = servers_by_name(parse_client_config(block))
    github = servers["github"]
    assert github.env_var_names == ["GITHUB_PERSONAL_ACCESS_TOKEN", "LOG_LEVEL"]
    assert "ghp_realsecret" not in json.dumps(github, default=str)


def test_cursor_remote_server_transport_and_url_redaction():
    servers = servers_by_name(parse_client_config(config_block("cursor_mcp.json", client="cursor")))
    remote = servers["remote-crm"]
    assert remote.transport is Transport.SSE
    assert remote.url_carries_secret is True
    assert "7f3c9a41b2e84d6597c0aa13be55d802" not in remote.url
    assert remote.url.startswith("https://crm-mcp.example.com/mcp/<redacted>")


def test_vscode_nested_mcp_servers():
    raw = json.loads(
        (CONFIGS / "vscode_settings.jsonc").read_text(encoding="utf-8")
        .replace("// VS Code settings are JSONC: comments and trailing commas are legal here", "")
        .replace("/* block comments too */", "")
        .replace('"args": ["mcp-server-fetch"],', '"args": ["mcp-server-fetch"]')
        .replace('},\n    }', '}\n    }')
    )
    servers = servers_by_name(
        parse_client_config({"client": "vscode", "path": "settings.json", "raw": raw})
    )
    assert set(servers) == {"fetch", "docs"}
    assert servers["docs"].transport is Transport.HTTP


def test_cline_tools_and_auto_approve():
    servers = servers_by_name(
        parse_client_config(config_block("cline_mcp_settings.poisoned.json", client="cline"))
    )
    notes = servers["notes"]
    assert notes.auto_approved_tools == ["read_file"]
    assert {t.name for t in notes.tools} == {"read_file", "list_notes"}


def test_continue_experimental_shape():
    servers = parse_client_config(config_block("continue_config.json", client="continue"))
    assert len(servers) == 1
    assert servers[0].command == "npx"
    assert servers[0].transport is Transport.STDIO


def test_generic_parser_finds_a_nested_server_map():
    block = {
        "client": "generic",
        "path": "/home/alex/.config/some-tool/mcp.json",
        "raw": {"integrations": {"ai": {"mcpServers": {"x": {"command": "node", "args": ["s.js"]}}}}},
    }
    servers = parse_client_config(block)
    assert [s.name for s in servers] == ["x"]


def test_unknown_client_falls_back_to_generic():
    block = {"client": "brand-new-ide", "path": "/x", "raw": {"mcpServers": {"y": {"command": "uvx"}}}}
    assert [s.name for s in parse_client_config(block)] == ["y"]


def test_collector_output_tolerates_single_object_arrays():
    """PowerShell 5.1 can collapse a one-element array into a bare object."""
    data = {
        "host": {"hostname": "w1", "os": "windows"},
        "client_configs": {"client": "cursor", "path": "C:/x", "raw": {"mcpServers": {"a": {"command": "npx"}}}},
        "agentic_tools": {"name": "claude", "path": "C:/y"},
    }
    inv = parse_collector_output(data)
    assert len(inv.mcp_servers) == 1
    assert len(inv.agentic_tools) == 1


def test_elevated_flag_derived_from_collector_uid():
    inv = parse_collector_output({"host": {"hostname": "h", "os": "linux", "collector_uid": 0}})
    assert inv.host.elevated is True


def test_url_redaction_keeps_useful_shape():
    assert redact_url_secrets("http://localhost:3000/sse") == ("http://localhost:3000/sse", False)
    assert redact_url_secrets("https://u:p@api.example.com/mcp")[0] == "https://api.example.com/mcp"
    assert redact_url_secrets("https://x.io/a?token=abc&mode=1")[0] == "https://x.io/a?token=<redacted>&mode=1"
