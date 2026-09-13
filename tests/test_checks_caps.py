"""ES-1xx — capability and scope."""

from __future__ import annotations

from endpointsweep.schema import MCPTool, ModelRuntime, Severity, Transport

from helpers import by_id, ids, make_inventory, make_server, run_checks


def test_shell_interpreter_is_execution_capable():
    inv = make_inventory(mcp_servers=[make_server("shell", command="/bin/bash", args=["-c", "srv.sh"])])
    finding = by_id(run_checks(inv), "ES-101")[0]
    assert finding.severity is Severity.HIGH
    assert "interpreter" in finding.detail


def test_inline_code_flag_counts_as_execution():
    inv = make_inventory(mcp_servers=[make_server("py", command="python3", args=["-c", "import x"])])
    assert "ES-101" in ids(run_checks(inv))


def test_plain_node_script_is_not_execution_capable():
    inv = make_inventory(mcp_servers=[make_server("ok", command="node", args=["/opt/app/server.js"])])
    assert "ES-101" not in ids(run_checks(inv))


def test_auto_approved_execution_escalates_to_critical():
    server = make_server(
        "commander",
        command="npx",
        args=["-y", "@wonderwhy-er/desktop-commander@latest"],
        auto_approved_tools=["execute_command"],
        tools=[MCPTool(name="execute_command", description="Run a command.")],
    )
    finding = by_id(run_checks(make_inventory(mcp_servers=[server])), "ES-101")[0]
    assert finding.severity is Severity.CRITICAL
    assert "no human in the loop" in finding.detail


def test_disabled_server_is_reported_one_step_lower():
    server = make_server("shell", command="/bin/bash", args=["-c", "x"], disabled=True)
    finding = by_id(run_checks(make_inventory(mcp_servers=[server])), "ES-101")[0]
    assert finding.severity is Severity.MEDIUM
    assert "disabled" in finding.detail


def test_filesystem_root_scope():
    server = make_server(
        "fs", command="npx", args=["-y", "@modelcontextprotocol/server-filesystem", "/"]
    )
    finding = by_id(run_checks(make_inventory(mcp_servers=[server])), "ES-102")[0]
    assert finding.severity is Severity.HIGH
    assert finding.evidence["scopes"] == ["/"]


def test_scoped_filesystem_server_is_clean():
    server = make_server(
        "fs",
        command="npx",
        args=["@modelcontextprotocol/server-filesystem@2.1.4", "/Users/alex/Projects/site"],
    )
    assert "ES-102" not in ids(run_checks(make_inventory(mcp_servers=[server])))


def test_root_path_on_a_non_filesystem_server_is_downgraded():
    server = make_server("odd", command="node", args=["/opt/s.js", "~"])
    finding = by_id(run_checks(make_inventory(mcp_servers=[server])), "ES-102")[0]
    assert finding.severity is Severity.MEDIUM


def test_unrestricted_egress_server():
    server = make_server("fetch", command="uvx", args=["mcp-server-fetch"])
    assert by_id(run_checks(make_inventory(mcp_servers=[server])), "ES-103")


def test_allow_list_argument_clears_egress_finding():
    server = make_server(
        "fetch", command="uvx", args=["mcp-server-fetch", "--allowed-hosts=docs.example.com"]
    )
    assert "ES-103" not in ids(run_checks(make_inventory(mcp_servers=[server])))


def test_loopback_remote_server_is_not_egress():
    server = make_server("docs", command="", url="http://localhost:3100/mcp", transport=Transport.HTTP)
    assert "ES-103" not in ids(run_checks(make_inventory(mcp_servers=[server])))


def test_url_embedded_credential_raises_egress_to_high():
    server = make_server(
        "crm",
        url="https://crm.example.com/mcp/<redacted>/sse",
        url_carries_secret=True,
        transport=Transport.SSE,
    )
    finding = by_id(run_checks(make_inventory(mcp_servers=[server])), "ES-103")[0]
    assert finding.severity is Severity.HIGH
    assert "credential-shaped segment" in finding.detail


def test_binary_in_temp_path():
    server = make_server("staged", command="node", args=["/tmp/mcp-build/server.js"])
    assert by_id(run_checks(make_inventory(mcp_servers=[server])), "ES-104")


def test_world_writable_binary_mode():
    server = make_server("x", command="node", command_path="/opt/n", command_mode="0777")
    finding = by_id(run_checks(make_inventory(mcp_servers=[server])), "ES-104")[0]
    assert "world-writable" in finding.detail


def test_elevated_scope_and_sudo_launch():
    servers = [
        make_server("a", command="sudo", args=["/usr/local/bin/srv"]),
        make_server("b", command="node", args=["/opt/s.js"], elevated_scope=True),
    ]
    findings = by_id(run_checks(make_inventory(mcp_servers=servers)), "ES-105")
    assert len(findings) == 2


def test_no_servers_produces_no_capability_findings():
    inv = make_inventory(model_runtimes=[ModelRuntime(name="ollama", installed=True)])
    assert not {f for f in ids(run_checks(inv)) if f.startswith("ES-1")}


def test_wildcard_auto_approval_also_removes_the_human():
    server = make_server(
        "shell",
        command="/bin/bash",
        args=["-c", "srv.sh"],
        auto_approved_tools=["*"],
    )
    finding = by_id(run_checks(make_inventory(mcp_servers=[server])), "ES-101")[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.evidence["auto_approved"] == ["*"]


def test_disabled_weak_evidence_filesystem_finding_is_also_downgraded():
    server = make_server("odd", command="node", args=["/opt/s.js", "~"], disabled=True)
    finding = by_id(run_checks(make_inventory(mcp_servers=[server])), "ES-102")[0]
    assert finding.severity is Severity.LOW
