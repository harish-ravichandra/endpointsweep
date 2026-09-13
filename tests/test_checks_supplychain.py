"""ES-3xx — package provenance."""

from __future__ import annotations

from endpointsweep.checks import CheckContext
from endpointsweep.matchers import is_pinned, package_from_invocation, split_spec
from endpointsweep.schema import Severity

from helpers import by_id, ids, make_inventory, make_server, run_checks


def test_npx_auto_install_is_unpinned():
    server = make_server("gh", command="npx", args=["-y", "@modelcontextprotocol/server-github"])
    finding = by_id(run_checks(make_inventory(mcp_servers=[server])), "ES-301")[0]
    assert finding.severity is Severity.HIGH
    assert "non-interactively" in finding.detail


def test_latest_tag_is_unpinned():
    server = make_server("gh", command="npx", args=["@modelcontextprotocol/server-github@latest"])
    assert by_id(run_checks(make_inventory(mcp_servers=[server])), "ES-301")


def test_exact_version_is_pinned():
    server = make_server("gh", command="npx", args=["@modelcontextprotocol/server-github@1.2.3"])
    assert "ES-301" not in ids(run_checks(make_inventory(mcp_servers=[server])))


def test_uvx_equality_pin_is_accepted():
    server = make_server("time", command="uvx", args=["mcp-server-time==0.4.1"])
    assert "ES-301" not in ids(run_checks(make_inventory(mcp_servers=[server])))


def test_local_script_has_no_registry_provenance():
    server = make_server("local", command="node", args=["/opt/acme/server.js"])
    assert "ES-301" not in ids(run_checks(make_inventory(mcp_servers=[server])))


def test_typosquat_distance_one_is_high():
    server = make_server(
        "fs", command="npx", args=["@modelcontextprotocol/server-filesystm@0.1.0"]
    )
    finding = by_id(run_checks(make_inventory(mcp_servers=[server])), "ES-302")[0]
    assert finding.severity is Severity.HIGH
    assert finding.evidence["nearest_known"] == "@modelcontextprotocol/server-filesystem"


def test_exact_known_package_is_not_a_typosquat():
    server = make_server(
        "fs", command="npx", args=["@modelcontextprotocol/server-filesystem@2.1.4"]
    )
    assert "ES-302" not in ids(run_checks(make_inventory(mcp_servers=[server])))


def test_unrelated_package_is_not_a_typosquat():
    server = make_server("weather", command="npx", args=["weather-mcp-tool@1.0.0"])
    assert "ES-302" not in ids(run_checks(make_inventory(mcp_servers=[server])))


def test_extra_known_packages_suppress_false_positives():
    server = make_server("fs", command="npx", args=["@acme/server-filesystm@1.0.0"])
    ctx = CheckContext(options={"known_packages": ["@acme/server-filesystm"]})
    assert "ES-302" not in ids(run_checks(make_inventory(mcp_servers=[server]), ctx))


def test_online_check_is_skipped_offline():
    server = make_server("gh", command="npx", args=["@modelcontextprotocol/server-github@1.2.3"])
    assert "ES-303" not in ids(run_checks(make_inventory(mcp_servers=[server])))


def test_package_extraction_helpers():
    assert package_from_invocation("npx", ["-y", "@scope/pkg", "/"]) == "@scope/pkg"
    assert package_from_invocation("npx", ["-p", "helper", "pkg@1.0.0"]) == "pkg@1.0.0"
    assert package_from_invocation("pnpm", ["dlx", "pkg@2.0.0"]) == "pkg@2.0.0"
    assert package_from_invocation("node", ["server.js"]) == ""
    assert split_spec("@scope/pkg@1.2.3") == ("@scope/pkg", "1.2.3")
    assert split_spec("pkg==1.0") == ("pkg", "1.0")
    assert is_pinned("pkg@^1.0.0") is False
    assert is_pinned("pkg@1.0.0") is True
