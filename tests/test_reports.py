"""Markdown, SARIF and HTML renderers."""

from __future__ import annotations

import json
import re

from endpointsweep.checks import REGISTRY
from endpointsweep.report import (
    fleet_report_html,
    fleet_report_markdown,
    fleet_sarif,
    host_report_markdown,
    host_sarif,
)
from endpointsweep.report.sarif import path_to_uri
from endpointsweep.schema import Severity

from helpers import make_inventory, make_server


def test_fleet_markdown_has_every_section(fleet):
    md = fleet_report_markdown(fleet)
    for heading in (
        "# EndpointSweep fleet report",
        "## Executive summary",
        "## Risk by vector",
        "## Shadow-AI census",
        "## Fleet-level findings",
        "## Hosts by risk",
        "## Per-host drill-down",
        "## Appendix A — checks run",
        "## Appendix B — methodology and limits",
    ):
        assert heading in md, heading


def test_fleet_markdown_reports_the_census_numbers(fleet):
    md = fleet_report_markdown(fleet)
    assert f"**Hosts:** {fleet.host_count}" in md
    assert "internal-tools" in md
    assert "Metadata only" not in md or "variable NAMES" in md


def test_drilldown_can_be_switched_off(fleet):
    assert "## Per-host drill-down" not in fleet_report_markdown(fleet, drilldown=0)


def test_markdown_table_cells_escape_pipes():
    server = make_server("weird", command="/bin/bash", args=["-c", "a | b"])
    md = host_report_markdown(_report(make_inventory(mcp_servers=[server])))
    table_rows = [line for line in md.splitlines() if line.startswith("| weird ")]
    assert table_rows and r"a \| b" in table_rows[0]


def _report(inventory):
    from endpointsweep.merge import analyze_host

    return analyze_host(inventory)


def test_host_markdown_shows_findings_and_fixes():
    server = make_server("fs", command="npx", args=["-y", "@modelcontextprotocol/server-filesystem", "/"])
    md = host_report_markdown(_report(make_inventory(mcp_servers=[server])))
    assert "ES-102" in md
    assert "**Fix:**" in md
    assert "OWASP LLM Top 10" in md


def test_host_markdown_never_prints_an_env_value():
    server = make_server("gh", env_var_names=["GITHUB_TOKEN"])
    md = host_report_markdown(_report(make_inventory(mcp_servers=[server])))
    assert "GITHUB_TOKEN" in md
    # The evidence block carries names, and has nowhere to put a value.
    assert '"variable_names"' in md
    assert '"value"' not in md


def test_sarif_document_shape(fleet):
    doc = fleet_sarif(fleet)
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "EndpointSweep"
    assert len(run["tool"]["driver"]["rules"]) == len(REGISTRY)
    assert run["invocations"][0]["executionSuccessful"] is True


def test_sarif_rule_index_matches_rule_id(fleet):
    run = fleet_sarif(fleet)["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_sarif_levels_and_security_severity(fleet):
    run = fleet_sarif(fleet)["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert rules["ES-201"]["defaultConfiguration"]["level"] == "error"
    assert rules["ES-403"]["defaultConfiguration"]["level"] == "note"
    assert float(rules["ES-201"]["properties"]["security-severity"]) > float(
        rules["ES-403"]["properties"]["security-severity"]
    )
    assert {r["level"] for r in run["results"]} <= {"error", "warning", "note"}


def test_sarif_fingerprints_are_stable_and_unique(fleet):
    first = fleet_sarif(fleet)["runs"][0]["results"]
    second = fleet_sarif(fleet)["runs"][0]["results"]
    keys = [r["partialFingerprints"]["endpointsweepFindingV1"] for r in first]
    assert keys == [r["partialFingerprints"]["endpointsweepFindingV1"] for r in second]
    assert len(set(keys)) == len(keys)


def test_sarif_every_result_has_a_location(fleet):
    for result in fleet_sarif(fleet)["runs"][0]["results"]:
        assert result["locations"]


def test_sarif_uris_are_well_formed():
    assert path_to_uri("/Users/alex/.cursor/mcp.json") == "file:///Users/alex/.cursor/mcp.json"
    assert path_to_uri("C:\\Users\\alex\\mcp.json") == "file:///C:/Users/alex/mcp.json"
    assert path_to_uri("/home/a/.claude.json#projects//home/a/x").endswith(".claude.json")
    assert path_to_uri("") == ""


def test_sarif_is_json_serialisable(fleet):
    json.loads(json.dumps(fleet_sarif(fleet)))


def test_host_sarif_is_scoped_to_one_host():
    server = make_server("fs", command="npx", args=["-y", "@modelcontextprotocol/server-filesystem", "/"])
    doc = host_sarif(_report(make_inventory(mcp_servers=[server], hostname="h9")))
    assert doc["runs"][0]["automationDetails"]["id"] == "endpointsweep/host/h9"
    assert all(r["properties"]["host"] == "h9" for r in doc["runs"][0]["results"])


def test_html_is_self_contained_and_themed(fleet):
    html = fleet_report_html(fleet)
    assert html.startswith("<!doctype html>")
    assert "prefers-color-scheme: dark" in html
    # Self-contained: nothing is fetched at render time. URLs inside finding
    # text are fine - they are evidence, not resource loads.
    assert "<script" not in html
    assert "<link" not in html
    assert not re.search(r"(src|href)\s*=\s*[\"\']https?://", html)
    assert "url(http" not in html and "@import" not in html
    assert re.search(r"<title>.*EndpointSweep.*</title>", html)


def test_html_escapes_content(fleet):
    server = make_server("x<script>", command="node", args=["a&b"])
    html = fleet_report_html(_fleet_of(make_inventory(mcp_servers=[server])))
    assert "<script>" not in html.split("<style>")[1]


def _fleet_of(*inventories):
    from endpointsweep.checks import CheckContext
    from endpointsweep.merge import merge

    return merge(list(inventories), CheckContext())


def test_html_renders_severity_pills(fleet):
    html = fleet_report_html(fleet)
    for severity in (Severity.CRITICAL, Severity.HIGH):
        assert f"pill {severity.value}" in html
