"""ES-9xx, merge, census and scoring — the fleet layer."""

from __future__ import annotations

import json

from endpointsweep.checks import CheckContext, run_fleet_checks
from endpointsweep.merge import analyze_host, fleet_from_dict, merge
from endpointsweep.schema import FleetModel, Severity, to_json
from endpointsweep.scoring import band_counts, percentile, risk_band, saturate

from helpers import GOLDEN, by_id, ids, make_inventory, make_server


def fleet_of(*inventories) -> FleetModel:
    return merge(list(inventories), CheckContext(min_fleet_for_prevalence=2))


def test_inconsistent_provenance_across_hosts():
    a = make_inventory("h1", mcp_servers=[make_server("tools", command="npx", args=["@acme/tools@1.4.0"])])
    b = make_inventory("h2", mcp_servers=[make_server("tools", command="npx", args=["@acme/tools@1.4.0"])])
    c = make_inventory("h3", mcp_servers=[make_server("tools", command="node", args=["/tmp/tools/server.js"])])
    findings = by_id(fleet_of(a, b, c).findings, "ES-901")
    assert findings[0].severity is Severity.HIGH
    assert findings[0].hosts == ["h1", "h2", "h3"]
    assert findings[0].evidence["variants"][0]["host_count"] == 2
    assert findings[0].evidence["singleton_variants"]


def test_consistent_server_produces_no_provenance_finding():
    hosts = [
        make_inventory(f"h{i}", mcp_servers=[make_server("tools", command="npx", args=["@acme/tools@1.4.0"])])
        for i in range(3)
    ]
    assert "ES-901" not in ids(fleet_of(*hosts).findings)


def test_user_home_paths_do_not_split_a_server_identity():
    a = make_inventory("h1", mcp_servers=[make_server("fs", command="npx", args=["pkg@1.0.0", "/Users/alex/p"])])
    b = make_inventory("h2", mcp_servers=[make_server("fs", command="npx", args=["pkg@1.0.0", "/Users/jordan/p"])])
    assert "ES-901" not in ids(fleet_of(a, b).findings)


def test_long_tail_server_below_threshold():
    hosts = [make_inventory(f"h{i}", mcp_servers=[make_server("common", command="npx", args=["c@1.0.0"])]) for i in range(20)]
    hosts.append(make_inventory("h99", mcp_servers=[make_server("rare", command="npx", args=["r@1.0.0"])]))
    findings = by_id(merge(hosts, CheckContext()).findings, "ES-902")
    assert [f.subject for f in findings] == ["rare"]
    assert findings[0].evidence["host_count"] == 1


def test_managed_software_list_suppresses_long_tail():
    hosts = [make_inventory(f"h{i}") for i in range(20)]
    hosts.append(make_inventory("h99", mcp_servers=[make_server("rare", command="npx", args=["rare-pkg@1.0.0"])]))
    ctx = CheckContext(managed_software={"rare-pkg"})
    assert "ES-902" not in ids(merge(hosts, ctx).findings)


def test_prevalence_check_needs_a_real_fleet():
    hosts = [make_inventory(f"h{i}", mcp_servers=[make_server("rare", command="npx", args=["r@1.0.0"])]) for i in range(3)]
    assert "ES-902" not in ids(merge(hosts, CheckContext()).findings)


def test_census_counts_hosts_not_declarations(fleet):
    census = fleet.census
    assert census["fleet_size"] == 28
    assert census["hosts_with"]["mcp_servers"] == 22
    top = {row["name"]: row for row in census["top_servers"]}
    assert top["internal-tools"]["variants"] == 3
    assert sum(census["os_breakdown"].values()) == 28


def test_duplicate_hostnames_collapse_to_the_latest_collection():
    old = make_inventory("dup", mcp_servers=[make_server("a")])
    old.host.collected_at = "2026-09-01T00:00:00Z"
    new = make_inventory("dup", mcp_servers=[make_server("a"), make_server("b")])
    new.host.collected_at = "2026-09-10T00:00:00Z"
    fleet = merge([old, new], CheckContext())
    assert fleet.host_count == 1
    assert len(fleet.hosts[0].inventory.mcp_servers) == 2


def test_scores_saturate_but_stay_monotonic():
    assert saturate(0, 35) == 0.0
    assert saturate(12, 35) < saturate(24, 35) < saturate(120, 35) <= 100.0
    assert risk_band(0) == "LOW"
    assert risk_band(50) == "ELEVATED"
    assert risk_band(95) == "CRITICAL"


def test_percentile_is_nearest_rank():
    assert percentile([1, 2, 3, 4], 50) == 2
    assert percentile([], 95) == 0.0


def test_fleet_score_blends_hosts_and_fleet_findings(fleet):
    assert 0 < fleet.score <= 100
    assert sum(band_counts(fleet).values()) == fleet.host_count


def test_fleet_round_trips_through_json(fleet):
    restored = fleet_from_dict(json.loads(to_json(fleet)))
    assert restored.host_count == fleet.host_count
    assert restored.score == fleet.score
    assert len(restored.all_findings) == len(fleet.all_findings)
    assert restored.hosts[0].findings[0].severity is fleet.hosts[0].findings[0].severity


def test_golden_fleet_summary(fleet):
    """Golden: the whole catalog against the synthetic fleet.

    Regenerate deliberately with ``python3 testdata/generate_golden.py`` and
    read the diff — it is the review of what the change did.
    """
    expected = json.loads((GOLDEN / "fleet_summary.json").read_text(encoding="utf-8"))
    counts = {}
    for finding in fleet.all_findings:
        key = f"{finding.id}:{finding.severity.value}"
        counts[key] = counts.get(key, 0) + 1
    assert counts == expected["finding_counts"]
    assert fleet.host_count == expected["host_count"]
    assert fleet.score == expected["fleet_score"]
    assert sorted(f"{f.id}:{f.subject}" for f in fleet.findings) == expected["fleet_finding_subjects"]
    assert fleet.census["totals"] == expected["census_totals"]


def test_golden_dirty_host(fleet):
    expected = json.loads((GOLDEN / "ws-mac-1021.json").read_text(encoding="utf-8"))
    host = next(h for h in fleet.hosts if h.inventory.hostname == expected["hostname"])
    assert sorted(f"{f.id}:{f.severity.value}:{f.subject}" for f in host.findings) == expected["findings"]
    assert host.score == expected["score"]
    assert host.max_severity.value == expected["max_severity"]


def test_every_finding_carries_its_catalog_metadata(fleet):
    for finding in fleet.all_findings:
        assert finding.id.startswith("ES-")
        assert finding.title and finding.fix
        assert finding.vector.title
        if finding.severity is not Severity.INFO:
            assert finding.owasp, f"{finding.id} has no OWASP mapping"
            assert finding.atlas, f"{finding.id} has no ATLAS mapping"


def test_analyze_host_is_deterministic(host_files):
    from endpointsweep.merge import load_inventory

    inv = load_inventory(host_files[0])
    first = analyze_host(inv)
    second = analyze_host(load_inventory(host_files[0]))
    assert to_json(first) == to_json(second)


def test_fleet_checks_need_no_context_object(fleet):
    assert run_fleet_checks(fleet) is not None
