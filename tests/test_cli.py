"""End-to-end CLI behaviour: subcommands, formats, exit codes."""

from __future__ import annotations

import json
import sys

import pytest

from endpointsweep.cli import build_parser, collectors_dir, detect_os, main

from helpers import HOSTS


def run(argv, capsys):
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_help_lists_every_subcommand(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for command in ("scan", "analyze", "merge", "report", "checks", "collector"):
        assert command in out


def test_version_flag(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert "endpointsweep" in capsys.readouterr().out


def test_checks_table_lists_the_whole_catalog(capsys):
    code, out, _ = run(["checks"], capsys)
    assert code == 0
    for check_id in ("ES-101", "ES-201", "ES-301", "ES-401", "ES-901", "ES-903"):
        assert check_id in out


def test_checks_scope_filter(capsys):
    _, out, _ = run(["checks", "--scope", "fleet"], capsys)
    assert "ES-901" in out and "ES-101" not in out


def test_checks_json_is_machine_readable(capsys):
    _, out, _ = run(["checks", "-f", "json"], capsys)
    catalog = json.loads(out)
    assert len(catalog) == 17
    entry = next(c for c in catalog if c["id"] == "ES-201")
    assert entry["severity"] == "CRITICAL"
    assert entry["owasp"] and entry["atlas"] and entry["fix"]


def test_checks_markdown_is_a_table(capsys):
    _, out, _ = run(["checks", "-f", "markdown"], capsys)
    assert out.startswith("| ID |")


def test_analyze_single_host_markdown(capsys):
    target = HOSTS / "ws-mac-1021.json"
    code, out, err = run(["analyze", str(target)], capsys)
    assert code == 1  # findings at or above the default --fail-on high
    assert "# EndpointSweep host report" in out
    assert "ENDPOINTSWEEP|ws-mac-1021|" in err


def test_analyze_json_output_round_trips(capsys):
    _, out, _ = run(["analyze", str(HOSTS / "ws-mac-1021.json"), "-f", "json"], capsys)
    report = json.loads(out)
    assert report["inventory"]["host"]["hostname"] == "ws-mac-1021"
    assert report["findings"]


def test_fail_on_none_exits_zero(capsys):
    code, _, _ = run(["analyze", str(HOSTS / "ws-mac-1021.json"), "--fail-on", "none"], capsys)
    assert code == 0


def test_fail_on_critical_ignores_high(capsys):
    code, _, _ = run(["analyze", str(HOSTS / "ws-mac-1021.json"), "--fail-on", "critical"], capsys)
    assert code == 0


def test_clean_host_exits_zero(capsys):
    clean = next(
        path
        for path in sorted(HOSTS.glob("*.json"))
        if not json.loads(path.read_text(encoding="utf-8"))["client_configs"]
    )
    code, _, _ = run(["analyze", str(clean)], capsys)
    assert code == 0


def test_merge_accepts_a_directory(tmp_path, capsys):
    out_file = tmp_path / "fleet.json"
    code, _, err = run(["merge", str(HOSTS), "-o", str(out_file)], capsys)
    assert code == 1
    fleet = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(fleet["hosts"]) == 28
    assert "ENDPOINTSWEEP|fleet:28hosts|" in err


def test_report_from_merged_fleet(tmp_path, capsys):
    merged = tmp_path / "fleet.json"
    run(["merge", str(HOSTS), "-o", str(merged)], capsys)
    code, out, _ = run(["report", str(merged), "--drilldown", "0"], capsys)
    assert code == 1
    assert "# EndpointSweep fleet report" in out
    assert "## Shadow-AI census" in out


def test_report_merges_host_documents_on_the_fly(tmp_path, capsys):
    _, out, _ = run(["report", str(HOSTS), "-f", "json", "--drilldown", "0"], capsys)
    assert len(json.loads(out)["hosts"]) == 28


def test_report_sarif_and_html(tmp_path, capsys):
    sarif_path = tmp_path / "out.sarif"
    html_path = tmp_path / "out.html"
    run(["report", str(HOSTS), "-f", "sarif", "-o", str(sarif_path)], capsys)
    run(["report", str(HOSTS), "-f", "html", "-o", str(html_path)], capsys)
    assert json.loads(sarif_path.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert html_path.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_rare_threshold_is_tunable(tmp_path, capsys):
    _, out, _ = run(["report", str(HOSTS), "-f", "json", "--rare-threshold", "0.5"], capsys)
    fleet = json.loads(out)
    rare = [f for f in fleet["findings"] if f["id"] == "ES-902"]
    assert len(rare) > 8  # a higher cutoff makes more servers "long tail"


def test_managed_software_list_is_honoured(tmp_path, capsys):
    allow = tmp_path / "managed.txt"
    allow.write_text("# approved MCP servers\nremote-crm\nkb-search\n", encoding="utf-8")
    _, out, _ = run(
        ["report", str(HOSTS), "-f", "json", "--managed-software", str(allow)], capsys
    )
    subjects = {f["subject"] for f in json.loads(out)["findings"] if f["id"] == "ES-902"}
    assert "remote-crm" not in subjects and "kb-search" not in subjects


def test_multi_host_analyze_writes_one_file_per_host(tmp_path, capsys):
    targets = [str(p) for p in sorted(HOSTS.glob("*.json"))[:3]]
    run(["analyze", *targets, "-f", "json", "-o", str(tmp_path)], capsys)
    assert len(list(tmp_path.glob("*.json"))) == 3


def test_missing_input_reports_cleanly(capsys):
    code, _, err = run(["analyze", "/nonexistent/host.json"], capsys)
    assert code == 2
    assert "nonexistent" in err


def test_collector_subcommand_resolves_a_script(capsys):
    code, out, _ = run(["collector", "--os", "linux"], capsys)
    assert code == 0
    assert out.strip().endswith("endpointsweep_collect.bash")


def test_collector_can_print_the_script_body(capsys):
    _, out, _ = run(["collector", "--os", "macos", "--print"], capsys)
    assert out.startswith("#!/bin/sh")


def test_collector_rejects_an_unknown_os():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["collector", "--os", "plan9"])


def test_collectors_dir_is_discoverable():
    assert (collectors_dir() / "endpointsweep_collect.bash").is_file()


@pytest.mark.skipif(sys.platform not in ("linux", "darwin", "win32"), reason="unknown platform")
def test_detect_os_returns_a_known_target():
    assert detect_os() in ("macos", "linux", "windows")


@pytest.mark.skipif(sys.platform != "linux", reason="runs the Linux collector")
def test_scan_runs_the_local_collector(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ES_VERSION_PROBE", "0")
    monkeypatch.setenv("ES_SCAN_MANIFESTS", "0")
    raw = tmp_path / "raw.json"
    code, out, err = run(["scan", "-f", "json", "--save-raw", str(raw), "--fail-on", "none"], capsys)
    assert code == 0
    assert json.loads(out)["inventory"]["host"]["os"] == "linux"
    assert json.loads(raw.read_text(encoding="utf-8"))["collector"]["name"] == "endpointsweep"
    assert "ENDPOINTSWEEP|" in err
