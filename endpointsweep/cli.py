"""``endpointsweep`` command line: scan | analyze | merge | report | checks | collector.

    scan       collect on this machine, then analyse it (the dev on-ramp)
    analyze    analyse one or more collector JSON documents, one report each
    merge      N host documents -> one scored fleet model
    report     render a fleet model as Markdown / HTML / SARIF / JSON
    checks     print the check catalog
    collector  print or locate the collector script for an OS

Exit codes: 0 = nothing at or above --fail-on, 1 = findings, 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .checks import CheckContext, all_checks
from .merge import (
    analyze_host,
    fleet_from_dict,
    inventory_from_any,
    is_fleet_document,
    load_inventory,
    merge,
)
from .report import (
    fleet_report_html,
    fleet_report_markdown,
    fleet_sarif,
    host_report_markdown,
    host_sarif,
    sarif_dumps,
)
from .schema import FleetModel, HostReport, Severity, to_dict, to_json

COLLECTORS = {
    "macos": "endpointsweep_collect.sh",
    "linux": "endpointsweep_collect.bash",
    "windows": "endpointsweep_collect.ps1",
}

_FAIL_LEVELS = {s.value.lower(): s for s in Severity}
_FAIL_LEVELS["none"] = None  # type: ignore[assignment]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def collectors_dir() -> Path:
    """Find the collectors directory in a checkout, an install, or via env."""
    override = os.environ.get("ENDPOINTSWEEP_COLLECTORS")
    candidates = [Path(override)] if override else []
    here = Path(__file__).resolve().parent
    # A checkout keeps collectors/ at the repo root; a wheel ships the same
    # directory inside the package as endpointsweep/collectors.
    candidates += [here.parent / "collectors", here / "collectors"]
    for path in candidates:
        if path.is_dir():
            return path
    raise FileNotFoundError(
        "collectors/ not found; set ENDPOINTSWEEP_COLLECTORS to the directory holding "
        "endpointsweep_collect.sh/.bash/.ps1"
    )


def detect_os() -> str:
    system = platform.system().lower()
    return {"darwin": "macos", "linux": "linux", "windows": "windows"}.get(system, "")


def _write(path: str | None, text: str) -> None:
    if not path or path == "-":
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    _eprint(f"wrote {out}")


def _context(args: argparse.Namespace) -> CheckContext:
    managed: set[str] = set()
    if getattr(args, "managed_software", None):
        managed = {
            line.strip().lower()
            for line in Path(args.managed_software).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
    options: dict[str, Any] = {}
    if getattr(args, "known_packages", None):
        options["known_packages"] = [
            line.strip()
            for line in Path(args.known_packages).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
    return CheckContext(
        online=bool(getattr(args, "online", False)),
        rare_threshold=float(getattr(args, "rare_threshold", 0.05)),
        min_fleet_for_prevalence=int(getattr(args, "min_fleet", 10)),
        managed_software=managed,
        options=options,
    )


def _exit_code(findings: list, fail_on: str) -> int:
    threshold = _FAIL_LEVELS.get(fail_on.lower(), Severity.HIGH)
    if threshold is None:
        return 0
    return 1 if any(f.severity.rank >= threshold.rank for f in findings) else 0


def _summary_line(name: str, findings: list) -> str:
    """The EDR/MDM-console one-liner, mirroring the collector's own."""
    max_sev = max((f.severity for f in findings), key=lambda s: s.rank, default=Severity.INFO)
    return f"ENDPOINTSWEEP|{name}|{len(findings)}|{max_sev.value}"


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_collector(args: argparse.Namespace) -> int:
    target = args.os or detect_os()
    if target not in COLLECTORS:
        _eprint(f"unknown or undetected OS {target!r}; pass --os macos|linux|windows")
        return 2
    path = collectors_dir() / COLLECTORS[target]
    if not path.is_file():
        _eprint(f"collector not found: {path}")
        return 2
    if args.print_script:
        sys.stdout.write(path.read_text(encoding="utf-8"))
    else:
        print(path)
    return 0


def run_local_collector(target_os: str, out_path: Path) -> tuple[int, str]:
    """Run this platform's collector, writing JSON to ``out_path``."""
    script = collectors_dir() / COLLECTORS[target_os]
    if target_os == "macos":
        cmd = ["/bin/sh", str(script), str(out_path)]
    elif target_os == "linux":
        cmd = ["/bin/bash", str(script), str(out_path)]
    else:
        pwsh = "pwsh" if _which("pwsh") else "powershell"
        cmd = [pwsh, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), str(out_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True)  # noqa: S603
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _which(name: str) -> str | None:
    from shutil import which

    return which(name)


def cmd_scan(args: argparse.Namespace) -> int:
    target = args.os or detect_os()
    if target not in COLLECTORS:
        _eprint("could not determine this OS; pass --os macos|linux|windows")
        return 2
    with tempfile.TemporaryDirectory(prefix="endpointsweep-") as tmp:
        raw_path = Path(args.save_raw) if args.save_raw else Path(tmp) / "collect.json"
        code, output = run_local_collector(target, raw_path)
        if not raw_path.is_file():
            _eprint(f"collector produced no output (exit {code}):\n{output.strip()}")
            return 2
        if args.save_raw:
            _eprint(f"wrote {raw_path}")
        inventory = load_inventory(raw_path)

    report = analyze_host(inventory, _context(args))
    _render_host(report, args)
    print(_summary_line(report.inventory.hostname, report.findings), file=sys.stderr)
    return _exit_code(report.findings, args.fail_on)


def _render_host(report: HostReport, args: argparse.Namespace) -> None:
    if args.format == "json":
        _write(args.out, to_json(report))
    elif args.format == "sarif":
        _write(args.out, sarif_dumps(host_sarif(report)))
    else:
        _write(args.out, host_report_markdown(report))


def cmd_analyze(args: argparse.Namespace) -> int:
    ctx = _context(args)
    findings: list = []
    reports: list[HostReport] = []
    for path in args.inputs:
        try:
            inventory = load_inventory(path)
        except (OSError, ValueError) as exc:
            _eprint(f"{path}: {exc}")
            return 2
        report = analyze_host(inventory, ctx)
        reports.append(report)
        findings.extend(report.findings)

    if len(reports) == 1:
        _render_host(reports[0], args)
    else:
        # Several hosts: write one file per host when --out is a directory.
        for report in reports:
            name = report.inventory.hostname or "host"
            ext = {"json": "json", "sarif": "sarif", "markdown": "md"}[args.format]
            target = str(Path(args.out) / f"{name}.{ext}") if args.out else None
            _render_host(report, argparse.Namespace(**{**vars(args), "out": target}))
    for report in reports:
        print(_summary_line(report.inventory.hostname, report.findings), file=sys.stderr)
    return _exit_code(findings, args.fail_on)


def _load_fleet(inputs: Sequence[str], ctx: CheckContext) -> FleetModel:
    """Accept a merged fleet document, or raw host documents to merge now."""
    if len(inputs) == 1:
        data = json.loads(Path(inputs[0]).read_text(encoding="utf-8"))
        if is_fleet_document(data):
            return fleet_from_dict(data)
        return merge([inventory_from_any(data, source_path=inputs[0])], ctx)
    inventories = [load_inventory(p) for p in inputs]
    return merge(inventories, ctx)


def cmd_merge(args: argparse.Namespace) -> int:
    paths = _expand_inputs(args.inputs)
    if not paths:
        _eprint("no input files matched")
        return 2
    fleet = merge([load_inventory(p) for p in paths], _context(args))
    _write(args.out, to_json(fleet))
    print(_summary_line(f"fleet:{fleet.host_count}hosts", fleet.all_findings), file=sys.stderr)
    return _exit_code(fleet.all_findings, args.fail_on)


def cmd_report(args: argparse.Namespace) -> int:
    paths = _expand_inputs(args.inputs)
    if not paths:
        _eprint("no input files matched")
        return 2
    fleet = _load_fleet(paths, _context(args))
    if args.format == "json":
        _write(args.out, to_json(fleet))
    elif args.format == "sarif":
        _write(args.out, sarif_dumps(fleet_sarif(fleet)))
    elif args.format == "html":
        _write(args.out, fleet_report_html(fleet))
    else:
        _write(args.out, fleet_report_markdown(fleet, drilldown=args.drilldown))
    print(_summary_line(f"fleet:{fleet.host_count}hosts", fleet.all_findings), file=sys.stderr)
    return _exit_code(fleet.all_findings, args.fail_on)


def cmd_checks(args: argparse.Namespace) -> int:
    checks = all_checks(args.scope)
    if args.format == "json":
        print(json.dumps([to_dict(c.meta) for c in checks], indent=2))
        return 0
    if args.format == "markdown":
        print("| ID | Severity | Vector | Scope | Title |")
        print("|---|---|---|---|---|")
        for c in checks:
            m = c.meta
            print(f"| {m.id} | {m.severity.value} | V{m.vector.value} | {m.scope} | {m.title} |")
        return 0
    width = max((len(c.meta.title) for c in checks), default=10)
    for c in checks:
        m = c.meta
        flag = " [--online]" if m.online else ""
        print(f"{m.id}  {m.severity.value:<8} V{m.vector.value} {m.scope:<5} {m.title:<{width}}{flag}")
    return 0


def _expand_inputs(inputs: Sequence[str]) -> list[str]:
    """Expand directories and globs so ``testdata/hosts/*.json`` always works."""
    out: list[str] = []
    for item in inputs:
        path = Path(item)
        if path.is_dir():
            out.extend(sorted(str(p) for p in path.glob("*.json")))
        elif any(ch in item for ch in "*?["):
            out.extend(sorted(str(p) for p in Path().glob(item)))
        else:
            out.append(item)
    return out


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------


def _add_common(parser: argparse.ArgumentParser, *, formats: tuple[str, ...]) -> None:
    parser.add_argument("-f", "--format", choices=formats, default=formats[0])
    parser.add_argument("-o", "--out", help="output file (or directory for multi-host analyze)")
    parser.add_argument(
        "--fail-on",
        default="high",
        choices=sorted(_FAIL_LEVELS),
        help="exit 1 when a finding at or above this severity exists (default: high)",
    )
    parser.add_argument("--online", action="store_true", help="enable checks that need network access")
    parser.add_argument("--managed-software", help="file of approved server/package names, one per line")
    parser.add_argument("--known-packages", help="extra known-good package names for ES-302")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="endpointsweep",
        description=(
            "Discover and audit MCP servers and agentic AI tooling across an endpoint fleet."
        ),
        epilog="Metadata only: EndpointSweep reports variable NAMES and file PATHS, never values.",
    )
    parser.add_argument("--version", action="version", version=f"endpointsweep {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="collect on this machine and analyse the result")
    scan.add_argument("--os", choices=sorted(COLLECTORS), help="override OS detection")
    scan.add_argument("--save-raw", help="keep the raw collector JSON at this path")
    _add_common(scan, formats=("markdown", "json", "sarif"))
    scan.set_defaults(func=cmd_scan)

    analyze = sub.add_parser("analyze", help="analyse collector JSON from one or more hosts")
    analyze.add_argument("inputs", nargs="+", help="collector JSON files")
    _add_common(analyze, formats=("markdown", "json", "sarif"))
    analyze.set_defaults(func=cmd_analyze)

    merge_cmd = sub.add_parser("merge", help="merge host documents into one scored fleet model")
    merge_cmd.add_argument("inputs", nargs="+", help="collector JSON files, globs or directories")
    merge_cmd.add_argument("--rare-threshold", type=float, default=0.05, help="ES-902 long-tail cutoff")
    merge_cmd.add_argument("--min-fleet", type=int, default=10, help="minimum hosts before ES-902 runs")
    _add_common(merge_cmd, formats=("json",))
    merge_cmd.set_defaults(func=cmd_merge)

    report = sub.add_parser("report", help="render a fleet report")
    report.add_argument("inputs", nargs="+", help="merged fleet JSON, or host documents to merge now")
    report.add_argument("--drilldown", type=int, default=15, help="per-host sections to include (0 = none)")
    report.add_argument("--rare-threshold", type=float, default=0.05)
    report.add_argument("--min-fleet", type=int, default=10)
    _add_common(report, formats=("markdown", "html", "sarif", "json"))
    report.set_defaults(func=cmd_report)

    checks = sub.add_parser("checks", help="print the check catalog")
    checks.add_argument("--scope", choices=("host", "fleet"), help="limit to one scope")
    checks.add_argument("-f", "--format", choices=("table", "markdown", "json"), default="table")
    checks.set_defaults(func=cmd_checks)

    collector = sub.add_parser("collector", help="locate or print a collector script")
    collector.add_argument("--os", choices=sorted(COLLECTORS), help="default: this machine's OS")
    collector.add_argument("--print", dest="print_script", action="store_true", help="print the script body")
    collector.set_defaults(func=cmd_collector)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except FileNotFoundError as exc:
        _eprint(f"error: {exc}")
        return 2
    except BrokenPipeError:  # pragma: no cover - `| head` on the terminal
        return 0
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
