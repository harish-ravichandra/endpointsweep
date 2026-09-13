"""N host inventories → one scored fleet model, plus the census tables.

This is the layer the competitor scanners do not have (brief §2.1): everything
here is an answer you can only give once you hold the whole fleet at once.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .checks import CheckContext, run_fleet_checks, run_host_checks
from .matchers import normalize_invocation, package_from_invocation, split_spec
from .parsers import parse_collector_output
from .schema import FleetModel, HostInventory, HostReport, host_inventory_from_dict
from .scoring import score_fleet, score_host

#: Top-N length for census tables.
TOP_N = 20


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def load_inventory(path: str | Path) -> HostInventory:
    """Load either raw collector output or a previous ``analyze`` JSON."""
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    return inventory_from_any(data, source_path=str(path))


def inventory_from_any(data: dict[str, Any], *, source_path: str = "") -> HostInventory:
    """Accept collector output, an analyze report, or a bare inventory."""
    if "client_configs" in data or "collector" in data:
        return parse_collector_output(data, source_path=source_path)
    if "inventory" in data:  # a per-host analyze report
        inv = host_inventory_from_dict(data["inventory"])
        inv.source_path = source_path
        return inv
    inv = host_inventory_from_dict(data)
    inv.source_path = source_path
    return inv


def load_inventories(paths: Iterable[str | Path]) -> list[HostInventory]:
    inventories: list[HostInventory] = []
    for path in paths:
        inventories.append(load_inventory(path))
    return inventories


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------


def analyze_host(inventory: HostInventory, ctx: CheckContext | None = None) -> HostReport:
    ctx = ctx or CheckContext()
    findings = run_host_checks(inventory, ctx)
    return score_host(inventory, findings)


def merge(
    inventories: Iterable[HostInventory],
    ctx: CheckContext | None = None,
    *,
    generated_at: str | None = None,
) -> FleetModel:
    """Analyse every host, build the census, then run the fleet-level checks."""
    ctx = ctx or CheckContext()
    reports = [analyze_host(inv, ctx) for inv in _dedupe_hosts(inventories)]
    reports.sort(key=lambda r: (-r.score, r.inventory.hostname))

    fleet = FleetModel(generated_at=generated_at or now_iso(), hosts=reports)
    fleet.census = build_census(fleet)
    fleet.findings = run_fleet_checks(fleet, ctx)
    return score_fleet(fleet)


def _dedupe_hosts(inventories: Iterable[HostInventory]) -> list[HostInventory]:
    """One inventory per hostname — the most recent collection wins."""
    best: dict[str, HostInventory] = {}
    for inv in inventories:
        key = inv.hostname or inv.source_path
        current = best.get(key)
        if current is None or inv.host.collected_at >= current.host.collected_at:
            best[key] = inv
    return sorted(best.values(), key=lambda i: i.hostname)


# --------------------------------------------------------------------------
# Census
# --------------------------------------------------------------------------


def _top(counter: Counter, total: int, key: str = "name") -> list[dict[str, Any]]:
    return [
        {key: name, "hosts": count, "prevalence": round(count / total, 4) if total else 0.0}
        for name, count in counter.most_common(TOP_N)
    ]


def build_census(fleet: FleetModel) -> dict[str, Any]:
    total = fleet.host_count
    os_counter: Counter = Counter()
    server_hosts: Counter = Counter()
    server_invocations: dict[str, set[str]] = defaultdict(set)
    package_hosts: Counter = Counter()
    client_hosts: Counter = Counter()
    agentic_hosts: Counter = Counter()
    agentic_versions: dict[str, Counter] = defaultdict(Counter)
    ext_hosts: Counter = Counter()
    ai_pkg_hosts: Counter = Counter()
    runtime_hosts: Counter = Counter()
    runtime_running: Counter = Counter()
    runtime_models: Counter = Counter()

    totals = Counter()
    hosts_with: Counter = Counter()

    for report in fleet.hosts:
        inv = report.inventory
        os_counter[inv.host.os.value] += 1

        for name in {s.identity for s in inv.mcp_servers}:
            server_hosts[name] += 1
        for client in {s.client for s in inv.mcp_servers}:
            client_hosts[client] += 1
        for server in inv.mcp_servers:
            server_invocations[server.identity].add(
                normalize_invocation(server.command, server.args)
            )
            pkg = package_from_invocation(server.command, server.args)
            name, _ = split_spec(pkg)
            if name:
                package_hosts[name] += 1
        totals["mcp_servers"] += len(inv.mcp_servers)
        hosts_with["mcp_servers"] += 1 if inv.mcp_servers else 0

        for tool in inv.agentic_tools:
            agentic_versions[tool.name][tool.version or "unknown"] += 1
        for name in {t.name for t in inv.agentic_tools}:
            agentic_hosts[name] += 1
        totals["agentic_tools"] += len(inv.agentic_tools)
        hosts_with["agentic_tools"] += 1 if inv.agentic_tools else 0

        for ext in {e.extension_id for e in inv.ide_extensions}:
            ext_hosts[ext] += 1
        totals["ide_extensions"] += len(inv.ide_extensions)
        hosts_with["ide_extensions"] += 1 if inv.ide_extensions else 0

        for pkg in {p for m in inv.package_manifests for p in m.ai_packages}:
            ai_pkg_hosts[pkg] += 1
        totals["ai_packages"] += sum(len(m.ai_packages) for m in inv.package_manifests)

        for runtime in inv.model_runtimes:
            if not runtime.installed:
                continue
            runtime_hosts[runtime.name] += 1
            if runtime.running:
                runtime_running[runtime.name] += 1
            for model in runtime.models:
                runtime_models[model] += 1
        installed = [r for r in inv.model_runtimes if r.installed]
        totals["model_runtimes"] += len(installed)
        hosts_with["model_runtimes"] += 1 if installed else 0

        totals["env_key_signals"] += len(inv.env_key_signals)
        totals["collector_errors"] += len(inv.errors)

    top_servers = _top(server_hosts, total)
    for row in top_servers:
        row["invocations"] = sorted(server_invocations[row["name"]])
        row["variants"] = len(row["invocations"])

    return {
        "fleet_size": total,
        "os_breakdown": dict(os_counter.most_common()),
        "totals": dict(totals),
        "hosts_with": dict(hosts_with),
        "top_servers": top_servers,
        "top_server_packages": _top(package_hosts, total, key="package"),
        "clients": _top(client_hosts, total, key="client"),
        "top_agentic_tools": [
            {
                "name": name,
                "hosts": count,
                "prevalence": round(count / total, 4) if total else 0.0,
                "versions": dict(agentic_versions[name].most_common()),
            }
            for name, count in agentic_hosts.most_common(TOP_N)
        ],
        "top_ide_extensions": _top(ext_hosts, total, key="extension"),
        "top_ai_packages": _top(ai_pkg_hosts, total, key="package"),
        "model_runtimes": [
            {
                "name": name,
                "hosts": count,
                "running": runtime_running.get(name, 0),
                "prevalence": round(count / total, 4) if total else 0.0,
            }
            for name, count in runtime_hosts.most_common(TOP_N)
        ],
        "top_models": [{"model": m, "hosts": c} for m, c in runtime_models.most_common(TOP_N)],
    }


# --------------------------------------------------------------------------
# Fleet model (de)serialisation
# --------------------------------------------------------------------------


def fleet_from_dict(data: dict[str, Any]) -> FleetModel:
    """Rehydrate a fleet model written by ``endpointsweep merge``."""
    from .schema import Vector, VectorScore, finding_from_dict

    hosts: list[HostReport] = []
    for raw in data.get("hosts") or []:
        inv = host_inventory_from_dict(raw.get("inventory") or {})
        hosts.append(
            HostReport(
                inventory=inv,
                findings=[finding_from_dict(f) for f in raw.get("findings") or []],
                score=float(raw.get("score", 0.0)),
                vector_scores=[
                    VectorScore(
                        vector=Vector(int(vs["vector"])),
                        score=float(vs.get("score", 0.0)),
                        findings=int(vs.get("findings", 0)),
                        covered=bool(vs.get("covered", True)),
                    )
                    for vs in raw.get("vector_scores") or []
                ],
            )
        )
    return FleetModel(
        generated_at=data.get("generated_at", ""),
        hosts=hosts,
        findings=[finding_from_dict(f) for f in data.get("findings") or []],
        score=float(data.get("score", 0.0)),
        vector_scores=[
            VectorScore(
                vector=Vector(int(vs["vector"])),
                score=float(vs.get("score", 0.0)),
                findings=int(vs.get("findings", 0)),
                covered=bool(vs.get("covered", True)),
            )
            for vs in data.get("vector_scores") or []
        ],
        census=data.get("census") or {},
        tool_version=data.get("tool_version", ""),
    )


def is_fleet_document(data: dict[str, Any]) -> bool:
    return isinstance(data.get("hosts"), list) and "census" in data
