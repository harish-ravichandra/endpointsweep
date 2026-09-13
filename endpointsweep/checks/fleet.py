"""ES-9xx — fleet-level checks.

These are the checks that only exist once you have N hosts in one model. No
single-host scanner can answer "is this server the same server everywhere?" or
"how much of the fleet actually runs this?" — that is the whole point of the
collect-and-aggregate split (brief §2.1).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from ..matchers import normalize_invocation, package_from_invocation, split_spec
from ..schema import Finding, FleetModel, Severity, Vector
from .registry import CheckContext, fleet_check


def _server_index(fleet: FleetModel) -> dict[str, dict[str, set[str]]]:
    """identity -> normalised invocation -> hosts running it."""
    index: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for report in fleet.hosts:
        host = report.inventory.hostname
        for server in report.inventory.mcp_servers:
            invocation = normalize_invocation(server.command, server.args)
            index[server.identity][invocation].add(host)
    return index


def _is_managed(ctx: CheckContext, identity: str, invocations: Iterable[str]) -> bool:
    managed = {m.lower() for m in ctx.managed_software}
    if not managed:
        return False
    if identity in managed:
        return True
    for invocation in invocations:
        parts = invocation.split()
        if not parts:
            continue
        pkg = package_from_invocation(parts[0], parts[1:])
        name, _ = split_spec(pkg)
        if name and name.lower() in managed:
            return True
    return False


@fleet_check(
    "ES-901",
    "Same MCP server name resolves to different commands across the fleet",
    Severity.HIGH,
    Vector.MCP_SERVERS,
    rationale=(
        "One name, several implementations: either the fleet is running unmanaged "
        "variants of a server, or one host's copy has been swapped. A per-machine "
        "scanner cannot see this — every host looks internally consistent."
    ),
    fix=(
        "Diff the variants. Standardise on one pinned invocation distributed by the "
        "software-management stack, and investigate any host whose variant is unique."
    ),
    owasp=("LLM03: Supply Chain", "LLM04: Data and Model Poisoning"),
    atlas=("AML.T0010: ML Supply Chain Compromise", "AML.T0018: Manipulate AI Model"),
)
def inconsistent_server_provenance(fleet: FleetModel, ctx: CheckContext) -> Iterable[Finding]:
    meta = inconsistent_server_provenance.meta
    for identity, variants in sorted(_server_index(fleet).items()):
        if len(variants) < 2:
            continue
        all_hosts = sorted({h for hosts in variants.values() for h in hosts})
        if len(all_hosts) < 2:
            continue
        ranked = sorted(variants.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        outliers = [inv for inv, hosts in ranked[1:] if len(hosts) == 1]
        severity = Severity.HIGH if outliers else Severity.MEDIUM
        yield meta.finding(
            subject=identity,
            detail=(
                f"server {identity!r} runs {len(variants)} distinct invocations across "
                f"{len(all_hosts)} host(s)"
                + (f"; {len(outliers)} appear on exactly one host" if outliers else "")
            ),
            severity=severity,
            hosts=all_hosts,
            evidence={
                "variants": [
                    {"invocation": inv, "host_count": len(hosts), "hosts": sorted(hosts)}
                    for inv, hosts in ranked
                ],
                "singleton_variants": outliers,
            },
        )


@fleet_check(
    "ES-902",
    "Long-tail MCP server installed on a small fraction of the fleet",
    Severity.MEDIUM,
    Vector.MCP_SERVERS,
    rationale=(
        "Managed software is common; shadow installs are rare. A server on a handful "
        "of hosts and on no approved-software list is the shape of an individually "
        "installed, unreviewed integration."
    ),
    fix="Confirm with the owning user, then either add the server to the managed baseline or remove it.",
    owasp=("LLM03: Supply Chain",),
    atlas=("AML.T0010: ML Supply Chain Compromise",),
)
def long_tail_server(fleet: FleetModel, ctx: CheckContext) -> Iterable[Finding]:
    meta = long_tail_server.meta
    total = fleet.host_count
    if total < ctx.min_fleet_for_prevalence:
        return
    for identity, variants in sorted(_server_index(fleet).items()):
        hosts = sorted({h for hs in variants.values() for h in hs})
        prevalence = len(hosts) / total
        if prevalence >= ctx.rare_threshold:
            continue
        if _is_managed(ctx, identity, variants.keys()):
            continue
        yield meta.finding(
            subject=identity,
            detail=(
                f"present on {len(hosts)}/{total} hosts ({prevalence:.1%}, below the "
                f"{ctx.rare_threshold:.0%} long-tail threshold) and not on the managed-software list"
            ),
            hosts=hosts,
            evidence={
                "host_count": len(hosts),
                "fleet_size": total,
                "prevalence": round(prevalence, 4),
                "invocations": sorted(variants.keys()),
            },
        )


@fleet_check(
    "ES-903",
    "Fleet shadow-AI census",
    Severity.INFO,
    Vector.AGENTIC_AI,
    rationale="The inventory answer to the question that prompted the scan: what is actually out there.",
    fix="No action. Use the census tables to set the approved-software baseline that ES-902 measures against.",
)
def fleet_census(fleet: FleetModel, ctx: CheckContext) -> Iterable[Finding]:
    meta = fleet_census.meta
    census = fleet.census or {}
    if not census:
        return
    totals = census.get("totals", {})
    yield meta.finding(
        subject="fleet-census",
        detail=(
            f"{fleet.host_count} host(s): {totals.get('mcp_servers', 0)} MCP server "
            f"declarations, {totals.get('agentic_tools', 0)} agentic CLI installs, "
            f"{totals.get('ide_extensions', 0)} IDE AI extensions, "
            f"{totals.get('model_runtimes', 0)} local model runtimes"
        ),
        hosts=[h.inventory.hostname for h in fleet.hosts],
        evidence={"totals": totals, "top_servers": census.get("top_servers", [])[:10]},
    )
