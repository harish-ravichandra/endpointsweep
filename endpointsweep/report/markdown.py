"""Markdown reports: one host, or a whole fleet.

Report layout follows the question the tool exists to answer: what is out there
(census), what is wrong with it (findings), and which boxes to go touch first
(per-host drill-down).
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from typing import Any

from ..checks import REGISTRY
from ..schema import Finding, FleetModel, HostReport, Severity, Vector
from ..scoring import band_counts, percentile, risk_band

SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: Iterable[Iterable[Any]]) -> list[str]:
    rows = [list(r) for r in rows]
    if not rows:
        return ["_none_", ""]
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    out += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    out.append("")
    return out


def _severity_counts(findings: list[Finding]) -> Counter:
    counts: Counter = Counter()
    for f in findings:
        counts[f.severity] += 1
    return counts


def _severity_line(findings: list[Finding]) -> str:
    counts = _severity_counts(findings)
    return " · ".join(f"**{s.value}** {counts.get(s, 0)}" for s in SEVERITY_ORDER)


def _finding_block(finding: Finding, *, show_host: bool = False) -> list[str]:
    head = f"#### {finding.id} — {finding.title}"
    lines = [head, ""]
    meta = [f"**Severity:** {finding.severity.value}", f"**Vector:** {finding.vector.value} ({finding.vector.title})"]
    if show_host and finding.host:
        meta.append(f"**Host:** `{finding.host}`")
    if finding.hosts and not finding.host:
        shown = ", ".join(f"`{h}`" for h in finding.hosts[:8])
        more = f" (+{len(finding.hosts) - 8} more)" if len(finding.hosts) > 8 else ""
        meta.append(f"**Hosts:** {shown}{more}")
    lines.append(" · ".join(meta))
    lines.append("")
    if finding.subject:
        lines.append(f"- **Subject:** `{finding.subject}`")
    if finding.detail:
        lines.append(f"- **Detail:** {finding.detail}")
    if finding.location:
        lines.append(f"- **Location:** `{finding.location}`")
    if finding.owasp:
        lines.append(f"- **OWASP LLM Top 10:** {', '.join(finding.owasp)}")
    if finding.atlas:
        lines.append(f"- **MITRE ATLAS:** {', '.join(finding.atlas)}")
    if finding.fix:
        lines.append(f"- **Fix:** {finding.fix}")
    if finding.evidence:
        lines.append("- **Evidence:**")
        lines.append("")
        lines.append("  ```json")
        for row in json.dumps(finding.evidence, indent=2, default=str).splitlines():
            lines.append(f"  {row}")
        lines.append("  ```")
    lines.append("")
    return lines


def _findings_section(findings: list[Finding], *, show_host: bool = False) -> list[str]:
    if not findings:
        return ["_No findings._", ""]
    lines: list[str] = []
    for severity in SEVERITY_ORDER:
        bucket = [f for f in findings if f.severity is severity]
        if not bucket:
            continue
        lines.append(f"### {severity.value} ({len(bucket)})")
        lines.append("")
        for finding in bucket:
            lines.extend(_finding_block(finding, show_host=show_host))
    return lines


def _vector_table(scores: list[Any]) -> list[str]:
    rows = []
    for vs in scores:
        coverage = "yes" if vs.covered else "not in v0.x scope"
        rows.append([f"V{vs.vector.value}", vs.vector.title, vs.findings, f"{vs.score:.1f}", coverage])
    return _table(["#", "Vector", "Findings", "Score", "Collected"], rows)


# --------------------------------------------------------------------------
# Single host
# --------------------------------------------------------------------------


def host_report_markdown(report: HostReport) -> str:
    inv = report.inventory
    host = inv.host
    lines = [
        f"# EndpointSweep host report — `{inv.hostname}`",
        "",
        f"**Risk score:** {report.score:.1f}/100 ({risk_band(report.score)}) · "
        f"**Max severity:** {report.max_severity.value} · **Findings:** {len(report.findings)}",
        "",
        _severity_line(report.findings),
        "",
        "## Host",
        "",
    ]
    lines += _table(
        ["Field", "Value"],
        [
            ["Hostname", inv.hostname],
            ["OS", f"{host.os.value} {host.os_version}".strip()],
            ["Arch", host.arch or "-"],
            ["Collected at", host.collected_at or "-"],
            ["Collector", f"{host.collector_version or '-'} (schema {host.collector_schema})"],
            ["Elevated collection", "yes" if host.elevated else "no"],
            ["Users scanned", ", ".join(host.users_scanned) or "-"],
        ],
    )

    lines += ["## Inventory", ""]
    lines += _table(
        ["Class", "Count"],
        [
            ["MCP server declarations", len(inv.mcp_servers)],
            ["Agentic CLI tools", len(inv.agentic_tools)],
            ["Local model runtimes", len([r for r in inv.model_runtimes if r.installed])],
            ["IDE AI extensions", len(inv.ide_extensions)],
            ["Manifests with AI SDKs", len([m for m in inv.package_manifests if m.ai_packages])],
            ["Files with key-shaped var names", len(inv.env_key_signals)],
        ],
    )

    if inv.mcp_servers:
        lines += ["### Declared MCP servers", ""]
        lines += _table(
            ["Server", "Client", "Transport", "Invocation", "Env var names", "Config"],
            [
                [
                    s.name,
                    s.client,
                    s.transport.value,
                    f"`{s.invocation or s.url}`",
                    ", ".join(s.env_var_names) or "-",
                    f"`{s.config_path}`",
                ]
                for s in inv.mcp_servers
            ],
        )

    lines += ["## Risk by vector", ""]
    lines += _vector_table(report.vector_scores)

    lines += ["## Findings", ""]
    lines += _findings_section(report.findings)

    if inv.errors:
        lines += ["## Collector notes", ""]
        lines += _table(["Scope", "Message"], [[e.scope, e.message] for e in inv.errors])

    lines += _methodology()
    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------
# Fleet
# --------------------------------------------------------------------------


def _census_sections(census: dict[str, Any]) -> list[str]:
    lines = ["## Shadow-AI census", ""]
    lines.append(
        "What is actually deployed, ranked by how much of the fleet runs it. "
        "The long tail is where unmanaged installs live."
    )
    lines.append("")

    lines += ["### MCP servers by prevalence", ""]
    lines += _table(
        ["Server", "Hosts", "% fleet", "Distinct invocations"],
        [
            [r["name"], r["hosts"], f"{r['prevalence']:.1%}", r.get("variants", 1)]
            for r in census.get("top_servers", [])
        ],
    )

    lines += ["### MCP server packages", ""]
    lines += _table(
        ["Package", "Hosts", "% fleet"],
        [[r["package"], r["hosts"], f"{r['prevalence']:.1%}"] for r in census.get("top_server_packages", [])],
    )

    lines += ["### Agentic CLI tools", ""]
    lines += _table(
        ["Tool", "Hosts", "% fleet", "Version spread"],
        [
            [
                r["name"],
                r["hosts"],
                f"{r['prevalence']:.1%}",
                ", ".join(f"{v} ({c})" for v, c in r.get("versions", {}).items()),
            ]
            for r in census.get("top_agentic_tools", [])
        ],
    )

    lines += ["### IDE AI extensions", ""]
    lines += _table(
        ["Extension", "Hosts", "% fleet"],
        [[r["extension"], r["hosts"], f"{r['prevalence']:.1%}"] for r in census.get("top_ide_extensions", [])],
    )

    lines += ["### Local model runtimes", ""]
    lines += _table(
        ["Runtime", "Hosts", "Running", "% fleet"],
        [
            [r["name"], r["hosts"], r["running"], f"{r['prevalence']:.1%}"]
            for r in census.get("model_runtimes", [])
        ],
    )
    if census.get("top_models"):
        lines += ["### Local models pulled", ""]
        lines += _table(
            ["Model", "Hosts"], [[r["model"], r["hosts"]] for r in census.get("top_models", [])]
        )

    lines += ["### AI SDKs in code manifests", ""]
    lines += _table(
        ["Package", "Hosts", "% fleet"],
        [[r["package"], r["hosts"], f"{r['prevalence']:.1%}"] for r in census.get("top_ai_packages", [])],
    )

    lines += ["### MCP clients in use", ""]
    lines += _table(
        ["Client", "Hosts", "% fleet"],
        [[r["client"], r["hosts"], f"{r['prevalence']:.1%}"] for r in census.get("clients", [])],
    )
    return lines


def fleet_report_markdown(fleet: FleetModel, *, drilldown: int = 15) -> str:
    all_findings = fleet.all_findings
    host_scores = [h.score for h in fleet.hosts]
    bands = band_counts(fleet)
    census = fleet.census or {}

    lines = [
        "# EndpointSweep fleet report",
        "",
        f"**Generated:** {fleet.generated_at} · **EndpointSweep:** v{fleet.tool_version} · "
        f"**Hosts:** {fleet.host_count}",
        "",
        f"**Fleet risk score:** {fleet.score:.1f}/100 ({risk_band(fleet.score)})",
        "",
        "## Executive summary",
        "",
        _severity_line(all_findings),
        "",
    ]
    lines += _table(
        ["Metric", "Value"],
        [
            ["Hosts analysed", fleet.host_count],
            ["Hosts with at least one MCP server", census.get("hosts_with", {}).get("mcp_servers", 0)],
            ["Hosts with an agentic CLI", census.get("hosts_with", {}).get("agentic_tools", 0)],
            ["Hosts with a local model runtime", census.get("hosts_with", {}).get("model_runtimes", 0)],
            ["Total findings", len(all_findings)],
            ["Fleet-level findings", len(fleet.findings)],
            ["Median host score", f"{percentile(host_scores, 50):.1f}"],
            ["p95 host score", f"{percentile(host_scores, 95):.1f}"],
            [
                "Hosts by band",
                " · ".join(f"{k} {v}" for k, v in bands.items()),
            ],
            ["OS breakdown", " · ".join(f"{k} {v}" for k, v in census.get("os_breakdown", {}).items())],
        ],
    )

    top_issues = Counter(
        (f.id, f.title) for f in all_findings if f.severity.rank >= Severity.MEDIUM.rank
    )
    lines += ["### Most common actionable findings", ""]
    lines += _table(
        ["Check", "Title", "Occurrences"],
        [[cid, title, count] for (cid, title), count in top_issues.most_common(10)],
    )

    lines += ["## Risk by vector", ""]
    lines += _vector_table(fleet.vector_scores)

    lines += _census_sections(census)

    lines += ["## Fleet-level findings", ""]
    lines += [
        "Findings that only exist across hosts — no single-machine scanner can produce these.",
        "",
    ]
    lines += _findings_section(fleet.findings)

    lines += ["## Hosts by risk", ""]
    lines += _table(
        ["Host", "OS", "Score", "Band", "Max severity", "Findings", "MCP servers"],
        [
            [
                h.inventory.hostname,
                h.inventory.host.os.value,
                f"{h.score:.1f}",
                risk_band(h.score),
                h.max_severity.value,
                len(h.findings),
                len(h.inventory.mcp_servers),
            ]
            for h in fleet.hosts
        ],
    )

    if drilldown:
        lines += ["## Per-host drill-down", ""]
        shown = [h for h in fleet.hosts if h.findings][:drilldown]
        if len(fleet.hosts) > len(shown):
            lines.append(
                f"_Showing the {len(shown)} highest-risk hosts of {fleet.host_count}. "
                "Use `endpointsweep report --drilldown 0` to omit, or `--drilldown N` for more._"
            )
            lines.append("")
        for host_report in shown:
            lines.append(
                f"### `{host_report.inventory.hostname}` — {host_report.score:.1f}/100 "
                f"({risk_band(host_report.score)})"
            )
            lines.append("")
            lines.append(_severity_line(host_report.findings))
            lines.append("")
            lines += _table(
                ["Check", "Severity", "Subject", "Detail"],
                [
                    [f.id, f.severity.value, f.subject, f.detail]
                    for f in host_report.findings
                    if f.severity is not Severity.INFO
                ],
            )

    lines += _check_catalog_appendix()
    lines += _methodology()
    return "\n".join(lines).rstrip() + "\n"


def _check_catalog_appendix() -> list[str]:
    lines = ["## Appendix A — checks run", ""]
    rows = []
    for check in sorted(REGISTRY.values(), key=lambda c: c.meta.id):
        m = check.meta
        rows.append(
            [
                m.id,
                m.severity.value,
                f"V{m.vector.value}",
                m.scope,
                m.title,
                ", ".join(m.owasp) or "-",
            ]
        )
    lines += _table(["ID", "Severity", "Vector", "Scope", "Title", "OWASP"], rows)
    return lines


def _methodology() -> list[str]:
    return [
        "## Appendix B — methodology and limits",
        "",
        "- Collectors report **metadata only**: variable NAMES and file PATHS, never values, "
        "file contents, or user documents (brief §4.3).",
        "- Checks are deterministic pattern and statistics checks over declared configuration. "
        "No traffic is intercepted and no model is consulted.",
        "- A declared MCP server is evidence of configuration, not of use: EndpointSweep reports "
        "what an agent *could* do on that endpoint, not what it did.",
        "- Risk scores saturate (see `docs/rubric.md`): the tenth HIGH on a host does not read "
        "as ten times the first, but it does read as worse.",
        f"- Vectors {', '.join(f'V{v.value}' for v in (Vector.BROWSER_AI_MODES, Vector.BROWSER_AI_EXTENSIONS))} "
        "(browser AI modes and extensions) are in the rubric but are not collected in v0.x; "
        "they are shown as coverage gaps rather than as clean.",
        "",
    ]
