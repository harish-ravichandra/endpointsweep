"""Single-file HTML fleet report — no CDN, no JavaScript dependencies.

Written to survive being emailed around: one self-contained file, readable in
light and dark, printable to PDF for the people who will ask for a PDF.
"""

from __future__ import annotations

import html
from collections.abc import Iterable
from typing import Any

from ..schema import FleetModel, Severity
from ..scoring import band_counts, percentile, risk_band

_SEVERITIES = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)

_CSS = """
:root { color-scheme: light dark; --bg:#fbfbf9; --fg:#1b1b1a; --muted:#6b6b66;
  --line:#e2e2dc; --card:#ffffff; --crit:#b3261e; --high:#c2410c; --med:#a16207;
  --low:#0f766e; --info:#52525b; }
@media (prefers-color-scheme: dark) { :root { --bg:#16161a; --fg:#ececea;
  --muted:#9a9a94; --line:#2c2c31; --card:#1d1d22; --crit:#f87171; --high:#fb923c;
  --med:#fbbf24; --low:#5eead4; --info:#a1a1aa; } }
* { box-sizing:border-box; }
body { margin:0; padding:0; background:var(--bg); color:var(--fg);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
main { max-width:1100px; margin:0 auto; padding:32px 20px 80px; }
h1 { font-size:28px; margin:0 0 4px; letter-spacing:-0.02em; }
h2 { font-size:20px; margin:40px 0 12px; padding-bottom:6px; border-bottom:1px solid var(--line); }
h3 { font-size:16px; margin:24px 0 8px; }
.sub { color:var(--muted); margin:0 0 24px; }
.cards { display:flex; flex-wrap:wrap; gap:12px; margin:16px 0 8px; }
.card { flex:1 1 150px; background:var(--card); border:1px solid var(--line);
  border-radius:10px; padding:12px 14px; }
.card .n { font-size:26px; font-weight:650; letter-spacing:-0.02em; }
.card .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; }
table { width:100%; border-collapse:collapse; margin:10px 0 20px; font-size:14px; }
th,td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.05em; }
tbody tr:hover { background:color-mix(in srgb, var(--card) 70%, transparent); }
code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; }
.pill { display:inline-block; padding:1px 8px; border-radius:999px; font-size:12px;
  font-weight:600; border:1px solid currentColor; }
.CRITICAL{color:var(--crit)} .HIGH{color:var(--high)} .MEDIUM{color:var(--med)}
.LOW{color:var(--low)} .INFO{color:var(--info)}
.wrap { overflow-x:auto; }
footer { color:var(--muted); font-size:13px; margin-top:48px; border-top:1px solid var(--line); padding-top:16px; }
@media (max-width:640px){ main{padding:20px 14px 60px} h1{font-size:22px} }
"""


class _Raw(str):
    """Marker for pre-escaped HTML fragments."""


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _table(headers: list[str], rows: Iterable[Iterable[Any]]) -> str:
    body = "".join(
        "<tr>" + "".join(f"<td>{c if isinstance(c, _Raw) else _e(c)}</td>" for c in row) + "</tr>"
        for row in rows
    )
    if not body:
        return "<p class='sub'>none</p>"
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    return f"<div class='wrap'><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def _pill(severity: Severity) -> _Raw:
    return _Raw(f"<span class='pill {severity.value}'>{severity.value}</span>")


def fleet_report_html(fleet: FleetModel) -> str:
    census = fleet.census or {}
    findings = fleet.all_findings
    counts = {s: sum(1 for f in findings if f.severity is s) for s in _SEVERITIES}
    scores = [h.score for h in fleet.hosts]
    bands = band_counts(fleet)

    cards = "".join(
        f"<div class='card'><div class='n {s.value}'>{counts[s]}</div>"
        f"<div class='l'>{s.value.lower()}</div></div>"
        for s in _SEVERITIES
    )

    summary = _table(
        ["Metric", "Value"],
        [
            ["Hosts analysed", fleet.host_count],
            ["Fleet risk score", f"{fleet.score:.1f}/100 ({risk_band(fleet.score)})"],
            ["Median host score", f"{percentile(scores, 50):.1f}"],
            ["p95 host score", f"{percentile(scores, 95):.1f}"],
            ["Hosts by band", " · ".join(f"{k} {v}" for k, v in bands.items())],
            ["OS breakdown", " · ".join(f"{k} {v}" for k, v in census.get("os_breakdown", {}).items())],
            ["Fleet-level findings", len(fleet.findings)],
        ],
    )

    servers = _table(
        ["Server", "Hosts", "% fleet", "Variants"],
        [
            [r["name"], r["hosts"], f"{r['prevalence']:.1%}", r.get("variants", 1)]
            for r in census.get("top_servers", [])
        ],
    )
    tools = _table(
        ["Agentic CLI", "Hosts", "% fleet", "Versions"],
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
    runtimes = _table(
        ["Runtime", "Hosts", "Running", "% fleet"],
        [
            [r["name"], r["hosts"], r["running"], f"{r['prevalence']:.1%}"]
            for r in census.get("model_runtimes", [])
        ],
    )

    fleet_findings = _table(
        ["Check", "Severity", "Subject", "Hosts", "Detail"],
        [
            [f.id, _pill(f.severity), f.subject, len(f.hosts), f.detail]
            for f in fleet.findings
        ],
    )

    hosts = _table(
        ["Host", "OS", "Score", "Band", "Max severity", "Findings", "MCP servers"],
        [
            [
                h.inventory.hostname,
                h.inventory.host.os.value,
                f"{h.score:.1f}",
                risk_band(h.score),
                _pill(h.max_severity),
                len(h.findings),
                len(h.inventory.mcp_servers),
            ]
            for h in fleet.hosts
        ],
    )

    actionable = [f for f in findings if f.severity.rank >= Severity.MEDIUM.rank and f.host]
    per_host = _table(
        ["Host", "Check", "Severity", "Subject", "Detail"],
        [[f.host, f.id, _pill(f.severity), f.subject, f.detail] for f in actionable[:300]],
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EndpointSweep fleet report</title>
<style>{_CSS}</style></head>
<body><main>
<h1>EndpointSweep fleet report</h1>
<p class="sub">{_e(fleet.generated_at)} · v{_e(fleet.tool_version)} · {fleet.host_count} hosts</p>
<div class="cards">{cards}</div>
<h2>Executive summary</h2>{summary}
<h2>Shadow-AI census</h2>
<h3>MCP servers by prevalence</h3>{servers}
<h3>Agentic CLI tools</h3>{tools}
<h3>Local model runtimes</h3>{runtimes}
<h2>Fleet-level findings</h2>{fleet_findings}
<h2>Hosts by risk</h2>{hosts}
<h2>Actionable per-host findings</h2>{per_host}
<footer>Metadata only: variable names and file paths, never values or file contents.
Declared configuration is evidence of capability, not of use.</footer>
</main></body></html>
"""
