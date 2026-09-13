# EndpointSweep

**Find every MCP server and AI agent on your fleet — before your attacker does.**

Nmap + osquery for the agentic AI era: discover every MCP server, agentic CLI and
AI integration running across an endpoint fleet, audit each against a published
risk rubric, and aggregate the findings into one report — built to run under real
EDR/MDM deployment constraints.

[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

---

## Why this exists

The per-machine MCP scanner niche is crowded and good: [MCP-Scan][mcp-scan],
[mcp-audit][mcp-audit], [MCTS][mcts] and others all answer *"is this laptop's MCP
configuration safe?"* well.

Nobody answers the enterprise question:

> **What MCP servers and agentic AI tools exist across my 20,000 endpoints, what
> can they touch, and which ones violate policy?**

That question needs a different shape of tool: tiny collectors that survive real
fleet-deployment constraints, and a central analyzer that can compare hosts to
each other. **Run mcp-audit on one box; run EndpointSweep on ten thousand.**

Three findings in this tool cannot exist on a single machine at all:

- **ES-901** — one server name resolving to different commands across the fleet.
  Every host looks internally consistent; the divergence is the finding.
- **ES-902** — a server on 0.4% of the fleet and on no approved-software list.
  Rarity is only measurable against a denominator.
- **ES-903** — the census: what is actually deployed, ranked by prevalence.

[mcp-scan]: https://github.com/invariantlabs-ai/mcp-scan
[mcp-audit]: https://pypi.org/project/mcp-audit-scanner/
[mcts]: https://github.com/mcp-audit/mcts

---

## Install

```sh
git clone https://github.com/endpointsweep/endpointsweep
cd endpointsweep
pip install -e .
```

Python 3.10+, standard library only. The collectors have no dependencies at all.

This installs two identical entry points: `endpointsweep` and the short alias
`esweep`. The rest of this README uses the long form; use whichever you prefer.

---

## Quick start

### One machine (the on-ramp)

`endpointsweep scan` runs this machine's collector and analyses the result — same
output as below, for your own laptop:

```console
$ endpointsweep analyze testdata/hosts/ws-win-1175.json
# EndpointSweep host report — `ws-win-1175`

**Risk score:** 82.5/100 (CRITICAL) · **Max severity:** CRITICAL · **Findings:** 8

**CRITICAL** 1 · **HIGH** 3 · **MEDIUM** 0 · **LOW** 0 · **INFO** 4
...
### CRITICAL (1)

#### ES-201 — Imperative-instruction pattern in MCP tool description (tool poisoning)

**Severity:** CRITICAL · **Vector:** 4 (Local MCP servers)

- **Subject:** `notes:read_file`
- **Detail:** tool description matches 4 injection pattern(s): fake-system-tag,
  conceal-from-user, mandatory-tool-call, tool-ordering-hijack
- **Location:** `C:\Users\morgan\.cursor\mcp.json`
- **OWASP LLM Top 10:** LLM01: Prompt Injection, LLM04: Data and Model Poisoning
- **MITRE ATLAS:** AML.T0051: LLM Prompt Injection, AML.T0053: LLM Plugin Compromise
- **Fix:** Treat the server as compromised until proven otherwise: disable it,
  diff the tool descriptions against the upstream source, and pin the package version.

$ echo $?
1
```

### A fleet

```sh
# 1. Push a collector with your MDM/EDR (see deploy/) and collect the JSON.
# 2. Merge and report.
endpointsweep merge collected/ -o fleet.json
endpointsweep report fleet.json -o fleet.md
endpointsweep report fleet.json -f sarif -o fleet.sarif   # into your scanning pipeline
endpointsweep report fleet.json -f html  -o fleet.html    # for the people who want a PDF
```

### Try it on the synthetic fleet

The repo ships 28 synthetic hosts (all invented — no real fleet data, ever):

```console
$ endpointsweep report testdata/hosts --drilldown 0 | head -20
# EndpointSweep fleet report

**Generated:** 2026-09-14T04:00:00+00:00 · **EndpointSweep:** v0.1.0 · **Hosts:** 28

**Fleet risk score:** 38.4/100 (MODERATE)

## Executive summary

**CRITICAL** 3 · **HIGH** 29 · **MEDIUM** 23 · **LOW** 0 · **INFO** 74

| Metric | Value |
|---|---|
| Hosts analysed | 28 |
| Hosts with at least one MCP server | 22 |
| Hosts with an agentic CLI | 21 |
| Hosts with a local model runtime | 5 |
| Total findings | 129 |
| Fleet-level findings | 10 |
| Median host score | 13.3 |
| p95 host score | 80.9 |
| Hosts by band | LOW 14 · MODERATE 4 · ELEVATED 5 · CRITICAL 5 |
```

The census section is the part people actually read (excerpt, aligned for
legibility — the real table is markdown):

```
### MCP servers by prevalence

| Server              | Hosts | % fleet | Distinct invocations |
|---------------------|-------|---------|----------------------|
| memory              |    15 |   53.6% |                    1 |
| sequential-thinking |    13 |   46.4% |                    1 |
| time                |     9 |   32.1% |                    1 |
| filesystem          |     8 |   28.6% |                    1 |
| internal-docs       |     6 |   21.4% |                    1 |
| github              |     4 |   14.3% |                    1 |
| internal-tools      |     4 |   14.3% |                    3 |  <- ES-901
| …                                                              |
| desktop-commander   |     1 |    3.6% |                    1 |  <- ES-902
```

---

## How it works

```
                 endpoint                          central
  ┌──────────────────────────────┐      ┌───────────────────────────────┐
  │ endpointsweep_collect.sh/.bash  │      │  endpointsweep analyze           │
  │ endpointsweep_collect.ps1       │ JSON │    parsers → checks → score   │
  │                              │ ───► │                               │
  │  · MCP client configs        │      │  endpointsweep merge             │
  │  · agentic CLIs, IDE plugins │      │    N hosts → fleet model      │
  │  · model runtimes, manifests │      │    → ES-9xx fleet checks      │
  │  · credential-shaped NAMES   │      │                               │
  │                              │      │  endpointsweep report            │
  │  no deps · root-tolerant     │      │    Markdown · SARIF · HTML    │
  └──────────────────────────────┘      └───────────────────────────────┘
```

**Collectors** are tiny and constraint-compliant, because that is the part that
has to survive an MDM console. **Everything else is central**, because that is
where it can be tested, reviewed, and changed without touching 20,000 endpoints.

### The collector contract

```sh
endpointsweep_collect.sh   [OUTPUT_JSON_PATH]   # macOS   — POSIX sh, .sh extension
endpointsweep_collect.bash [OUTPUT_JSON_PATH]   # Linux
endpointsweep_collect.ps1  [OUTPUT_JSON_PATH]   # Windows — PowerShell 5.1
```

- With a path: JSON goes to the file, the summary line goes to **stdout**.
- Without one: JSON goes to **stdout**, the summary line goes to **stderr**.
- Exit `0` = nothing flagged, `1` = something flagged, `2` = the collector failed.

```
ENDPOINTSWEEP|ws-mac-1042|9|HIGH
```

One line, under 500 characters, so it survives a console that truncates stdout —
and an exit code, for the consoles that only trust exit codes. See
[deploy/](deploy/) for Endpoint Central, Jamf, Intune and ssh recipes.

---

## The red line

**EndpointSweep reports variable NAMES and file PATHS. It never reports a value.**

This is enforced in four places, not asserted in a README:

1. **The collectors** cut each rc-file line at the first `=` before the name
   reaches a pipeline, and pass every config file through an embedded
   JSONC-aware redactor that replaces the value of any `env`/`headers`/
   credential-shaped key with `"[redacted]"` before it is written.
2. **The parsers** drop the `env` mapping entirely at the boundary, and strip
   credential-shaped segments out of remote server URLs.
3. **The schema** has no field that can hold a value — `MCPServer.env_var_names`
   exists, `MCPServer.env` does not — and `to_json()` refuses to serialise any
   structure containing a forbidden key.
4. **The tests** prove it: every schema dataclass is inspected for value-bearing
   fields, and the Linux collector is executed against a fake home seeded with
   real-looking secrets, which must not appear in its output.

The collectors also never execute a binary from a user-writable path while
running as root — a fleet script that runs `~/.local/bin/claude --version` as
root is a privilege-escalation primitive, not an inventory tool.

---

## The check catalog

17 checks, each carrying an ID, severity, vector, OWASP LLM Top 10 and MITRE
ATLAS mapping, and fix guidance. Full detail in [docs/checks.md](docs/checks.md).

```console
$ endpointsweep checks
ES-101  HIGH     V4 host  MCP server has local command-execution capability
ES-102  HIGH     V4 host  Filesystem MCP server rooted at a filesystem or home directory
ES-103  MEDIUM   V4 host  Network-egress MCP server with unrestricted host scope
ES-104  HIGH     V4 host  MCP server binary runs from a user- or world-writable path
ES-105  MEDIUM   V4 host  MCP server declared in an elevated (root/SYSTEM) scope
ES-201  CRITICAL V4 host  Imperative-instruction pattern in MCP tool description (tool poisoning)
ES-202  MEDIUM   V4 host  Anomalous MCP tool description length, entropy or character mix
ES-301  HIGH     V7 host  MCP server launched from an unpinned package version
ES-302  MEDIUM   V7 host  MCP server package name is a near-miss of a known server (typosquat)
ES-303  MEDIUM   V7 host  MCP server package is very new or has a single maintainer [--online]
ES-401  HIGH     V8 host  Credential-shaped variable names embedded in an MCP server config
ES-402  MEDIUM   V8 host  Credential-shaped variable names in shell rc or .env files
ES-403  LOW      V5 host  Local model runtime listening on a non-loopback interface
ES-404  INFO     V3 host  Shadow-AI inventory (census signal, not an alert)
ES-901  HIGH     V4 fleet Same MCP server name resolves to different commands across the fleet
ES-902  MEDIUM   V4 fleet Long-tail MCP server installed on a small fraction of the fleet
ES-903  INFO     V3 fleet Fleet shadow-AI census
```

Everything is deterministic and offline by default. Exactly one check (ES-303)
makes a network request, and only behind `--online`.

---

## The rubric

[docs/rubric.md](docs/rubric.md) is the durable part of this project: a
tool-agnostic way to describe enterprise AI exposure that outlives the MCP spec.

- **Eight vectors** — browser AI modes, browser AI extensions, agentic AI, local
  MCP servers, local model runtimes, IDE AI plugins, AI libraries, direct
  API-key integrations.
- **Six capability axes** — execution, filesystem reach, network reach,
  credential exposure, privilege, provenance & control.
- **A scoring formula you can reproduce by hand**, that saturates, with honest
  coverage reporting: vectors EndpointSweep does not yet collect are shown as gaps,
  never as clean.

---

## Commands

| Command | What it does |
|---|---|
| `endpointsweep scan` | Run this machine's collector, then analyse it |
| `endpointsweep analyze HOST.json...` | Analyse collector output, one report per host |
| `endpointsweep merge HOSTS/ -o fleet.json` | N hosts → one scored fleet model |
| `endpointsweep report fleet.json` | Markdown (default), `-f html\|sarif\|json` |
| `endpointsweep checks` | Print the catalog (`-f json` for machines) |
| `endpointsweep collector --os macos --print` | Emit a collector for deployment |

`esweep` is a drop-in alias for `endpointsweep` on every command above.

Useful flags: `--fail-on {none,info,low,medium,high,critical}` (default `high`)
for CI exit codes, `--managed-software FILE` to suppress expected long-tail
installs, `--rare-threshold` to tune ES-902, `--online` to enable ES-303.

---

## Project layout

```
collectors/    three self-contained endpoint scripts (the deployable part)
endpointsweep/    parsers → checks → scoring → merge → report
  checks/      one module per family; registry pattern; ES-1xx … ES-9xx
  parsers/     one module per client config shape
  report/      markdown, sarif, html
plugins/       optional: fold mcp-scan / mcp-audit output into the fleet report
testdata/      28 synthetic hosts, config fixtures, golden expectations, SARIF schema
deploy/        Endpoint Central, Jamf, Intune, ssh recipes
docs/          rubric.md (the IP), checks.md (the catalog)
```

---

## Development

```sh
pip install -e ".[dev]"
pytest            # 165 tests, incl. live collector runs and SARIF schema validation
ruff check .
python3 testdata/generate_fleet.py    # regenerate the synthetic fleet
python3 testdata/generate_golden.py   # regenerate golden expectations, then read the diff
```

Adding a check: [docs/checks.md § Adding a check](docs/checks.md#adding-a-check).
`tests/test_docs.py` fails the build if a check is not documented.

---

## Scope

**In scope:** discovery, audit, aggregation, reporting.

**Out of scope, deliberately:** runtime proxying and traffic inspection (MCP-Scan
owns that lane); LLM-based semantic analysis of tool descriptions (checks stay
deterministic); remediation and enforcement (report first, enforce later); and
any transmission of secret values, file contents or user documents.

## Credits

EndpointSweep stands on work done by others in the open: [MCP-Scan][mcp-scan] for
naming tool poisoning and rug pulls, [mcp-audit][mcp-audit] for the OWASP MCP
mapping, and [MCTS][mcts] for live tool discovery. They solve the single-machine
problem well — `plugins/external_scanners.py` will fold their output into an
EndpointSweep fleet report rather than duplicate it.

Mappings reference the OWASP LLM Top 10 (2025) and MITRE ATLAS.

## License

MIT. All test data in this repository is synthetic.
