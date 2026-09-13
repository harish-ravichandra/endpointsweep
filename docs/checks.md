# Check catalog v0.1

Every check EndpointSweep ships, what it looks at, what it will and will not catch,
and what to do about it. IDs are stable: once published, an `ES-###` never means
something else.

Severity and vector definitions live in [rubric.md](rubric.md). `endpointsweep
checks -f json` prints this catalog in machine-readable form; the table below is
generated from the same registry.

| ID | Severity | Vector | Scope | Title |
|---|---|---|---|---|
| ES-101 | HIGH | V4 | host | MCP server has local command-execution capability |
| ES-102 | HIGH | V4 | host | Filesystem MCP server rooted at a filesystem or home directory |
| ES-103 | MEDIUM | V4 | host | Network-egress MCP server with unrestricted host scope |
| ES-104 | HIGH | V4 | host | MCP server binary runs from a user- or world-writable path |
| ES-105 | MEDIUM | V4 | host | MCP server declared in an elevated (root/SYSTEM) scope |
| ES-201 | CRITICAL | V4 | host | Imperative-instruction pattern in MCP tool description (tool poisoning) |
| ES-202 | MEDIUM | V4 | host | Anomalous MCP tool description length, entropy or character mix |
| ES-301 | HIGH | V7 | host | MCP server launched from an unpinned package version |
| ES-302 | MEDIUM | V7 | host | MCP server package name is a near-miss of a known server (typosquat) |
| ES-303 | MEDIUM | V7 | host | MCP server package is very new or has a single maintainer |
| ES-401 | HIGH | V8 | host | Credential-shaped variable names embedded in an MCP server config |
| ES-402 | MEDIUM | V8 | host | Credential-shaped variable names in shell rc or .env files |
| ES-403 | LOW | V5 | host | Local model runtime listening on a non-loopback interface |
| ES-404 | INFO | V3 | host | Shadow-AI inventory (census signal, not an alert) |
| ES-901 | HIGH | V4 | fleet | Same MCP server name resolves to different commands across the fleet |
| ES-902 | MEDIUM | V4 | fleet | Long-tail MCP server installed on a small fraction of the fleet |
| ES-903 | INFO | V3 | fleet | Fleet shadow-AI census |

Two severities are dynamic, and the finding always says which applied:

- A **disabled** server is reported one step below its live severity (rubric §4).
- A check may **escalate**: ES-101 becomes CRITICAL when execution is
  auto-approved; ES-103 becomes HIGH when the endpoint URL carries a credential;
  ES-302 becomes HIGH at edit-distance 1.

---

## ES-1xx — Capability and scope (vector 4)

### ES-101 — Local command-execution capability

**Detects.** A server whose `command` is a shell or interpreter (`sh`, `bash`,
`zsh`, `cmd`, `powershell`, `pwsh`, `osascript`, `perl`, `ruby`, …); a runtime
invoked with an inline-code flag (`python -c`, `node -e`, `deno eval`); a package
name matching a known execution server (`mcp-server-commands`,
`desktop-commander`, `iterm-mcp`, …); or a cached tool list advertising
`run_command` / `execute` / `shell` / `terminal`.

**Escalates to CRITICAL** when one of those tools also appears in the client's
`autoApprove` / `alwaysAllow` list — at that point there is no human between a
poisoned tool description and a process.

**Why.** A1 in the rubric. Every other finding on the host gets worse if this one
is present: injection stops being a content problem and becomes code execution
in the user's security context.

**Evidence.** `command`, `args`, `auto_approved`, `user`.

**False positives.** `node /opt/app/server.js` is *not* flagged — running a
JavaScript server is not the same as evaluating attacker-supplied JavaScript.
A wrapper script that happens to be named `*-shell-*` will be flagged; confirm
what it wraps.

**Fix.** Remove it, or replace it with a task-specific server. If execution is
genuinely required, allow-list the commands and require per-call approval.

---

### ES-102 — Filesystem server rooted at a filesystem or home directory

**Detects.** A path argument of `/`, `~`, `/Users`, `/home`, `/Volumes`, `C:\`,
or a wildcard high in the tree, on a server that looks filesystem-capable (by
package name or by advertised file tools).

**Downgraded to MEDIUM** when the root-scoped argument is on a server with no
filesystem signal — weaker evidence, still worth a look.

**Why.** A2. A filesystem server scoped to `~` can read SSH keys, browser
profiles, cloud credential files and every source tree on the box.

**Evidence.** `scopes` (the offending arguments), `command`, `args`.

**False positives.** A server that takes a root path but enforces its own
allow-list internally. The check cannot see inside the binary; confirm with the
server's documentation.

**Fix.** Re-scope to the specific project directories the work needs.

---

### ES-103 — Network-egress server with unrestricted host scope

**Detects.** Fetch/browser/crawler servers (`server-fetch`, `puppeteer`,
`playwright`, `crawl4ai`, `mcp-proxy`, …) with no `--allow`/`--allowed-hosts`/
`--domains`-style argument; **or** a remote `http`/`sse` transport pointing at a
non-loopback endpoint.

**Escalates to HIGH** when the endpoint URL contains a credential-shaped path
segment or query value. EndpointSweep redacts that segment before it stores the URL,
and records that it did.

**Why.** A3. An egress-capable tool with model-chosen destinations is an
exfiltration channel that needs no malware.

**Evidence.** `command`, `args`, `url` (redacted), `url_carries_secret`.

**False positives.** A fetch server pinned to one API by an environment variable
EndpointSweep cannot read the value of. Egress through a proxy that enforces the
allow-list centrally is a legitimate reason to suppress this check.

**Fix.** Constrain to an allow-list, or enforce one at the egress proxy. Rotate
any credential that was living in a URL.

---

### ES-104 — Server binary in a user- or world-writable path

**Detects.** A resolved command path or leading argument under `/tmp`,
`/var/tmp`, `/dev/shm`, `/Users/Shared`, `%TEMP%`, `C:\Users\Public`, a
`Downloads` directory — or a binary whose mode grants write to others (`o+w`).

**Why.** A6. Whoever can rewrite the file inherits every permission the agent has
granted the server, silently, with no config change to detect.

**Evidence.** `command`, `command_path`, `command_mode`, `writable_paths`.

**False positives.** A build directory that is genuinely temporary during
development. On a managed endpoint it should not be the launch path.

**Fix.** Move the server under a managed, root-owned install path; tighten to
`0755` or stricter.

---

### ES-105 — Declared in an elevated scope

**Detects.** A server launched via `sudo`/`doas`/`runas`/`pkexec`, declared in a
root/SYSTEM-owned config scope (`/Library`, `/etc`, `%ProgramData%`), or whose
config is owned by `root`/`SYSTEM`.

**Why.** A5. The tools act with administrative rights, outside the user's blast
radius and usually outside the user's awareness.

**Evidence.** `command`, `user`, `config`.

**False positives.** A deliberately fleet-managed server deployed system-wide.
That is a legitimate pattern — the finding is still correct, and the answer is an
approved-software entry, not a code change.

**Fix.** Move the declaration to user scope and drop elevation.

---

## ES-2xx — Injection surface (vectors 3 and 4)

Tool descriptions are attacker-controlled text that the model reads as trusted
instructions. Both checks are deterministic: patterns and statistics, no model in
the loop (a design constraint, not a limitation to fix later).

### ES-201 — Imperative-instruction pattern in a tool description

**Detects.** Fourteen pattern families, reported by name in the evidence:
`ignore-previous-instructions`, `disregard-instructions`, `fake-system-tag`
(`<system>`, `<IMPORTANT>`), `bracket-system-tag`, `conceal-from-user`
("do not tell the user"), `mandatory-tool-call` ("you must always call"),
`tool-ordering-hijack` ("before using any other tool"),
`credential-read-instruction` (`.env`, `id_rsa`, `.ssh`, `.aws`, keychain),
`exfil-instruction`, `hidden-html-comment`, `zero-width-characters`,
`ansi-control-sequence`, `private-use-glyphs`, `tag-block-smuggling`.

**Why.** LLM01. This is the tool-poisoning and rug-pull class: the description a
user approved on Monday is not necessarily the description the model reads on
Friday.

**Evidence.** `server`, `tool`, `patterns`, `excerpt` (unicode-escaped so control
characters are visible in a terminal and a report), `description_chars`.

**False positives.** A legitimate description that says "always call `init`
first". Read the excerpt: the question is whether the instruction addresses the
*model* about *other tools*, and whether it tries to hide anything.

**Fix.** Treat the server as compromised until proven otherwise: disable it, diff
the descriptions against the upstream source, pin the version.

---

### ES-202 — Anomalous description length, entropy or character mix

**Detects.** Descriptions over 1500 characters; non-ASCII ratio above 0.15 on
text longer than 80 characters; Shannon entropy above 4.7 bits/char on text
longer than 300; or a base64-shaped run of 100+ characters.

**Why.** Smuggling shows up as a statistical anomaly before it matches a known
pattern. This is the check that catches the payload ES-201 has no signature for.

**Evidence.** `anomalies`, `entropy`, `description_chars`, `excerpt`.

**False positives.** Genuinely long API documentation, and non-English
descriptions — which is exactly why this is MEDIUM and never fires an alert on
its own.

**Fix.** Compare against the upstream published documentation. If it does not
match, treat it as ES-201.

---

## ES-3xx — Supply chain (vector 7)

Applies only to servers launched through a package runner (`npx`, `bunx`, `uvx`,
`pipx`, `pnpm dlx`). A bare binary or a local script has no registry provenance
to check, and is not flagged here.

### ES-301 — Unpinned package version

**Detects.** No version in the spec, a mutable tag (`@latest`, `@next`, `@beta`,
`*`), or a range (`^1.2.0`, `~1.2`). Notes separately when the package is also
installed non-interactively (`-y`).

**Why.** A6. `npx -y pkg` re-resolves on every agent start. The code that ran
yesterday is not the code that runs today, and a compromised release reaches the
whole fleet without a single endpoint changing.

**Evidence.** `package`, `spec`, `ecosystem`, `command`, `args`.

**False positives.** None in substance — an unpinned dependency is unpinned. The
judgement call is whether you accept it, and that belongs in an approved-software
decision.

**Fix.** Pin an exact version, or vendor the server into a managed internal
registry.

---

### ES-302 — Typosquat-shaped package name

**Detects.** A package name at Levenshtein distance 1 or 2 from a name in
`endpointsweep/data/known_packages.json` (58 widely deployed MCP servers), for names
of at least 8 characters. Distance 1 escalates to HIGH.

**Why.** Registry typosquats of popular MCP servers are cheap: the config looks
right at a glance and the impostor inherits the same tool permissions.

**Evidence.** `package`, `nearest_known`, `distance`.

**False positives.** A legitimate fork or an internal package that deliberately
mirrors an upstream name. Add it with `--known-packages` and the check goes
quiet, per host or fleet-wide.

**Fix.** Verify against the upstream project's published name and repository,
then pin.

---

### ES-303 — Very new or single-maintainer package *(requires `--online`)*

**Detects.** First published under 30 days ago, or exactly one maintainer
account, per the npm or PyPI registry.

**Why.** No reputation, and no second pair of eyes on releases.

**Evidence.** `package`, `ecosystem`, `created`, `maintainers`.

**Network behaviour.** The only check that makes a network request. Skipped
unless `--online` is passed; 6-second timeout; a failed lookup produces no
finding rather than a false one. It queries public registry metadata for package
names only — never host data.

**Fix.** Require review before fleet-wide use; pin, and re-review on upgrade.

---

## ES-4xx — Hygiene (vectors 3, 5, 6, 7, 8)

### ES-401 — Credential-shaped variable names in a server config

**Detects.** Names in a server's `env` block matching the credential name shapes
(`*API_KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*CREDENTIAL*`,
`*PRIVATE_KEY*`, `*_PAT`, `*_KEY`, …).

**Why.** A4. Client configs are readable in the user's profile, sync to backup
and settings-sync services, and get pasted into support tickets.

**Evidence.** `variable_names`, `config_path`, `user`. **Nothing else — the
schema has no field that could hold a value** (see `tests/test_schema.py`).

**False positives.** A variable whose *name* looks credential-shaped but holds a
path or a flag (`OPENAI_API_KEY_FILE`). The finding is still worth a glance.

**Fix.** Move the secret to the platform keychain or a broker the server reads at
start-up, and rotate anything that has lived in a config file.

---

### ES-402 — Credential-shaped variable names in shell rc or `.env` files

**Detects.** The same name shapes in shell rc files (`.zshrc`, `.bashrc`,
`.profile`, PowerShell profiles) and `.env` files inside the scanned project
roots. The collector cuts each line at the first `=` before the name ever reaches
a pipeline — the value is not read, not just not reported.

**Why.** A4. Keys exported from an rc file are inherited by every agent and MCP
server that user starts. One poisoned tool call reaches all of them.

**Evidence.** `variable_names`, `path`, `kind` (`shell_rc` or `dotenv`), `user`.

**Fix.** Secret manager, sourced on demand; per-project keys in a `.env` excluded
from backup and sync.

---

### ES-403 — Local model runtime on a non-loopback interface

**Detects.** A runtime listening on `0.0.0.0`, `::`, or `*`. **MEDIUM** when the
runtime is running, **LOW** when it is installed but stopped.

**Why.** An Ollama endpoint bound to `0.0.0.0` is an unauthenticated inference
API on the corporate network: anyone on the segment can use the host's GPU, list
its models, and prompt it.

**Evidence.** `runtime`, `listen_addrs`, `running`, `models`.

**False positives.** A deliberate shared inference host. Suppress by policy, not
by ignoring it.

**Fix.** Bind to `127.0.0.1` (`OLLAMA_HOST=127.0.0.1:11434`) and add a host
firewall rule.

---

### ES-404 — Shadow-AI inventory *(informational)*

**Detects.** Nothing wrong. Emits one INFO finding per class present on the host
— agentic CLIs (V3), IDE AI extensions (V6), AI SDKs in manifests (V7), local
model runtimes (V5), MCP server declarations (V4) — carrying the full list in
evidence.

**Why.** Most of the fleet answer is an inventory, not a vulnerability. These
findings are the denominator for every percentage in the census, and they carry
zero risk weight by design (rubric §5.1), so a busy vector can legitimately score
zero.

**Fix.** No per-host action. Compare against the approved-software list; the long
tail is ES-902's job.

---

## ES-9xx — Fleet level

These run only on a merged fleet model. No single-host scanner can produce them:
each host is internally consistent, and the finding lives in the comparison.

### ES-901 — One server name, several implementations

**Detects.** A server name resolving to more than one normalised invocation
across two or more hosts. Normalisation drops the interpreter's absolute path and
the user's home prefix, and keeps the package, version and arguments — so
`/opt/homebrew/bin/npx` and `/usr/local/bin/npx` are the same, and
`pkg@1.4.0` and `pkg@latest` are not.

**Escalates to HIGH** when at least one variant appears on exactly one host — the
shape of a swapped or hand-modified copy. Otherwise MEDIUM.

**Evidence.** `variants` (each with invocation, host count and host list),
`singleton_variants`.

**Fix.** Diff the variants. Standardise on one pinned invocation distributed by
the software-management stack; investigate any host whose variant is unique.

---

### ES-902 — Long-tail install

**Detects.** A server on fewer than `--rare-threshold` of hosts (default 5%),
where the fleet has at least `--min-fleet` hosts (default 10), and neither the
server name nor its package appears in `--managed-software`.

**Why.** Managed software is common; shadow installs are rare. Rarity plus
absence from the approved list is the shape of an individually installed,
unreviewed integration.

**Evidence.** `host_count`, `fleet_size`, `prevalence`, `invocations`.

**False positives.** Legitimately niche tooling for one team. That is what the
approved-software list is for — and building that list is most of the value of
the first run.

**Fix.** Confirm with the owning user, then either add it to the managed baseline
or remove it.

---

### ES-903 — Fleet census *(informational)*

**Detects.** Nothing. Publishes the totals that head the census section: server
declarations, agentic CLI installs, IDE AI extensions, local model runtimes, and
the top servers by prevalence.

---

## Adding a check

1. Pick the next free ID in the right family. Never reuse an ID.
2. Register it in the matching module under `endpointsweep/checks/` with severity,
   vector, rationale, fix and OWASP/ATLAS mappings — the metadata travels onto
   every finding it produces.
3. Add a fixture to `testdata/` that triggers it and one that must not, and a
   test for each.
4. Regenerate the goldens (`python3 testdata/generate_golden.py`) and read the
   diff: it is the review of what your check changed fleet-wide.
5. Document it here in the same pull request. `tests/test_docs.py` fails if you
   do not.
