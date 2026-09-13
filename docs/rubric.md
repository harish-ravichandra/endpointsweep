# The EndpointSweep Risk Rubric v0.1

A tool-agnostic way to describe, score and compare enterprise exposure to agentic
AI on endpoints.

This document is deliberately independent of EndpointSweep, of MCP, and of any
vendor. MCP is two years old and the spec still moves; the questions below do
not. If the protocol is replaced tomorrow, the eight vectors and the six
capability axes survive the change — only the collectors need rewriting.

- **Audience:** endpoint security, detection engineering, and the people who have
  to answer "what AI is running on our fleet?" to an auditor.
- **Unit of analysis:** one endpoint, then a fleet of them.
- **Evidence standard:** declared configuration and installed software. This
  rubric scores *capability*, not observed behaviour.

---

## 1. The core question

> For each endpoint: which AI integrations are present, what can each of them
> touch, who authorised it, and how would we know if one of them turned hostile?

Everything below is a way of answering that consistently enough that two
assessors get the same number.

---

## 2. The eight vectors

The enterprise AI attack surface on a managed endpoint decomposes into eight
vectors. They are disjoint by *where the integration lives*, which is what makes
them collectable.

| # | Vector | What it covers | Why it is its own vector |
|---|---|---|---|
| V1 | Browser AI modes | AI features built into the browser itself (sidebars, page summarisation, agentic browsing) | Enabled by browser policy, not by software install; invisible to software inventory |
| V2 | Browser AI extensions | Third-party AI extensions with page and DOM access | Extension permissions are the grant; the store is the supply chain |
| V3 | Agentic AI tooling | CLI/desktop agents that act on the machine (coding agents, task agents) | They *execute*: their blast radius is the user's whole session |
| V4 | Local MCP servers | Tool servers an agent connects to, declared in client configs | The tool is the privilege; one config line can grant shell or filesystem |
| V5 | Local model runtimes | Locally hosted inference (Ollama, llama.cpp, LM Studio, vLLM) | Unauthenticated local APIs, GPU use, and data that never leaves — or does |
| V6 | IDE AI plugins | AI extensions inside IDEs (completion, chat, agent modes) | Source code and credentials in the workspace are in scope by default |
| V7 | AI libraries in code | SDKs in project dependency manifests | Determines which teams ship AI, and pulls in AI supply chain |
| V8 | Direct API-key integrations | Long-lived provider keys in configs, env and dotfiles | The credential outlives the tool that created it |

**Vector selection rule.** Assign a finding to the vector that describes *where
the risk lives*, not where it was found. A credential-shaped variable inside an
MCP server config is V8 (credential exposure), not V4 — removing the server does
not rotate the key.

---

## 3. The six capability axes

Within a vector, risk is a function of what the integration can *do*. Six axes,
each answerable from configuration alone:

| Axis | Question | Low | High |
|---|---|---|---|
| **A1 Execution** | Can it run arbitrary local code? | No process spawning | Shell / interpreter / `exec`-style tool |
| **A2 Filesystem reach** | What paths are in scope? | One project directory | `/`, `~`, or a wildcard |
| **A3 Network reach** | Where can it send data? | No egress, or a fixed allow-list | Arbitrary URLs from model-supplied input |
| **A4 Credential exposure** | What secrets are reachable? | Broker/keychain at call time | Long-lived keys in plaintext config or env |
| **A5 Privilege** | In whose security context? | Unprivileged user | root / SYSTEM, or declared system-wide |
| **A6 Provenance & control** | Do we know what code runs, and does a human approve calls? | Pinned, managed, per-call approval | Unpinned `@latest`, auto-approved tools |

An integration that is high on A1 **and** A3 is an exfiltration path. High on A1
**and** A5 is a privilege-escalation path. High on A6 alone is how both arrive
without anyone changing an endpoint.

**This is the part that transfers.** A2–A6 apply just as well to a browser
extension's manifest permissions or an IDE plugin's workspace trust settings as
they do to an MCP server's argv.

---

## 4. Severity

Severity is assigned to a *finding*, from the axes it implicates and whether the
capability is live.

| Severity | Definition | Typical shape |
|---|---|---|
| **CRITICAL** | A working path from untrusted model input to code execution or data egress, with no human in the loop | Poisoned tool description; auto-approved execution tool |
| **HIGH** | A capability that would make a successful injection materially worse, or a credential exposed in plaintext | Shell-capable server; filesystem rooted at `~`; unpinned `@latest`; API key in a config |
| **MEDIUM** | A weakening of containment that needs a second condition to be exploitable | Unrestricted egress; elevated declaration; typosquat-shaped package name |
| **LOW** | A hygiene defect with a narrow or local impact | Local model runtime bound to `0.0.0.0` on a trusted segment |
| **INFO** | Inventory. Not a defect; the denominator that makes the rest meaningful | Agentic CLI present; IDE AI extension installed |

**Live-versus-latent rule.** A capability that is present but disabled is real —
it takes one click to enable — but it is not live. Report it one severity step
below the live equivalent, and say so in the finding. Never drop it silently.

---

## 5. Scoring

Two properties matter: the number must saturate (the tenth HIGH on a host is not
ten times the first), and it must be reproducible by hand.

### 5.1 Weights

| Severity | Weight |
|---|---|
| CRITICAL | 25 |
| HIGH | 12 |
| MEDIUM | 5 |
| LOW | 2 |
| INFO | 0 |

### 5.2 Formula

```
raw   = Σ weight(finding)
score = 100 × (1 − e^(−raw / K))        K = 35 (host), 20 (vector), 60 (fleet findings)
```

### 5.3 Bands

| Score | Band | Reading |
|---|---|---|
| 0–19 | LOW | Hygiene only |
| 20–44 | MODERATE | Real capability, contained |
| 45–69 | ELEVATED | Would not survive a targeted injection |
| 70–100 | CRITICAL | Treat as an incident queue, not a backlog |

### 5.4 Worked examples

| Host | Findings | raw | Score | Band |
|---|---|---|---|---|
| Tidy laptop | 1 MEDIUM (unrestricted fetch) | 5 | 13.3 | LOW |
| Typical dev | 2 HIGH (unpinned, key in config) + 1 MEDIUM | 29 | 56.4 | ELEVATED |
| Worst case | 1 CRITICAL + 3 HIGH | 61 | 82.5 | CRITICAL |

Note the shape: the first HIGH moves a host from LOW to MODERATE; the fourth
moves it much less. That is intended — triage should be driven by the *first*
serious finding on many hosts, not by the *tenth* on one.

### 5.5 Fleet score

```
fleet = 0.7 × mean(host scores) + 0.3 × saturate(Σ fleet-finding weights, K = 60)
```

A fleet of individually tidy hosts running six variants of the same server is not
tidy, and the second term is what says so. Report the mean **and** p95 host
score: the mean tells you the baseline, p95 tells you what your worst 5% looks
like, and on a real fleet those two numbers tell very different stories.

Per-vector scores across a fleet use `K = 20 × hosts / 2`. Without that scaling,
every vector carrying any finding saturates at 100 on any fleet worth scanning,
and the breakdown stops discriminating between a vector with three findings and
one with three hundred.

---

## 6. Fleet-level questions

These have no single-host answer, and they are the reason a fleet tool exists at
all:

1. **Consistency.** Does one server name resolve to one implementation everywhere?
   Divergence is either unmanaged sprawl or a swapped copy.
2. **Prevalence.** What fraction of the fleet runs this? Managed software is
   common; shadow installs are rare. Rarity plus absence from the approved list
   is the shape of an unreviewed integration.
3. **Drift.** How many versions of the same agent are in flight, and how old is
   the oldest?
4. **Concentration.** Is the risk spread evenly, or does one team hold it all?
   (Answered by tagging hosts; the rubric does not prescribe a taxonomy.)

---

## 7. Coverage and honesty about gaps

A rubric that silently scores an uncollected vector as zero is worse than no
rubric. Every report must state coverage per vector.

| Vector | Collected by EndpointSweep v0.x |
|---|---|
| V1 Browser AI modes | **No** — browser policy state, not yet collected |
| V2 Browser AI extensions | **No** — extension inventory, not yet collected |
| V3 Agentic AI tooling | Yes |
| V4 Local MCP servers | Yes |
| V5 Local model runtimes | Yes |
| V6 IDE AI plugins | Yes |
| V7 AI libraries in code | Yes (best-effort, bounded path globs) |
| V8 Direct API-key integrations | Yes (names and paths only) |

---

## 8. Evidence and red lines

The rubric is only usable if collecting against it is safe to deploy fleet-wide.

- **Metadata only.** Variable *names* and file *paths*. Never a value, never a
  file body, never user documents. A tool that needs to read the secret to tell
  you the secret is exposed has already made the problem worse.
- **Capability, not behaviour.** Declared configuration says what an agent
  *could* do. Nothing in this rubric claims a tool was used.
- **Deterministic.** No model is consulted to produce a score. A number you
  cannot reproduce by hand is not a number you can defend in a review.
- **Attributable.** Every finding carries its check ID, the axes it implicates,
  and the evidence it rests on.

---

## 9. Mappings

Findings carry external mappings so they land in existing programmes.

| Axis | OWASP LLM Top 10 (2025) | MITRE ATLAS |
|---|---|---|
| A1 Execution | LLM06 Excessive Agency, LLM05 Improper Output Handling | AML.T0053, AML.T0011 |
| A2 Filesystem reach | LLM06, LLM02 Sensitive Information Disclosure | AML.T0053, AML.T0025 |
| A3 Network reach | LLM02, LLM06 | AML.T0025 |
| A4 Credential exposure | LLM02 | AML.T0055 |
| A5 Privilege | LLM06 | AML.T0053, AML.T0012 |
| A6 Provenance & control | LLM03 Supply Chain, LLM04 Data and Model Poisoning | AML.T0010, AML.T0018 |
| Injection surface | LLM01 Prompt Injection | AML.T0051 |

---

## 10. Adapting the rubric

Sites differ. Two knobs are meant to be turned, and one is not:

- **Turn:** the long-tail prevalence threshold (what counts as rare on *your*
  fleet), and the approved-software list that suppresses expected rarity.
- **Turn:** severity for a check whose risk genuinely differs in your
  environment — an Ollama endpoint on an isolated lab VLAN is not the same
  finding as one on a user segment. Record the override and why.
- **Do not turn:** the weights and the formula. Once those move per site, scores
  stop comparing, and the number loses the only property that made it useful.

---

## 11. Versioning

The rubric is versioned independently of the tool. `v0.1` is the initial
publication. Changes that alter a score — new weights, new bands, a severity
change — take a new minor version and a changelog entry, because someone will be
trending these numbers quarter over quarter.
