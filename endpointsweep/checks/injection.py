"""ES-2xx — injection surface in MCP tool metadata (vectors 3 and 4).

Tool descriptions are attacker-controlled text that the model reads as
instructions ("tool poisoning"). These heuristics are deterministic pattern and
statistics checks — no LLM in the loop, by design (brief §4.2).
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..matchers import non_ascii_ratio, shannon_entropy
from ..schema import Finding, HostInventory, Severity, Vector
from .registry import CheckContext, check

#: (pattern name, compiled regex) — each is an imperative aimed at the model,
#: not at the human reading the tool list.
INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ignore-previous-instructions", re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+\w*\s*instructions?", re.I)),
    ("disregard-instructions", re.compile(r"disregard\s+(the\s+)?(previous|prior|above|system|all)\b", re.I)),
    ("fake-system-tag", re.compile(r"<\s*/?\s*(system|important|secret|instructions?)\s*>", re.I)),
    ("bracket-system-tag", re.compile(r"\[\s*(system|important|admin)\s*\]", re.I)),
    ("conceal-from-user", re.compile(r"do\s+not\s+(tell|inform|mention|show|reveal)\s+(the\s+)?user", re.I)),
    ("mandatory-tool-call", re.compile(r"(you\s+must|always)\s+(first\s+)?call\b", re.I)),
    ("tool-ordering-hijack", re.compile(r"before\s+(using|calling)\s+any\s+other\s+tool", re.I)),
    ("credential-read-instruction", re.compile(r"(read|open|cat|send|include)\b[^.\n]{0,40}(\.env|id_rsa|\.ssh|credentials|\.aws|keychain)", re.I)),
    ("exfil-instruction", re.compile(r"(send|post|upload|forward)\b[^.\n]{0,40}\b(to\s+https?://|to\s+the\s+following\s+(url|endpoint|address))", re.I)),
    ("hidden-html-comment", re.compile(r"<!--(?:(?!-->).){0,400}?(instruction|system|ignore|must call|do not)(?:(?!-->).){0,400}?-->", re.I | re.S)),
    ("zero-width-characters", re.compile(r"[​-‏‪-‮⁠-⁤﻿]")),
    ("ansi-control-sequence", re.compile(r"\x1b\[[0-9;]*[A-Za-z]")),
    ("private-use-glyphs", re.compile(r"[-]")),
    ("tag-block-smuggling", re.compile(r"[\U000e0000-\U000e007f]")),
)

_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")

#: Descriptions above this are far outside normal MCP tool documentation.
MAX_DESCRIPTION_CHARS = 1500
ENTROPY_THRESHOLD = 4.7
NON_ASCII_THRESHOLD = 0.15


def _excerpt(text: str, match: re.Match[str] | None, width: int = 120) -> str:
    """A short, control-character-escaped window around the match."""
    if match is None:
        window = text[:width]
    else:
        start = max(0, match.start() - width // 3)
        window = text[start : start + width]
    return window.encode("unicode_escape").decode("ascii")


@check(
    "ES-201",
    "Imperative-instruction pattern in MCP tool description (tool poisoning)",
    Severity.CRITICAL,
    Vector.MCP_SERVERS,
    rationale=(
        "Tool descriptions are read by the model as trusted context. Instructions "
        "hidden there redirect the agent without the user ever seeing them — the "
        "tool-poisoning and rug-pull class."
    ),
    fix=(
        "Treat the server as compromised until proven otherwise: disable it, diff the "
        "tool descriptions against the upstream source, and pin the package version."
    ),
    owasp=("LLM01: Prompt Injection", "LLM04: Data and Model Poisoning"),
    atlas=("AML.T0051: LLM Prompt Injection", "AML.T0053: LLM Plugin Compromise"),
)
def poisoned_tool_description(inv: HostInventory, ctx: CheckContext) -> Iterable[Finding]:
    meta = poisoned_tool_description.meta
    for server in inv.mcp_servers:
        for tool in server.tools:
            text = tool.description or ""
            if not text:
                continue
            hits: list[tuple[str, re.Match[str]]] = []
            for name, pattern in INJECTION_PATTERNS:
                m = pattern.search(text)
                if m:
                    hits.append((name, m))
            if not hits:
                continue
            names = [h[0] for h in hits]
            yield meta.finding(
                host=inv.hostname,
                subject=f"{server.name}:{tool.name}",
                detail=(
                    f"tool description matches {len(names)} injection pattern(s): "
                    f"{', '.join(names)}"
                ),
                evidence={
                    "server": server.name,
                    "tool": tool.name,
                    "patterns": names,
                    "excerpt": _excerpt(text, hits[0][1]),
                    "description_chars": len(text),
                },
                location=server.config_path,
            )


@check(
    "ES-202",
    "Anomalous MCP tool description length, entropy or character mix",
    Severity.MEDIUM,
    Vector.MCP_SERVERS,
    rationale=(
        "Payload smuggling shows up as statistical anomaly before it shows up as a "
        "known pattern: oversized descriptions, encoded blobs, or heavy non-ASCII "
        "runs used to carry instructions past a human reviewer."
    ),
    fix="Review the description against upstream; if it does not match the published tool documentation, treat it as ES-201.",
    owasp=("LLM01: Prompt Injection",),
    atlas=("AML.T0051: LLM Prompt Injection",),
)
def anomalous_tool_description(inv: HostInventory, ctx: CheckContext) -> Iterable[Finding]:
    meta = anomalous_tool_description.meta
    for server in inv.mcp_servers:
        for tool in server.tools:
            text = tool.description or ""
            if not text:
                continue
            anomalies: list[str] = []
            if len(text) > MAX_DESCRIPTION_CHARS:
                anomalies.append(f"length {len(text)} chars (> {MAX_DESCRIPTION_CHARS})")
            ratio = non_ascii_ratio(text)
            if len(text) > 80 and ratio > NON_ASCII_THRESHOLD:
                anomalies.append(f"non-ASCII ratio {ratio:.2f}")
            entropy = shannon_entropy(text)
            if len(text) > 300 and entropy > ENTROPY_THRESHOLD:
                anomalies.append(f"entropy {entropy:.2f} bits/char")
            blob = _BASE64_RUN.search(text)
            if blob:
                anomalies.append(f"encoded blob of {len(blob.group(0))} chars")
            if not anomalies:
                continue
            yield meta.finding(
                host=inv.hostname,
                subject=f"{server.name}:{tool.name}",
                detail="description anomalies: " + "; ".join(anomalies),
                evidence={
                    "server": server.name,
                    "tool": tool.name,
                    "anomalies": anomalies,
                    "description_chars": len(text),
                    "entropy": round(entropy, 2),
                    "excerpt": _excerpt(text, None),
                },
                location=server.config_path,
            )
