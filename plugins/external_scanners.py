"""Optional plugin: run an existing single-host scanner alongside EndpointSweep.

EndpointSweep does not compete with the per-machine scanners (brief §2.1, §9) — it
aggregates. This plugin shells out to one of them on a host and folds its output
in as EndpointSweep findings, so a team already running mcp-scan or mcp-audit keeps
those results inside the fleet report.

Nothing here runs by default. It is opt-in, it is the only place in the project
that executes third-party code, and it never runs during ``merge`` or ``report``.

    from plugins.external_scanners import SCANNERS, run_scanner
    findings = run_scanner("mcp-audit", hostname="ws-mac-1001")
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from endpointsweep.schema import Finding, Severity, Vector

#: Severity strings these tools use, mapped onto ours.
_SEVERITY_ALIASES = {
    "critical": Severity.CRITICAL,
    "error": Severity.HIGH,
    "high": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "note": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


def _severity(raw: Any) -> Severity:
    return _SEVERITY_ALIASES.get(str(raw).strip().lower(), Severity.MEDIUM)


@dataclass(frozen=True)
class ExternalScanner:
    """How to invoke a third-party scanner and read what it produces."""

    name: str
    binary: str
    args: tuple[str, ...]
    parse: Callable[[dict[str, Any]], list[dict[str, Any]]]
    homepage: str = ""

    @property
    def available(self) -> bool:
        return shutil.which(self.binary) is not None


def _parse_sarif(document: dict[str, Any]) -> list[dict[str, Any]]:
    """SARIF is the common denominator: mcp-audit and MCTS both emit it."""
    out: list[dict[str, Any]] = []
    for run in document.get("runs") or []:
        rules = {
            rule.get("id"): rule
            for rule in (run.get("tool", {}).get("driver", {}).get("rules") or [])
        }
        for result in run.get("results") or []:
            rule = rules.get(result.get("ruleId"), {})
            location = ""
            for loc in result.get("locations") or []:
                uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                if uri:
                    location = uri
                    break
            out.append(
                {
                    "id": result.get("ruleId", "EXTERNAL"),
                    "title": (rule.get("shortDescription") or {}).get("text")
                    or result.get("ruleId", "External finding"),
                    "severity": result.get("level", "warning"),
                    "detail": (result.get("message") or {}).get("text", ""),
                    "location": location,
                }
            )
    return out


def _parse_mcp_scan(document: dict[str, Any]) -> list[dict[str, Any]]:
    """MCP-Scan's JSON: ``{path: {"issues": [...]}}``."""
    out: list[dict[str, Any]] = []
    for path, payload in document.items():
        if not isinstance(payload, dict):
            continue
        for issue in payload.get("issues") or []:
            out.append(
                {
                    "id": issue.get("code", "MCP-SCAN"),
                    "title": issue.get("message", "MCP-Scan issue"),
                    "severity": issue.get("severity", "medium"),
                    "detail": issue.get("reference", ""),
                    "location": path,
                }
            )
    return out


SCANNERS: dict[str, ExternalScanner] = {
    "mcp-audit": ExternalScanner(
        name="mcp-audit",
        binary="mcp-audit",
        args=("scan", "--format", "sarif", "--stdout"),
        parse=_parse_sarif,
        homepage="https://pypi.org/project/mcp-audit-scanner/",
    ),
    "mcp-scan": ExternalScanner(
        name="mcp-scan",
        binary="mcp-scan",
        args=("scan", "--json"),
        parse=_parse_mcp_scan,
        homepage="https://github.com/invariantlabs-ai/mcp-scan",
    ),
    "mcts": ExternalScanner(
        name="mcts",
        binary="mcts",
        args=("scan", "--format", "sarif"),
        parse=_parse_sarif,
        homepage="https://github.com/mcp-audit/mcts",
    ),
}

#: Findings imported from another tool get their own ID prefix so nobody
#: mistakes them for an EndpointSweep check.
EXTERNAL_PREFIX = "EXT"
TIMEOUT_SECONDS = 120


def run_scanner(
    scanner: str,
    *,
    hostname: str = "",
    timeout: int = TIMEOUT_SECONDS,
    extra_args: tuple[str, ...] = (),
) -> list[Finding]:
    """Run one external scanner locally and return its findings as ours.

    Raises ``FileNotFoundError`` when the scanner is not installed; returns an
    empty list when it runs but produces nothing parseable.
    """
    spec = SCANNERS.get(scanner)
    if spec is None:
        raise KeyError(f"unknown scanner {scanner!r}; known: {', '.join(sorted(SCANNERS))}")
    if not spec.available:
        raise FileNotFoundError(f"{spec.binary} is not on PATH ({spec.homepage})")

    proc = subprocess.run(  # noqa: S603 - opt-in, explicit binary from SCANNERS
        [spec.binary, *spec.args, *extra_args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    try:
        document = json.loads(proc.stdout)
    except ValueError:
        return []

    findings: list[Finding] = []
    for raw in spec.parse(document):
        findings.append(
            Finding(
                id=f"{EXTERNAL_PREFIX}-{spec.name}-{raw['id']}",
                title=raw["title"],
                severity=_severity(raw["severity"]),
                vector=Vector.MCP_SERVERS,
                host=hostname,
                subject=raw.get("location", ""),
                detail=raw.get("detail", ""),
                evidence={"scanner": spec.name, "scanner_finding_id": raw["id"]},
                fix=f"See {spec.name} documentation: {spec.homepage}",
                location=raw.get("location", ""),
            )
        )
    return findings


def available_scanners() -> list[str]:
    return sorted(name for name, spec in SCANNERS.items() if spec.available)
