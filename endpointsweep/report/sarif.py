"""SARIF 2.1.0 output, so findings land in the tooling security teams already run.

Every registered check becomes a SARIF rule; every finding becomes a result with
a stable partial fingerprint so re-runs de-duplicate instead of re-alerting.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import quote

from .. import __version__
from ..checks import REGISTRY
from ..schema import Finding, FleetModel, HostReport, Severity

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
INFORMATION_URI = "https://github.com/harish-ravichandra/endpointsweep"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

#: GitHub code-scanning reads this to sort alerts.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}

_WINDOWS_PATH = re.compile(r"^[A-Za-z]:[\\/]")


def path_to_uri(path: str) -> str:
    """Turn a collector-reported path into a SARIF-legal URI."""
    if not path:
        return ""
    # Strip our own "#projects/..." config-fragment annotation.
    path = path.split("#", 1)[0]
    if _WINDOWS_PATH.match(path):
        drive, rest = path[0], path[2:].replace("\\", "/")
        return "file:///" + quote(f"{drive}:{rest}", safe="/:")
    if path.startswith("/"):
        return "file://" + quote(path, safe="/")
    return quote(path, safe="/")


def _rules() -> tuple[list[dict[str, Any]], dict[str, int]]:
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    for check in sorted(REGISTRY.values(), key=lambda c: c.meta.id):
        m = check.meta
        index[m.id] = len(rules)
        rules.append(
            {
                "id": m.id,
                "name": re.sub(r"[^A-Za-z0-9]", "", m.title.title())[:120] or m.id.replace("-", ""),
                "shortDescription": {"text": m.title},
                "fullDescription": {"text": m.rationale},
                "help": {
                    "text": f"{m.rationale}\n\nFix: {m.fix}",
                    "markdown": f"**{m.title}**\n\n{m.rationale}\n\n**Fix:** {m.fix}",
                },
                "defaultConfiguration": {"level": _LEVEL[m.severity]},
                "properties": {
                    "tags": [
                        "endpointsweep",
                        f"vector-{m.vector.value}",
                        m.vector.title.lower().replace(" ", "-"),
                        m.scope,
                        *[o.split(":")[0] for o in m.owasp],
                        *[a.split(":")[0] for a in m.atlas],
                    ],
                    "security-severity": _SECURITY_SEVERITY[m.severity],
                    "precision": "high" if m.scope == "host" else "medium",
                    "owasp": list(m.owasp),
                    "atlas": list(m.atlas),
                    "vector": m.vector.value,
                },
            }
        )
    return rules, index


def _fingerprint(finding: Finding) -> str:
    basis = "|".join([finding.id, finding.host, finding.subject, finding.location])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]


def _result(finding: Finding, rule_index: dict[str, int]) -> dict[str, Any]:
    message = f"{finding.title}: {finding.detail}" if finding.detail else finding.title
    if finding.host:
        message = f"[{finding.host}] {message}"
    result: dict[str, Any] = {
        "ruleId": finding.id,
        "ruleIndex": rule_index.get(finding.id, 0),
        "level": _LEVEL[finding.severity],
        "message": {"text": message},
        "partialFingerprints": {"endpointsweepFindingV1": _fingerprint(finding)},
        "properties": {
            "host": finding.host,
            "hosts": finding.hosts,
            "subject": finding.subject,
            "severity": finding.severity.value,
            "vector": finding.vector.value,
            "owasp": finding.owasp,
            "atlas": finding.atlas,
            "fix": finding.fix,
            "evidence": finding.evidence,
        },
    }
    uri = path_to_uri(finding.location)
    if uri:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": finding.host or "fleet", "kind": "resource"}],
            }
        ]
    else:
        result["locations"] = [
            {"logicalLocations": [{"name": finding.host or "fleet", "kind": "resource"}]}
        ]
    return result


def _run(findings: list[Finding], *, automation_id: str, end_time: str) -> dict[str, Any]:
    rules, index = _rules()
    return {
        "tool": {
            "driver": {
                "name": "EndpointSweep",
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }
        },
        "automationDetails": {"id": automation_id},
        "invocations": [{"executionSuccessful": True, "endTimeUtc": end_time}],
        "results": [_result(f, index) for f in findings],
        "columnKind": "utf16CodeUnits",
    }


def _document(run: dict[str, Any]) -> dict[str, Any]:
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def fleet_sarif(fleet: FleetModel) -> dict[str, Any]:
    return _document(
        _run(
            fleet.all_findings,
            automation_id=f"endpointsweep/fleet/{fleet.host_count}-hosts",
            end_time=fleet.generated_at,
        )
    )


def host_sarif(report: HostReport, *, end_time: str = "") -> dict[str, Any]:
    return _document(
        _run(
            report.findings,
            automation_id=f"endpointsweep/host/{report.inventory.hostname}",
            end_time=end_time or report.inventory.host.collected_at,
        )
    )


def dumps(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2)
