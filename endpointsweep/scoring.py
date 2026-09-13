"""Risk scoring — the 8-vector rubric in code.

The formula is deliberately simple and deterministic so that two people can
argue about a number and both reproduce it. Full narrative: docs/rubric.md.

    raw    = Σ severity_weight(finding)        INFO=0 LOW=2 MED=5 HIGH=12 CRIT=25
    score  = 100 · (1 − e^(−raw / K))          K = 35 host, 20 vector, 60 fleet

Saturation matters: the tenth HIGH on one host should not read as ten times the
risk of the first, but it must still read as worse.
"""

from __future__ import annotations

import math

from .schema import Finding, FleetModel, HostInventory, HostReport, Vector, VectorScore

K_HOST = 35.0
K_VECTOR = 20.0
K_FLEET = 60.0

#: Vectors the v0.x collectors actually inventory. 1 and 2 (browser AI modes
#: and browser AI extensions) are in the rubric but out of scope for v0.x, and
#: are reported as coverage gaps rather than as clean.
COVERED_VECTORS = frozenset(
    {
        Vector.AGENTIC_AI,
        Vector.MCP_SERVERS,
        Vector.LOCAL_MODELS,
        Vector.IDE_AI_PLUGINS,
        Vector.AI_LIBRARIES,
        Vector.API_KEY_INTEGRATIONS,
    }
)

#: (upper bound exclusive, label)
_BANDS = ((20.0, "LOW"), (45.0, "MODERATE"), (70.0, "ELEVATED"), (101.0, "CRITICAL"))


def raw_weight(findings: list[Finding]) -> int:
    return sum(f.severity.weight for f in findings)


def saturate(raw: float, k: float) -> float:
    """Map an unbounded raw weight onto 0–100 with diminishing returns."""
    if raw <= 0:
        return 0.0
    return round(100.0 * (1.0 - math.exp(-raw / k)), 1)


def risk_band(score: float) -> str:
    for upper, label in _BANDS:
        if score < upper:
            return label
    return "CRITICAL"


def vector_scores(findings: list[Finding], *, k: float = K_VECTOR) -> list[VectorScore]:
    by_vector: dict[Vector, list[Finding]] = {v: [] for v in Vector}
    for f in findings:
        by_vector[f.vector].append(f)
    return [
        VectorScore(
            vector=v,
            score=saturate(raw_weight(fs), k),
            findings=len(fs),
            covered=v in COVERED_VECTORS,
        )
        for v, fs in sorted(by_vector.items(), key=lambda kv: kv[0].value)
    ]


def score_host(inventory: HostInventory, findings: list[Finding]) -> HostReport:
    """Build the scored per-host report."""
    return HostReport(
        inventory=inventory,
        findings=findings,
        score=saturate(raw_weight(findings), K_HOST),
        vector_scores=vector_scores(findings),
    )


def score_fleet(fleet: FleetModel) -> FleetModel:
    """Score the fleet in place and return it.

    Fleet risk is 70% the average host's exposure and 30% the fleet-only
    findings (inconsistent provenance, long-tail installs) — a fleet of
    individually-tidy hosts running six variants of one server is not tidy.
    """
    host_scores = [h.score for h in fleet.hosts]
    host_component = sum(host_scores) / len(host_scores) if host_scores else 0.0
    fleet_component = saturate(raw_weight(fleet.findings), K_FLEET)
    fleet.score = round(0.7 * host_component + 0.3 * fleet_component, 1)
    # Vector scores across a fleet aggregate every host's findings, so K scales
    # with fleet size — otherwise every vector with any finding saturates at 100
    # on any fleet worth scanning, and the bar chart stops discriminating.
    fleet.vector_scores = vector_scores(fleet.all_findings, k=fleet_vector_k(len(fleet.hosts)))
    return fleet


def fleet_vector_k(host_count: int) -> float:
    """Per-vector saturation constant for a fleet of ``host_count`` hosts."""
    return K_VECTOR * max(1, host_count) / 2


def band_counts(fleet: FleetModel) -> dict[str, int]:
    counts = {label: 0 for _, label in _BANDS}
    for host in fleet.hosts:
        counts[risk_band(host.score)] += 1
    return counts


def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile; stable and dependency-free."""
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, math.ceil(pct / 100.0 * len(ordered)) - 1)
    return ordered[idx]
