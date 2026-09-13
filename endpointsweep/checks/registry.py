"""Check registry.

Every check is a pure function over the schema, registered with metadata that
travels onto each finding it produces: ID (``ES-###``), severity, vector, OWASP
LLM Top 10 + MITRE ATLAS mapping, and fix guidance (brief §5, §6).

Host checks see one :class:`HostInventory`; fleet checks see the merged
:class:`FleetModel` and are the checks no single-host scanner can run.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from ..schema import Finding, FleetModel, HostInventory, Severity, Vector

HostCheckFn = Callable[[HostInventory, "CheckContext"], Iterable[Finding]]
FleetCheckFn = Callable[[FleetModel, "CheckContext"], Iterable[Finding]]


@dataclass
class CheckContext:
    """Knobs a check may consult. Deterministic and offline by default."""

    online: bool = False
    #: Fraction of the fleet below which a server counts as long-tail (ES-902).
    rare_threshold: float = 0.05
    #: Minimum fleet size before prevalence checks are meaningful (ES-902).
    min_fleet_for_prevalence: int = 10
    #: Server/package names blessed by the site's managed-software list.
    managed_software: set[str] = field(default_factory=set)
    #: Free-form extras for plugins.
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CheckMeta:
    id: str
    title: str
    severity: Severity
    vector: Vector
    scope: str  # "host" | "fleet"
    rationale: str
    fix: str
    owasp: tuple[str, ...] = ()
    atlas: tuple[str, ...] = ()
    #: True when the check needs network access (gated behind --online).
    online: bool = False

    def finding(
        self,
        *,
        host: str = "",
        subject: str = "",
        detail: str = "",
        evidence: dict[str, Any] | None = None,
        severity: Severity | None = None,
        vector: Vector | None = None,
        hosts: Iterable[str] = (),
        location: str = "",
    ) -> Finding:
        return Finding(
            id=self.id,
            title=self.title,
            severity=severity or self.severity,
            vector=vector or self.vector,
            host=host,
            subject=subject,
            detail=detail,
            evidence=dict(evidence or {}),
            owasp=list(self.owasp),
            atlas=list(self.atlas),
            fix=self.fix,
            hosts=sorted(hosts),
            location=location,
        )


@dataclass(frozen=True)
class Check:
    meta: CheckMeta
    fn: Callable


REGISTRY: dict[str, Check] = {}


def _register(meta: CheckMeta, fn: Callable) -> Callable:
    if meta.id in REGISTRY:
        raise ValueError(f"duplicate check id {meta.id}")
    REGISTRY[meta.id] = Check(meta=meta, fn=fn)
    fn.meta = meta  # type: ignore[attr-defined]
    return fn


def check(
    id: str,
    title: str,
    severity: Severity,
    vector: Vector,
    *,
    rationale: str,
    fix: str,
    owasp: tuple[str, ...] = (),
    atlas: tuple[str, ...] = (),
    online: bool = False,
) -> Callable[[HostCheckFn], HostCheckFn]:
    """Register a per-host check."""

    def deco(fn: HostCheckFn) -> HostCheckFn:
        meta = CheckMeta(
            id=id,
            title=title,
            severity=severity,
            vector=vector,
            scope="host",
            rationale=rationale,
            fix=fix,
            owasp=owasp,
            atlas=atlas,
            online=online,
        )
        return _register(meta, fn)  # type: ignore[return-value]

    return deco


def fleet_check(
    id: str,
    title: str,
    severity: Severity,
    vector: Vector,
    *,
    rationale: str,
    fix: str,
    owasp: tuple[str, ...] = (),
    atlas: tuple[str, ...] = (),
    online: bool = False,
) -> Callable[[FleetCheckFn], FleetCheckFn]:
    """Register a fleet-level check (runs on the merged model only)."""

    def deco(fn: FleetCheckFn) -> FleetCheckFn:
        meta = CheckMeta(
            id=id,
            title=title,
            severity=severity,
            vector=vector,
            scope="fleet",
            rationale=rationale,
            fix=fix,
            owasp=owasp,
            atlas=atlas,
            online=online,
        )
        return _register(meta, fn)  # type: ignore[return-value]

    return deco


def all_checks(scope: str | None = None) -> list[Check]:
    checks = sorted(REGISTRY.values(), key=lambda c: c.meta.id)
    return [c for c in checks if scope is None or c.meta.scope == scope]


def _selected(scope: str, only: Iterable[str] | None, skip: Iterable[str] | None) -> list[Check]:
    only_set = {c.upper() for c in only} if only else None
    skip_set = {c.upper() for c in skip} if skip else set()
    out = []
    for c in all_checks(scope):
        if only_set is not None and c.meta.id not in only_set:
            continue
        if c.meta.id in skip_set:
            continue
        out.append(c)
    return out


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity.rank, f.id, f.host, f.subject))


def run_host_checks(
    inventory: HostInventory,
    ctx: CheckContext | None = None,
    *,
    only: Iterable[str] | None = None,
    skip: Iterable[str] | None = None,
) -> list[Finding]:
    ctx = ctx or CheckContext()
    findings: list[Finding] = []
    for chk in _selected("host", only, skip):
        if chk.meta.online and not ctx.online:
            continue
        findings.extend(chk.fn(inventory, ctx) or [])
    return _sort_findings(findings)


def run_fleet_checks(
    fleet: FleetModel,
    ctx: CheckContext | None = None,
    *,
    only: Iterable[str] | None = None,
    skip: Iterable[str] | None = None,
) -> list[Finding]:
    ctx = ctx or CheckContext()
    findings: list[Finding] = []
    for chk in _selected("fleet", only, skip):
        if chk.meta.online and not ctx.online:
            continue
        findings.extend(chk.fn(fleet, ctx) or [])
    return _sort_findings(findings)
