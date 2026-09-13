"""ES-3xx — supply-chain provenance of MCP server packages (vector 7).

An MCP server launched through ``npx``/``uvx`` is a package pulled from a public
registry at agent start-up. Whoever controls that package controls the tools the
agent trusts, on every host that runs it.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Iterable
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..matchers import basename, is_pinned, levenshtein, package_from_invocation, split_spec
from ..schema import Finding, HostInventory, Severity, Vector
from .registry import CheckContext, check

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "known_packages.json"

#: Typosquat candidates shorter than this produce too much noise.
MIN_TYPOSQUAT_LEN = 8
#: A package published this recently has no reputation to speak of.
NEW_PACKAGE_DAYS = 30
_HTTP_TIMEOUT = 6


@lru_cache(maxsize=1)
def known_packages() -> dict[str, list[str]]:
    try:
        data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"npm": [], "pypi": []}
    return {"npm": list(data.get("npm", [])), "pypi": list(data.get("pypi", []))}


def _all_known(ctx: CheckContext) -> list[str]:
    extra = list(ctx.options.get("known_packages", []))
    kp = known_packages()
    return kp["npm"] + kp["pypi"] + extra


def _ecosystem(command: str) -> str:
    cmd = basename(command)
    if cmd in ("npx", "npx.cmd", "bunx", "bunx.cmd", "pnpm", "yarn", "npm"):
        return "npm"
    if cmd in ("uvx", "uvx.exe", "uv", "uv.exe", "pipx"):
        return "pypi"
    return ""


def _server_packages(inv: HostInventory) -> Iterable[tuple[Any, str, str, str]]:
    """Yield (server, spec, name, version) for registry-launched servers."""
    for server in inv.mcp_servers:
        spec = package_from_invocation(server.command, server.args)
        if not spec or spec.startswith(("/", ".", "~")) or "://" in spec:
            continue
        name, version = split_spec(spec)
        if not name:
            continue
        yield server, spec, name, version


@check(
    "ES-301",
    "MCP server launched from an unpinned package version",
    Severity.HIGH,
    Vector.AI_LIBRARIES,
    rationale=(
        "`npx -y pkg` / `pkg@latest` re-resolves on every agent start. The code that "
        "ran yesterday is not the code that runs today, and a compromised release "
        "reaches the whole fleet with no change on any endpoint."
    ),
    fix="Pin an exact version (`pkg@1.4.2`), or vendor the server into a managed internal registry and reference that.",
    owasp=("LLM03: Supply Chain",),
    atlas=("AML.T0010: ML Supply Chain Compromise",),
)
def unpinned_package(inv: HostInventory, ctx: CheckContext) -> Iterable[Finding]:
    meta = unpinned_package.meta
    for server, spec, name, version in _server_packages(inv):
        if is_pinned(spec):
            continue
        auto_install = any(a in ("-y", "--yes") for a in server.args)
        why = f"version spec {version or '(none)'!r}"
        if auto_install:
            why += "; installed non-interactively (-y)"
        yield meta.finding(
            host=inv.hostname,
            subject=f"{server.client}:{server.name}",
            detail=f"{name} resolved at launch — {why}",
            evidence={
                "package": name,
                "spec": spec,
                "ecosystem": _ecosystem(server.command),
                "command": server.command,
                "args": server.args,
            },
            location=server.config_path,
        )


@check(
    "ES-302",
    "MCP server package name is a near-miss of a known server (typosquat)",
    Severity.MEDIUM,
    Vector.AI_LIBRARIES,
    rationale=(
        "Registry typosquats of popular MCP servers are cheap and effective: the "
        "config looks right at a glance and the agent grants the impostor the same "
        "tool permissions."
    ),
    fix="Verify the package against the upstream project's published name and repository before re-enabling; then pin it.",
    owasp=("LLM03: Supply Chain",),
    atlas=("AML.T0010: ML Supply Chain Compromise",),
)
def typosquat_package(inv: HostInventory, ctx: CheckContext) -> Iterable[Finding]:
    meta = typosquat_package.meta
    known = _all_known(ctx)
    known_set = set(known)
    for server, _spec, name, _version in _server_packages(inv):
        if name in known_set or len(name) < MIN_TYPOSQUAT_LEN:
            continue
        nearest: tuple[str, int] | None = None
        for candidate in known:
            dist = levenshtein(name.lower(), candidate.lower(), max_distance=2)
            if dist in (1, 2) and (nearest is None or dist < nearest[1]):
                nearest = (candidate, dist)
        if nearest is None:
            continue
        candidate, dist = nearest
        severity = Severity.HIGH if dist == 1 else meta.severity
        yield meta.finding(
            host=inv.hostname,
            subject=f"{server.client}:{server.name}",
            detail=f"package {name!r} is edit-distance {dist} from known package {candidate!r}",
            severity=severity,
            evidence={"package": name, "nearest_known": candidate, "distance": dist},
            location=server.config_path,
        )


def _fetch_json(url: str) -> dict[str, Any] | None:
    req = urllib.request.Request(url, headers={"User-Agent": "endpointsweep/0.1 (+audit)"})
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None


def _npm_provenance(name: str) -> dict[str, Any] | None:
    data = _fetch_json(f"https://registry.npmjs.org/{urllib.request.quote(name, safe='@/')}")
    if not data:
        return None
    created = (data.get("time") or {}).get("created", "")
    maintainers = data.get("maintainers") or []
    return {"created": created, "maintainers": len(maintainers)}


def _pypi_provenance(name: str) -> dict[str, Any] | None:
    data = _fetch_json(f"https://pypi.org/pypi/{urllib.request.quote(name, safe='')}/json")
    if not data:
        return None
    releases = data.get("releases") or {}
    times = [
        f["upload_time_iso_8601"]
        for files in releases.values()
        for f in files
        if f.get("upload_time_iso_8601")
    ]
    return {"created": min(times) if times else "", "maintainers": 1 if data.get("info") else 0}


def _age_days(created: str) -> float | None:
    if not created:
        return None
    try:
        stamp = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - stamp).total_seconds() / 86400


@check(
    "ES-303",
    "MCP server package is very new or has a single maintainer",
    Severity.MEDIUM,
    Vector.AI_LIBRARIES,
    rationale=(
        "A package published in the last month, or maintained by exactly one account, "
        "has neither reputation nor a second pair of eyes on releases."
    ),
    fix="Require a review before fleet-wide use; pin the version and re-review on upgrade.",
    owasp=("LLM03: Supply Chain",),
    atlas=("AML.T0010: ML Supply Chain Compromise",),
    online=True,
)
def package_provenance(inv: HostInventory, ctx: CheckContext) -> Iterable[Finding]:
    meta = package_provenance.meta
    seen: set[str] = set()
    for server, _spec, name, _version in _server_packages(inv):
        if name in seen:
            continue
        seen.add(name)
        eco = _ecosystem(server.command)
        prov = _npm_provenance(name) if eco == "npm" else _pypi_provenance(name) if eco == "pypi" else None
        if not prov:
            continue
        age = _age_days(str(prov.get("created", "")))
        reasons = []
        if age is not None and age < NEW_PACKAGE_DAYS:
            reasons.append(f"first published {age:.0f} days ago")
        if prov.get("maintainers") == 1:
            reasons.append("single maintainer account")
        if not reasons:
            continue
        yield meta.finding(
            host=inv.hostname,
            subject=f"{server.client}:{server.name}",
            detail=f"{name}: " + "; ".join(reasons),
            evidence={"package": name, "ecosystem": eco, **prov},
            location=server.config_path,
        )
