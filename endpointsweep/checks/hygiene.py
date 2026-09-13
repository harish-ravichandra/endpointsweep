"""ES-4xx — credential, runtime and inventory hygiene (vectors 3, 5, 6, 7, 8).

Red line (brief §4.3, §8): these checks report variable NAMES and file PATHS.
No value ever reaches this module — the collectors do not read them and
:mod:`endpointsweep.schema` has nowhere to put them.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..parsers.base import key_shaped_names
from ..schema import Finding, HostInventory, Severity, Vector
from .registry import CheckContext, check

#: Addresses that expose a local model runtime beyond the loopback interface.
EXPOSED_BINDS = ("0.0.0.0", "::", "[::]", "*")


@check(
    "ES-401",
    "Credential-shaped variable names embedded in an MCP server config",
    Severity.HIGH,
    Vector.API_KEY_INTEGRATIONS,
    rationale=(
        "Client configs are world-readable in the user's profile, sync to backup and "
        "settings-sync services, and get pasted into issues. A long-lived API key in "
        "an `env` block is a credential stored in plaintext outside any secret store."
    ),
    fix=(
        "Move the secret into the platform keychain/credential manager or a broker the "
        "server reads at start-up, and rotate anything that has lived in a config file."
    ),
    owasp=("LLM02: Sensitive Information Disclosure",),
    atlas=("AML.T0055: Unsecured Credentials",),
)
def credentials_in_server_config(inv: HostInventory, ctx: CheckContext) -> Iterable[Finding]:
    meta = credentials_in_server_config.meta
    for server in inv.mcp_servers:
        names = key_shaped_names(server.env_var_names)
        if not names:
            continue
        yield meta.finding(
            host=inv.hostname,
            subject=f"{server.client}:{server.name}",
            detail=(
                f"{len(names)} credential-shaped variable name(s) declared in the server "
                f"env block: {', '.join(sorted(names))}"
            ),
            evidence={
                "variable_names": sorted(names),
                "config_path": server.config_path,
                "user": server.user,
            },
            location=server.config_path,
        )


@check(
    "ES-402",
    "Credential-shaped variable names in shell rc or .env files",
    Severity.MEDIUM,
    Vector.API_KEY_INTEGRATIONS,
    rationale=(
        "Keys exported from a shell rc file are inherited by every agent, MCP server "
        "and child process that user starts — the blast radius of one poisoned tool "
        "call is every key in the environment."
    ),
    fix="Move keys to a secret manager and source them on demand; scope per-project keys to a per-project .env excluded from backup and sync.",
    owasp=("LLM02: Sensitive Information Disclosure",),
    atlas=("AML.T0055: Unsecured Credentials",),
)
def credentials_in_dotfiles(inv: HostInventory, ctx: CheckContext) -> Iterable[Finding]:
    meta = credentials_in_dotfiles.meta
    for signal in inv.env_key_signals:
        names = key_shaped_names(signal.var_names)
        if not names:
            continue
        yield meta.finding(
            host=inv.hostname,
            subject=signal.path,
            detail=(
                f"{len(names)} credential-shaped variable name(s) in {signal.kind or 'file'}: "
                f"{', '.join(sorted(names))}"
            ),
            evidence={
                "variable_names": sorted(names),
                "path": signal.path,
                "kind": signal.kind,
                "user": signal.user,
            },
            location=signal.path,
        )


@check(
    "ES-403",
    "Local model runtime listening on a non-loopback interface",
    Severity.LOW,
    Vector.LOCAL_MODELS,
    rationale=(
        "An Ollama/llama.cpp endpoint bound to 0.0.0.0 is an unauthenticated inference "
        "API on the corporate network: anyone on the segment can use the host's GPU, "
        "pull its model list, and prompt it."
    ),
    fix="Bind the runtime to 127.0.0.1 (e.g. OLLAMA_HOST=127.0.0.1:11434) and put a host firewall rule in front of the port.",
    owasp=("LLM10: Unbounded Consumption", "LLM02: Sensitive Information Disclosure"),
    atlas=("AML.T0040: ML Model Inference API Access",),
)
def exposed_model_runtime(inv: HostInventory, ctx: CheckContext) -> Iterable[Finding]:
    meta = exposed_model_runtime.meta
    for runtime in inv.model_runtimes:
        exposed = [a for a in runtime.listen_addrs if any(a.startswith(b) for b in EXPOSED_BINDS)]
        if not exposed:
            continue
        yield meta.finding(
            host=inv.hostname,
            subject=runtime.name,
            detail=f"{runtime.name} is listening on {', '.join(exposed)} with {len(runtime.models)} model(s) loaded",
            severity=Severity.MEDIUM if runtime.running else meta.severity,
            evidence={
                "runtime": runtime.name,
                "listen_addrs": runtime.listen_addrs,
                "running": runtime.running,
                "models": runtime.models,
            },
        )


@check(
    "ES-404",
    "Shadow-AI inventory (census signal, not an alert)",
    Severity.INFO,
    Vector.AGENTIC_AI,
    rationale=(
        "Most of the fleet answer is not a vulnerability, it is an inventory: which "
        "agentic CLIs, IDE AI plugins, AI SDKs and local runtimes exist where. These "
        "findings feed the census sections of the fleet report."
    ),
    fix="No action per host. Compare against the approved-software list and investigate the long tail (see ES-902).",
)
def shadow_ai_inventory(inv: HostInventory, ctx: CheckContext) -> Iterable[Finding]:
    meta = shadow_ai_inventory.meta
    host = inv.hostname

    if inv.agentic_tools:
        names = sorted({t.name for t in inv.agentic_tools})
        yield meta.finding(
            host=host,
            subject="agentic-cli",
            detail=f"{len(names)} agentic CLI tool(s) present: {', '.join(names)}",
            vector=Vector.AGENTIC_AI,
            evidence={
                "tools": [
                    {"name": t.name, "path": t.path, "version": t.version, "user": t.user}
                    for t in inv.agentic_tools
                ]
            },
        )

    if inv.ide_extensions:
        ids = sorted({e.extension_id for e in inv.ide_extensions})
        yield meta.finding(
            host=host,
            subject="ide-ai-extensions",
            detail=f"{len(ids)} AI extension(s) installed across IDEs: {', '.join(ids)}",
            vector=Vector.IDE_AI_PLUGINS,
            evidence={
                "extensions": [
                    {"ide": e.ide, "id": e.extension_id, "version": e.version, "user": e.user}
                    for e in inv.ide_extensions
                ]
            },
        )

    manifests = [m for m in inv.package_manifests if m.ai_packages]
    if manifests:
        pkgs = sorted({p for m in manifests for p in m.ai_packages})
        yield meta.finding(
            host=host,
            subject="ai-sdk-usage",
            detail=f"AI SDK packages declared in {len(manifests)} manifest(s): {', '.join(pkgs)}",
            vector=Vector.AI_LIBRARIES,
            evidence={
                "manifests": [
                    {"path": m.path, "ecosystem": m.ecosystem, "packages": m.ai_packages}
                    for m in manifests
                ]
            },
        )

    installed = [r for r in inv.model_runtimes if r.installed]
    if installed:
        yield meta.finding(
            host=host,
            subject="local-model-runtimes",
            detail=(
                f"{len(installed)} local model runtime(s): "
                + ", ".join(f"{r.name}({'running' if r.running else 'stopped'})" for r in installed)
            ),
            vector=Vector.LOCAL_MODELS,
            evidence={
                "runtimes": [
                    {
                        "name": r.name,
                        "running": r.running,
                        "models": r.models,
                        "version": r.version,
                    }
                    for r in installed
                ]
            },
        )

    if inv.mcp_servers:
        yield meta.finding(
            host=host,
            subject="mcp-servers",
            detail=(
                f"{len(inv.mcp_servers)} MCP server declaration(s) across "
                f"{len({s.client for s in inv.mcp_servers})} client(s)"
            ),
            vector=Vector.MCP_SERVERS,
            evidence={
                "servers": [
                    {"name": s.name, "client": s.client, "command": s.command, "user": s.user}
                    for s in inv.mcp_servers
                ]
            },
        )
