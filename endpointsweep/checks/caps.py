"""ES-1xx — capability and scope checks for declared MCP servers (vector 4).

What can this server actually touch on the endpoint? These are the checks that
turn "an MCP server is installed" into "an MCP server that can run shell
commands as root over the whole filesystem is installed".
"""

from __future__ import annotations

from collections.abc import Iterable

from ..matchers import (
    EGRESS_SCOPE_ARGS,
    EXEC_SERVER_HINTS,
    EXEC_TOOL_NAMES,
    FILESYSTEM_HINTS,
    NETWORK_HINTS,
    basename,
    inline_code_flags,
    is_exec_interpreter,
    is_writable_path,
    matches_any,
    mode_is_world_writable,
    root_scope_args,
)
from ..schema import Finding, HostInventory, MCPServer, Severity, Vector
from .registry import CheckContext, CheckMeta, check

_LOOPBACK = ("localhost", "127.0.0.1", "::1", "0.0.0.0")


_ONE_STEP_LOWER = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
}


def downgrade(severity: Severity) -> Severity:
    return _ONE_STEP_LOWER.get(severity, severity)


def severity_for(meta: CheckMeta, server: MCPServer) -> Severity:
    """A disabled server is latent, not live: report it one step lower."""
    return meta.severity if not server.disabled else downgrade(meta.severity)


def _suffix(server: MCPServer) -> str:
    return " (currently disabled in config)" if server.disabled else ""


@check(
    "ES-101",
    "MCP server has local command-execution capability",
    Severity.HIGH,
    Vector.MCP_SERVERS,
    rationale=(
        "A server that can spawn a shell turns any successful prompt injection into "
        "local code execution in the user's security context."
    ),
    fix=(
        "Remove the server, or replace it with a task-specific server. If execution is "
        "genuinely required, pin it to an allow-list of commands and require per-call "
        "approval (never autoApprove)."
    ),
    owasp=("LLM06: Excessive Agency", "LLM05: Improper Output Handling"),
    atlas=("AML.T0053: LLM Plugin Compromise", "AML.T0011: User Execution"),
)
def exec_capable_server(inv: HostInventory, ctx: CheckContext) -> Iterable[Finding]:
    meta = exec_capable_server.meta
    for server in inv.mcp_servers:
        reasons: list[str] = []
        if is_exec_interpreter(server.command):
            reasons.append(f"command is the interpreter {basename(server.command)!r}")
        flags = inline_code_flags(server.command, server.args)
        if flags:
            reasons.append(f"runtime invoked with inline-code flag {flags[0]!r}")
        hint = matches_any(server.invocation, EXEC_SERVER_HINTS)
        if hint:
            reasons.append(f"package name matches known exec server {hint!r}")
        exec_tools = [t.name for t in server.tools if t.name.lower() in EXEC_TOOL_NAMES]
        if exec_tools:
            reasons.append(f"advertises execution tools: {', '.join(sorted(exec_tools))}")
        if not reasons:
            continue

        # Auto-approval is what removes the human from the loop: either the
        # execution tool is listed explicitly, or the client approves everything.
        if "*" in server.auto_approved_tools:
            auto = sorted(server.auto_approved_tools)
        else:
            auto = sorted(set(server.auto_approved_tools) & set(exec_tools))
        severity = Severity.CRITICAL if auto else severity_for(meta, server)
        detail = "; ".join(reasons) + _suffix(server)
        if auto:
            detail += f"; execution is auto-approved ({', '.join(auto)}) — no human in the loop"
        yield meta.finding(
            host=inv.hostname,
            subject=f"{server.client}:{server.name}",
            detail=detail,
            severity=severity,
            evidence={
                "command": server.command,
                "args": server.args,
                "auto_approved": auto,
                "user": server.user,
            },
            location=server.config_path,
        )


@check(
    "ES-102",
    "Filesystem MCP server rooted at a filesystem or home directory",
    Severity.HIGH,
    Vector.MCP_SERVERS,
    rationale=(
        "A filesystem server scoped to /, ~ or a wildcard can read SSH keys, browser "
        "profiles, cloud credentials and source trees — the whole endpoint is in scope "
        "of any injected instruction."
    ),
    fix="Re-scope the server to the specific project directories it needs, never a home or root path.",
    owasp=("LLM06: Excessive Agency", "LLM02: Sensitive Information Disclosure"),
    atlas=("AML.T0053: LLM Plugin Compromise", "AML.T0025: Exfiltration via Cyber Means"),
)
def filesystem_root_scope(inv: HostInventory, ctx: CheckContext) -> Iterable[Finding]:
    meta = filesystem_root_scope.meta
    for server in inv.mcp_servers:
        risky = root_scope_args(server.args)
        if not risky:
            continue
        fs_hint = matches_any(server.invocation, FILESYSTEM_HINTS)
        fs_tools = [t.name for t in server.tools if "file" in t.name.lower() or "read" in t.name.lower()]
        if not fs_hint and not fs_tools and not is_exec_interpreter(server.command):
            # A root-ish path argument to a non-filesystem server is weaker
            # evidence; still worth a look, one severity step down.
            severity = downgrade(Severity.MEDIUM) if server.disabled else Severity.MEDIUM
            why = "root-scoped path argument on a non-filesystem server"
        else:
            severity = severity_for(meta, server)
            why = f"filesystem-capable server ({fs_hint or 'advertised file tools'})"
        yield meta.finding(
            host=inv.hostname,
            subject=f"{server.client}:{server.name}",
            detail=f"{why} granted scope: {', '.join(risky)}{_suffix(server)}",
            severity=severity,
            evidence={"scopes": risky, "command": server.command, "args": server.args},
            location=server.config_path,
        )


@check(
    "ES-103",
    "Network-egress MCP server with unrestricted host scope",
    Severity.MEDIUM,
    Vector.MCP_SERVERS,
    rationale=(
        "A fetch/browser server with no host allow-list is a ready-made exfiltration "
        "channel: injected content can name the destination."
    ),
    fix=(
        "Constrain the server to an allow-list of hosts/domains, or route it through an "
        "egress proxy that enforces one. If the endpoint URL itself carries the credential, "
        "rotate it and move to a header- or broker-supplied token."
    ),
    owasp=("LLM02: Sensitive Information Disclosure", "LLM06: Excessive Agency"),
    atlas=("AML.T0025: Exfiltration via Cyber Means",),
)
def unrestricted_egress(inv: HostInventory, ctx: CheckContext) -> Iterable[Finding]:
    meta = unrestricted_egress.meta
    for server in inv.mcp_servers:
        hint = matches_any(server.invocation, NETWORK_HINTS)
        remote = server.url and not any(h in server.url.lower() for h in _LOOPBACK)
        if not hint and not remote:
            continue
        if any(a.split("=")[0] in EGRESS_SCOPE_ARGS for a in server.args):
            continue
        severity = severity_for(meta, server)
        if remote:
            detail = f"remote {server.transport.value} transport to external endpoint {server.url}"
            if server.url_carries_secret:
                # The endpoint URL is the credential: anyone who reads the
                # config — or a backup of it — holds the session.
                detail += "; endpoint URL embeds a credential-shaped segment (redacted here)"
                severity = Severity.HIGH
        else:
            detail = f"egress-capable server ({hint}) with no host allow-list argument"
        yield meta.finding(
            host=inv.hostname,
            subject=f"{server.client}:{server.name}",
            detail=detail + _suffix(server),
            severity=severity,
            evidence={
                "command": server.command,
                "args": server.args,
                "url": server.url,
                "url_carries_secret": server.url_carries_secret,
            },
            location=server.config_path,
        )


@check(
    "ES-104",
    "MCP server binary runs from a user- or world-writable path",
    Severity.HIGH,
    Vector.MCP_SERVERS,
    rationale=(
        "Anything that can write to /tmp, %TEMP% or a world-writable file can replace "
        "the server binary and inherit every permission the agent has granted it."
    ),
    fix="Move the server under a managed, root-owned install path and tighten permissions to 0755 or stricter.",
    owasp=("LLM03: Supply Chain",),
    atlas=("AML.T0010: ML Supply Chain Compromise", "AML.T0011: User Execution"),
)
def writable_server_path(inv: HostInventory, ctx: CheckContext) -> Iterable[Finding]:
    meta = writable_server_path.meta
    for server in inv.mcp_servers:
        candidates = [server.command_path or server.command, *server.args[:2]]
        hits = [c for c in candidates if is_writable_path(c)]
        world_writable = mode_is_world_writable(server.command_mode)
        if not hits and not world_writable:
            continue
        if world_writable:
            detail = f"server binary {server.command_path} has mode {server.command_mode} (world-writable)"
        else:
            detail = f"server launches from writable staging path: {hits[0]}"
        yield meta.finding(
            host=inv.hostname,
            subject=f"{server.client}:{server.name}",
            detail=detail + _suffix(server),
            severity=severity_for(meta, server),
            evidence={
                "command": server.command,
                "command_path": server.command_path,
                "command_mode": server.command_mode,
                "writable_paths": hits,
            },
            location=server.config_path,
        )


@check(
    "ES-105",
    "MCP server declared in an elevated (root/SYSTEM) scope",
    Severity.MEDIUM,
    Vector.MCP_SERVERS,
    rationale=(
        "A server declared system-wide or launched with elevation runs outside the "
        "user's blast radius: its tools act with administrative rights."
    ),
    fix="Move the declaration into the user scope and drop elevation; no MCP server should need root to answer a model.",
    owasp=("LLM06: Excessive Agency",),
    atlas=("AML.T0053: LLM Plugin Compromise", "AML.T0012: Valid Accounts"),
)
def elevated_server(inv: HostInventory, ctx: CheckContext) -> Iterable[Finding]:
    meta = elevated_server.meta
    escalators = {"sudo", "doas", "runas", "runas.exe", "gsudo", "pkexec"}
    for server in inv.mcp_servers:
        reasons = []
        if basename(server.command) in escalators:
            reasons.append(f"launched via {basename(server.command)}")
        if server.elevated_scope:
            reasons.append("declared in a root/SYSTEM-owned config scope")
        if server.user in ("root", "SYSTEM") and server.user:
            reasons.append(f"config owned by {server.user}")
        if not reasons:
            continue
        yield meta.finding(
            host=inv.hostname,
            subject=f"{server.client}:{server.name}",
            detail="; ".join(reasons) + _suffix(server),
            severity=severity_for(meta, server),
            evidence={"command": server.command, "user": server.user, "config": server.config_path},
            location=server.config_path,
        )
