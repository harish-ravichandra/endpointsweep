"""Deterministic matchers shared by checks, merge and reporting.

Kept in one place so the check catalog stays readable and so that the same
notion of "what package is this server, really?" is used by the per-host checks
and by the fleet-level provenance check (ES-901).
"""

from __future__ import annotations

import math
import posixpath
import re

# --------------------------------------------------------------------------
# Command / package identification
# --------------------------------------------------------------------------

#: Interpreters that give an MCP server arbitrary local execution.
EXEC_INTERPRETERS = frozenset(
    {
        "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish",
        "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
        "wsl", "wsl.exe", "osascript", "applescript",
        "perl", "ruby", "php", "lua", "tclsh",
    }
)

#: Runtimes that only reach arbitrary execution with an inline-code flag.
INLINE_CODE_RUNTIMES: dict[str, tuple[str, ...]] = {
    "python": ("-c", "-m"),
    "python3": ("-c", "-m"),
    "python.exe": ("-c", "-m"),
    "node": ("-e", "--eval", "-p", "--print"),
    "node.exe": ("-e", "--eval", "-p", "--print"),
    "deno": ("eval",),
    "bun": ("-e", "--eval"),
}

#: Substrings in a package/command that mark a shell/exec-capable MCP server.
EXEC_SERVER_HINTS = (
    "server-shell", "mcp-shell", "shell-mcp", "mcp-server-shell",
    "mcp-server-commands", "command-runner", "run-command", "code-runner",
    "desktop-commander", "iterm-mcp", "terminal-mcp", "mcp-terminal",
    "server-terminal", "cli-mcp", "mcp-exec", "exec-server", "ssh-mcp",
)

#: Tool names that advertise local execution.
EXEC_TOOL_NAMES = (
    "run_command", "runcommand", "execute_command", "execute", "exec",
    "shell", "bash", "run_shell", "terminal", "run_script", "spawn_process",
    "start_process", "run_code", "python_exec", "eval",
)

FILESYSTEM_HINTS = (
    "server-filesystem", "filesystem-mcp", "mcp-filesystem", "mcp-fs",
    "file-system", "fs-server", "server-files", "everything-search",
    "desktop-commander", "mcp-server-file",
)

NETWORK_HINTS = (
    "server-fetch", "mcp-fetch", "fetch-mcp", "puppeteer", "playwright",
    "browser-use", "mcp-browser", "browserbase", "server-crawl", "crawl4ai",
    "scrape", "web-search", "curl", "wget", "httpie", "requests-mcp",
    "mcp-proxy", "server-http",
)

#: Args that constrain an egress-capable server to a host/domain allowlist.
EGRESS_SCOPE_ARGS = (
    "--allow", "--allowed-hosts", "--allowlist", "--allowed-domains",
    "--domains", "--host-allowlist", "--base-url", "--origin",
)

#: Path prefixes that any local user (or any process) can write to.
WRITABLE_PATH_PREFIXES = (
    "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/dev/shm/",
    "/users/shared/", "/var/folders/",
    "c:\\windows\\temp\\", "c:\\temp\\", "c:\\users\\public\\",
    "%temp%", "%tmp%", "$tmpdir", "/downloads/",
)

#: Root-ish scopes for a filesystem server.
ROOT_SCOPES = frozenset({"/", "~", "~/", "/users", "/home", "c:\\", "c:/", "/volumes", "*", "/*", "**"})

_PKG_RUNNERS = frozenset({"npx", "npx.cmd", "bunx", "bunx.cmd", "uvx", "uvx.exe", "pnpm", "yarn", "dlx"})
_RUNNER_VALUE_FLAGS = frozenset({"-p", "--package", "--with", "--from", "-w"})

_SEMVER_RE = re.compile(r"^\d+(\.\d+)*")


def basename(path: str) -> str:
    """Cross-platform basename, lowercased. Handles both slash flavours."""
    if not path:
        return ""
    return posixpath.basename(path.replace("\\", "/")).strip().lower()


def is_exec_interpreter(command: str) -> bool:
    return basename(command) in EXEC_INTERPRETERS


def inline_code_flags(command: str, args: list[str]) -> list[str]:
    """Return the inline-code flags present for runtimes like python/node."""
    flags = INLINE_CODE_RUNTIMES.get(basename(command), ())
    return [a for a in args if a in flags]


def split_spec(spec: str) -> tuple[str, str]:
    """Split ``@scope/name@version`` or ``name==1.2`` into (name, version)."""
    spec = spec.strip()
    if not spec:
        return "", ""
    for sep in ("==", ">=", "<=", "~=", "==="):
        if sep in spec:
            name, _, version = spec.partition(sep)
            return name.strip(), version.strip()
    if spec.startswith("@"):
        at = spec.find("@", 1)
        if at == -1:
            return spec, ""
        return spec[:at], spec[at + 1 :]
    name, sep, version = spec.partition("@")
    return (name, version) if sep else (spec, "")


def package_from_invocation(command: str, args: list[str]) -> str:
    """Best-effort package spec for a server launched via a package runner.

    Returns "" when the server is not launched through npx/uvx/pipx-style
    runners (a bare binary or a local script has no registry provenance).
    """
    cmd = basename(command)
    argv = list(args)

    if cmd in ("pnpm", "yarn", "npm"):
        while argv and argv[0] in ("dlx", "exec", "x", "run", "-s", "--silent"):
            argv.pop(0)
    elif cmd in ("pipx", "uv", "uv.exe"):
        while argv and argv[0] in ("run", "tool", "--quiet", "-q"):
            argv.pop(0)
    elif cmd not in _PKG_RUNNERS:
        return ""

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in _RUNNER_VALUE_FLAGS:
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        return arg
    return ""


def is_pinned(spec: str) -> bool:
    """True when a package spec names an exact, immutable version."""
    _, version = split_spec(spec)
    if not version:
        return False
    if version.lower() in ("latest", "next", "beta", "alpha", "*", "x", "canary"):
        return False
    if version[0] in "^~<>=":
        return False
    return bool(_SEMVER_RE.match(version))


_USER_HOME_RE = re.compile(r"^(/Users/|/home/|C:\\Users\\|C:/Users/)[^/\\]+", re.IGNORECASE)


def generalize_user_paths(text: str) -> str:
    """Replace a per-user home prefix with ``~`` so hosts compare cleanly."""
    return _USER_HOME_RE.sub("~", text or "")


def normalize_invocation(command: str, args: list[str]) -> str:
    """Canonical invocation string for cross-host comparison (ES-901).

    Drops the absolute path to the interpreter and the user's home prefix, but
    keeps the package, its version spec and its arguments — two hosts running
    the same server from different registries or versions must not collapse.
    """
    parts = [basename(command) or command.strip().lower()]
    for arg in args:
        parts.append(generalize_user_paths(arg).strip())
    return " ".join(p for p in parts if p)


# --------------------------------------------------------------------------
# Path judgements
# --------------------------------------------------------------------------


def is_writable_path(path: str) -> bool:
    """True when a path sits in a world- or user-writable staging area."""
    if not path:
        return False
    p = path.replace("\\", "/").lower()
    for prefix in WRITABLE_PATH_PREFIXES:
        norm = prefix.replace("\\", "/").lower()
        if p.startswith(norm) or norm in p:
            return True
    return False


def mode_is_world_writable(mode: str) -> bool:
    """``mode`` is an octal permission string such as ``0777`` or ``777``."""
    digits = (mode or "").strip()
    if not digits.isdigit() or len(digits) < 3:
        return False
    return int(digits[-1]) & 0o2 == 0o2


def looks_like_path(arg: str) -> bool:
    return bool(arg) and (
        arg.startswith(("/", "~", "./", "../", "*"))
        or re.match(r"^[A-Za-z]:[\\/]", arg) is not None
    )


#: /Users, /home, /Volumes, C:\Users — the parent of every user's whole world.
_ALL_HOMES_RE = re.compile(r"(/users|/home|/volumes|c:[\\/]users)/?\*?")


def _is_root_scope(arg: str) -> bool:
    """True when this path argument hands over a filesystem or home tree."""
    norm = arg.rstrip("/").lower() or "/"
    if norm in ROOT_SCOPES or arg.strip() in ROOT_SCOPES:
        return True
    if _ALL_HOMES_RE.fullmatch(norm):
        return True
    # A wildcard high in the tree, e.g. "/opt/*" or "~/*".
    return "*" in arg and arg.count("/") <= 2


def root_scope_args(args: list[str]) -> list[str]:
    """Path arguments that hand a server the whole filesystem or a home dir."""
    return [arg for arg in args if looks_like_path(arg) and _is_root_scope(arg)]


def matches_any(haystack: str, needles: tuple[str, ...]) -> str:
    """Return the first needle found in ``haystack`` (lowercased), else ""."""
    low = (haystack or "").lower()
    for needle in needles:
        if needle in low:
            return needle
    return ""


# --------------------------------------------------------------------------
# Text statistics (injection heuristics)
# --------------------------------------------------------------------------


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def non_ascii_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for ch in text if ord(ch) > 127) / len(text)


def levenshtein(a: str, b: str, *, max_distance: int = 3) -> int:
    """Bounded Levenshtein distance; returns ``max_distance + 1`` if beyond."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > max_distance:
            return max_distance + 1
        prev = cur
    return prev[-1]
