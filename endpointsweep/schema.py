"""Canonical data model shared by collectors, checks, merge and reporting.

Red line (brief §8): no dataclass in this module has a field that can hold a
secret *value*. Environment variables are represented by NAME and the PATH they
were seen in, never by value. ``assert_no_secret_values`` enforces that on any
structure about to be serialised, and ``tests/test_no_secret_values.py`` proves
it for the whole schema.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from . import COLLECTOR_SCHEMA_VERSION, __version__

# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------


class Severity(str, Enum):
    """Finding severity. Ordering is given by :meth:`rank`, not by name."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def weight(self) -> int:
        """Risk-score weight (see docs/rubric.md §4)."""
        return _SEVERITY_WEIGHT[self]

    @classmethod
    def max(cls, severities: list[Severity]) -> Severity:
        return max(severities, key=lambda s: s.rank) if severities else cls.INFO


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 5,
    Severity.HIGH: 12,
    Severity.CRITICAL: 25,
}


class Vector(int, Enum):
    """The eight enterprise AI attack-surface vectors (docs/rubric.md §2)."""

    BROWSER_AI_MODES = 1
    BROWSER_AI_EXTENSIONS = 2
    AGENTIC_AI = 3
    MCP_SERVERS = 4
    LOCAL_MODELS = 5
    IDE_AI_PLUGINS = 6
    AI_LIBRARIES = 7
    API_KEY_INTEGRATIONS = 8

    @property
    def title(self) -> str:
        return _VECTOR_TITLE[self]


_VECTOR_TITLE: dict[Vector, str] = {
    Vector.BROWSER_AI_MODES: "Browser AI modes",
    Vector.BROWSER_AI_EXTENSIONS: "Browser AI extensions",
    Vector.AGENTIC_AI: "Agentic AI tooling",
    Vector.MCP_SERVERS: "Local MCP servers",
    Vector.LOCAL_MODELS: "Local model runtimes",
    Vector.IDE_AI_PLUGINS: "IDE AI plugins",
    Vector.AI_LIBRARIES: "AI libraries in code",
    Vector.API_KEY_INTEGRATIONS: "Direct API-key integrations",
}


class Transport(str, Enum):
    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"
    UNKNOWN = "unknown"


class OS(str, Enum):
    MACOS = "macos"
    LINUX = "linux"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


# --------------------------------------------------------------------------
# Host inventory
# --------------------------------------------------------------------------


@dataclass
class HostMeta:
    hostname: str
    os: OS = OS.UNKNOWN
    os_version: str = ""
    arch: str = ""
    collected_at: str = ""
    collector_version: str = ""
    collector_schema: str = COLLECTOR_SCHEMA_VERSION
    #: 0 when the collector ran as root/SYSTEM (the EDR/MDM case).
    collector_uid: int | None = None
    elevated: bool = False
    users_scanned: list[str] = field(default_factory=list)
    #: Optional site-supplied tags (business unit, managed status, ...).
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class MCPTool:
    """A tool advertised by an MCP server, as cached by a client config.

    Descriptions are kept because they are the injection surface (ES-201/202).
    They are tool metadata, not user content.
    """

    name: str
    description: str = ""
    server: str = ""


@dataclass
class MCPServer:
    """One declared MCP server entry from one client config."""

    name: str
    client: str
    config_path: str
    user: str = ""
    transport: Transport = Transport.UNKNOWN
    command: str = ""
    args: list[str] = field(default_factory=list)
    #: Names only. Values are never collected (brief §4.3).
    env_var_names: list[str] = field(default_factory=list)
    url: str = ""
    #: True when a credential-shaped segment was stripped from ``url``.
    url_carries_secret: bool = False
    disabled: bool = False
    #: True when the config was found under a root/SYSTEM-owned scope.
    elevated_scope: bool = False
    #: Resolved absolute path of ``command`` when the collector could find it.
    command_path: str = ""
    #: Permission bits of ``command_path`` as an octal string, e.g. "0777".
    command_mode: str = ""
    tools: list[MCPTool] = field(default_factory=list)
    #: Approved/ignored via an ``autoApprove``-style key in the client config.
    auto_approved_tools: list[str] = field(default_factory=list)

    @property
    def invocation(self) -> str:
        return " ".join([self.command, *self.args]).strip()

    @property
    def identity(self) -> str:
        """Fleet-wide identity key: the server name, case-normalised."""
        return self.name.strip().lower()


@dataclass
class AgenticTool:
    name: str
    path: str = ""
    version: str = ""
    user: str = ""
    source: str = "path"  # path | app_bundle | package_manager | registry


@dataclass
class ModelRuntime:
    name: str
    installed: bool = False
    running: bool = False
    #: e.g. ["127.0.0.1:11434"] — addresses only, never request contents.
    listen_addrs: list[str] = field(default_factory=list)
    models: list[str] = field(default_factory=list)
    version: str = ""


@dataclass
class IDEExtension:
    ide: str
    extension_id: str
    version: str = ""
    user: str = ""
    path: str = ""


@dataclass
class PackageManifest:
    """A dependency manifest containing AI SDK packages (names only)."""

    path: str
    ecosystem: str = ""  # npm | pypi | other
    user: str = ""
    ai_packages: list[str] = field(default_factory=list)


@dataclass
class EnvKeySignal:
    """Key-shaped variable NAMES seen in a file. Values are never read."""

    path: str
    var_names: list[str] = field(default_factory=list)
    user: str = ""
    kind: str = ""  # shell_rc | dotenv | mcp_env


@dataclass
class CollectorError:
    scope: str
    message: str


@dataclass
class HostInventory:
    host: HostMeta
    mcp_servers: list[MCPServer] = field(default_factory=list)
    agentic_tools: list[AgenticTool] = field(default_factory=list)
    model_runtimes: list[ModelRuntime] = field(default_factory=list)
    ide_extensions: list[IDEExtension] = field(default_factory=list)
    package_manifests: list[PackageManifest] = field(default_factory=list)
    env_key_signals: list[EnvKeySignal] = field(default_factory=list)
    errors: list[CollectorError] = field(default_factory=list)
    #: Where this inventory was loaded from (not sent by the collector).
    source_path: str = ""

    @property
    def hostname(self) -> str:
        return self.host.hostname


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


@dataclass
class Finding:
    """One check result. Immutable in spirit: checks build, nobody mutates."""

    id: str
    title: str
    severity: Severity
    vector: Vector
    #: Hostname, or "" for fleet-level findings.
    host: str = ""
    #: What the finding is about: server name, file path, package, ...
    subject: str = ""
    detail: str = ""
    #: Machine-readable supporting facts. Redacted by construction.
    evidence: dict[str, Any] = field(default_factory=dict)
    owasp: list[str] = field(default_factory=list)
    atlas: list[str] = field(default_factory=list)
    fix: str = ""
    #: Hosts involved, for fleet-level findings.
    hosts: list[str] = field(default_factory=list)
    #: Best-effort file location for SARIF, when the finding has one.
    location: str = ""

    @property
    def is_fleet(self) -> bool:
        return not self.host


@dataclass
class VectorScore:
    vector: Vector
    score: float
    findings: int
    covered: bool = True


@dataclass
class HostReport:
    inventory: HostInventory
    findings: list[Finding] = field(default_factory=list)
    score: float = 0.0
    vector_scores: list[VectorScore] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        return Severity.max([f.severity for f in self.findings])


@dataclass
class FleetModel:
    """N host reports plus fleet-level findings and census."""

    generated_at: str = ""
    hosts: list[HostReport] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    score: float = 0.0
    vector_scores: list[VectorScore] = field(default_factory=list)
    census: dict[str, Any] = field(default_factory=dict)
    tool_version: str = __version__

    @property
    def host_count(self) -> int:
        return len(self.hosts)

    @property
    def all_findings(self) -> list[Finding]:
        out: list[Finding] = list(self.findings)
        for h in self.hosts:
            out.extend(h.findings)
        return out


# --------------------------------------------------------------------------
# Serialisation helpers
# --------------------------------------------------------------------------

#: Keys that must never appear in any serialised EndpointSweep structure.
FORBIDDEN_KEYS = frozenset(
    {
        "value",
        "values",
        "secret",
        "secrets",
        "token",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "credential",
        "credentials",
        "env",  # the raw env *mapping*; env_var_names is the allowed shape
        "file_contents",
        "content",
    }
)


class SecretLeakError(AssertionError):
    """Raised when a structure carries a field that could hold a secret."""


def assert_no_secret_values(obj: Any, path: str = "$") -> None:
    """Recursively assert that no forbidden key name appears in ``obj``.

    This is a structural guard, not a content scanner: the design rule is that
    a value-bearing field must not *exist*, so its name must not appear.
    """
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        obj = dataclasses.asdict(obj)
    if isinstance(obj, dict):
        for key, val in obj.items():
            if str(key).lower() in FORBIDDEN_KEYS:
                raise SecretLeakError(f"forbidden key {key!r} at {path}")
            assert_no_secret_values(val, f"{path}.{key}")
    elif isinstance(obj, (list, tuple)):
        for i, val in enumerate(obj):
            assert_no_secret_values(val, f"{path}[{i}]")


def _encode(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _encode(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _encode(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_encode(v) for v in obj]
    return obj


def to_dict(obj: Any) -> Any:
    """Convert dataclasses/enums to plain JSON-safe structures."""
    return _encode(obj)


def to_json(obj: Any, *, indent: int = 2, guard: bool = True) -> str:
    data = to_dict(obj)
    if guard:
        assert_no_secret_values(data)
    return json.dumps(data, indent=indent, sort_keys=False, default=str)


def _enum_from(enum_cls: type[Enum], raw: Any, default: Any) -> Any:
    if raw is None or raw == "":
        return default
    try:
        return enum_cls(raw)
    except ValueError:
        try:
            return enum_cls[str(raw).upper()]
        except KeyError:
            return default


def _build(cls: type, data: dict[str, Any]) -> Any:
    """Instantiate a dataclass from a dict, ignoring unknown keys."""
    names = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in names})


def host_inventory_from_dict(data: dict[str, Any]) -> HostInventory:
    """Rehydrate a :class:`HostInventory` from ``endpointsweep analyze`` JSON."""
    raw_host = dict(data.get("host") or {})
    raw_host["os"] = _enum_from(OS, raw_host.get("os"), OS.UNKNOWN)
    host = _build(HostMeta, raw_host)

    servers: list[MCPServer] = []
    for raw in data.get("mcp_servers") or []:
        raw = dict(raw)
        raw["transport"] = _enum_from(Transport, raw.get("transport"), Transport.UNKNOWN)
        raw["tools"] = [_build(MCPTool, t) for t in raw.get("tools") or []]
        servers.append(_build(MCPServer, raw))

    return HostInventory(
        host=host,
        mcp_servers=servers,
        agentic_tools=[_build(AgenticTool, r) for r in data.get("agentic_tools") or []],
        model_runtimes=[_build(ModelRuntime, r) for r in data.get("model_runtimes") or []],
        ide_extensions=[_build(IDEExtension, r) for r in data.get("ide_extensions") or []],
        package_manifests=[
            _build(PackageManifest, r) for r in data.get("package_manifests") or []
        ],
        env_key_signals=[_build(EnvKeySignal, r) for r in data.get("env_key_signals") or []],
        errors=[_build(CollectorError, r) for r in data.get("errors") or []],
        source_path=data.get("source_path", ""),
    )


def finding_from_dict(data: dict[str, Any]) -> Finding:
    raw = dict(data)
    raw["severity"] = _enum_from(Severity, raw.get("severity"), Severity.INFO)
    raw["vector"] = _enum_from(Vector, raw.get("vector"), Vector.MCP_SERVERS)
    return _build(Finding, raw)
