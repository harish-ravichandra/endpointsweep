"""The red line: no structure EndpointSweep produces can carry a secret value."""

from __future__ import annotations

import dataclasses
import json

import pytest

from endpointsweep import schema
from endpointsweep.schema import (
    FORBIDDEN_KEYS,
    Finding,
    HostInventory,
    HostMeta,
    MCPServer,
    SecretLeakError,
    Severity,
    Vector,
    assert_no_secret_values,
    to_dict,
    to_json,
)

DATACLASSES = [
    obj
    for obj in vars(schema).values()
    if dataclasses.is_dataclass(obj) and isinstance(obj, type)
]


def test_no_dataclass_declares_a_value_bearing_field():
    """A field that could hold a secret must not exist anywhere in the schema."""
    offenders = []
    for cls in DATACLASSES:
        for field in dataclasses.fields(cls):
            if field.name.lower() in FORBIDDEN_KEYS:
                offenders.append(f"{cls.__name__}.{field.name}")
    assert offenders == [], f"value-bearing fields present: {offenders}"


def test_env_is_represented_by_names_only():
    fields = {f.name for f in dataclasses.fields(MCPServer)}
    assert "env_var_names" in fields
    assert "env" not in fields


def test_guard_rejects_a_forbidden_key():
    with pytest.raises(SecretLeakError):
        assert_no_secret_values({"server": {"env": {"TOKEN": "sk-live"}}})


def test_guard_walks_nested_lists():
    with pytest.raises(SecretLeakError):
        assert_no_secret_values({"hosts": [{"creds": [{"password": "x"}]}]})


def test_to_json_runs_the_guard():
    finding = Finding(
        id="ES-999",
        title="t",
        severity=Severity.LOW,
        vector=Vector.MCP_SERVERS,
        evidence={"token": "sk-live-leak"},
    )
    with pytest.raises(SecretLeakError):
        to_json(finding)


def test_round_trip_preserves_the_inventory():
    inv = HostInventory(
        host=HostMeta(hostname="h1", os=schema.OS.MACOS, users_scanned=["alex"]),
        mcp_servers=[
            MCPServer(
                name="fs",
                client="claude_desktop",
                config_path="/tmp/c.json",
                command="npx",
                args=["-y", "pkg"],
                env_var_names=["GITHUB_TOKEN"],
            )
        ],
    )
    restored = schema.host_inventory_from_dict(json.loads(to_json(inv)))
    assert restored.hostname == "h1"
    assert restored.host.os is schema.OS.MACOS
    assert restored.mcp_servers[0].env_var_names == ["GITHUB_TOKEN"]
    assert restored.mcp_servers[0].transport is schema.Transport.UNKNOWN


def test_severity_ordering_and_weights():
    assert Severity.max([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL
    assert Severity.INFO.weight == 0
    weights = [s.weight for s in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
    assert weights == sorted(weights)


def test_to_dict_encodes_enums_as_values():
    encoded = to_dict(Finding(id="ES-1", title="t", severity=Severity.HIGH, vector=Vector.LOCAL_MODELS))
    assert encoded["severity"] == "HIGH"
    assert encoded["vector"] == 5
