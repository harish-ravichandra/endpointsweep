"""ES-4xx — credential, runtime and inventory hygiene."""

from __future__ import annotations

from endpointsweep.schema import (
    AgenticTool,
    EnvKeySignal,
    IDEExtension,
    ModelRuntime,
    PackageManifest,
    Severity,
)

from helpers import by_id, ids, make_inventory, make_server, run_checks


def test_key_shaped_env_names_in_config():
    server = make_server("gh", env_var_names=["GITHUB_PERSONAL_ACCESS_TOKEN", "LOG_LEVEL"])
    finding = by_id(run_checks(make_inventory(mcp_servers=[server])), "ES-401")[0]
    assert finding.severity is Severity.HIGH
    assert finding.evidence["variable_names"] == ["GITHUB_PERSONAL_ACCESS_TOKEN"]


def test_non_credential_env_names_are_ignored():
    server = make_server("x", env_var_names=["LOG_LEVEL", "PORT", "NODE_ENV"])
    assert "ES-401" not in ids(run_checks(make_inventory(mcp_servers=[server])))


def test_findings_never_carry_a_value_field():
    server = make_server("gh", env_var_names=["OPENAI_API_KEY"])
    finding = by_id(run_checks(make_inventory(mcp_servers=[server])), "ES-401")[0]
    assert "value" not in finding.evidence
    assert set(finding.evidence) == {"variable_names", "config_path", "user"}


def test_dotfile_key_names():
    inv = make_inventory(
        env_key_signals=[
            EnvKeySignal(path="/home/alex/.bashrc", var_names=["ANTHROPIC_API_KEY"], kind="shell_rc")
        ]
    )
    finding = by_id(run_checks(inv), "ES-402")[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.location == "/home/alex/.bashrc"


def test_exposed_ollama_is_medium_while_running():
    inv = make_inventory(
        model_runtimes=[
            ModelRuntime(name="ollama", installed=True, running=True, listen_addrs=["0.0.0.0:11434"])
        ]
    )
    finding = by_id(run_checks(inv), "ES-403")[0]
    assert finding.severity is Severity.MEDIUM


def test_stopped_exposed_runtime_stays_low():
    inv = make_inventory(
        model_runtimes=[
            ModelRuntime(name="ollama", installed=True, running=False, listen_addrs=["0.0.0.0:11434"])
        ]
    )
    assert by_id(run_checks(inv), "ES-403")[0].severity is Severity.LOW


def test_loopback_runtime_is_clean():
    inv = make_inventory(
        model_runtimes=[
            ModelRuntime(name="ollama", installed=True, running=True, listen_addrs=["127.0.0.1:11434"])
        ]
    )
    assert "ES-403" not in ids(run_checks(inv))


def test_inventory_findings_are_informational_and_split_by_vector():
    inv = make_inventory(
        mcp_servers=[make_server("a")],
        agentic_tools=[AgenticTool(name="claude", path="/usr/local/bin/claude", version="2.1.270")],
        ide_extensions=[IDEExtension(ide="vscode", extension_id="Continue.continue")],
        package_manifests=[PackageManifest(path="/p/package.json", ai_packages=["openai"])],
        model_runtimes=[ModelRuntime(name="ollama", installed=True)],
    )
    findings = by_id(run_checks(inv), "ES-404")
    assert {f.severity for f in findings} == {Severity.INFO}
    assert {f.subject for f in findings} == {
        "agentic-cli",
        "ide-ai-extensions",
        "ai-sdk-usage",
        "local-model-runtimes",
        "mcp-servers",
    }
    assert {f.vector.value for f in findings} == {3, 4, 5, 6, 7}


def test_empty_host_produces_no_inventory_findings():
    assert "ES-404" not in ids(run_checks(make_inventory()))
