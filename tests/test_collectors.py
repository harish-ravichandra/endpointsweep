"""The collectors themselves: contract, redaction, and a live Linux run.

The Linux collector is executed for real against a seeded fake home that
contains genuine-looking secret values. The test that matters is that none of
those values appear anywhere in the output.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from endpointsweep.merge import analyze_host, inventory_from_any

from helpers import COLLECTORS

MACOS = COLLECTORS / "endpointsweep_collect.sh"
LINUX = COLLECTORS / "endpointsweep_collect.bash"
WINDOWS = COLLECTORS / "endpointsweep_collect.ps1"

# Values seeded into the fake home. None of these may survive collection.
SECRETS = [
    "sk-ant-api03-REALLOOKINGSECRET0000",
    "ghp_REALLOOKINGGITHUBTOKEN000000",
    "postgres://user:hunter2@db.internal:5432/app",
    "Bearer eyJhbGciOiJIUzI1NiJ9.FAKEJWT.sig",
]

SUMMARY_RE = re.compile(r"^ENDPOINTSWEEP\|[^|]+\|\d+\|(NONE|LOW|MEDIUM|HIGH|CRITICAL)$")


def extract_awk(script: Path) -> str:
    """Pull the embedded JSONC redactor out of a collector."""
    text = script.read_text(encoding="utf-8")
    start = text.index("<<'AWKEOF'\n") + len("<<'AWKEOF'\n")
    end = text.index("\nAWKEOF\n", start)
    return text[start:end]


# ---------------------------------------------------------------------------
# Contract checks that run on any platform
# ---------------------------------------------------------------------------


def test_all_three_collectors_exist_with_the_documented_extensions():
    assert MACOS.is_file() and LINUX.is_file() and WINDOWS.is_file()
    assert MACOS.read_text(encoding="utf-8").startswith("#!/bin/sh\n")
    assert LINUX.read_text(encoding="utf-8").startswith("#!/bin/bash\n")


def test_macos_collector_is_free_of_bashisms():
    """POSIX sh only: no arrays, no [[ ]], no `local`, no += (brief §4.3)."""
    body = "\n".join(
        line for line in MACOS.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("#")
    )
    # `[[` is a bashism; `[[:space:]]` inside a regex is not.
    assert not re.search(r"\[\[(?!:)", body)
    assert not re.search(r"^\s*local\s", body, re.M)
    assert not re.search(r"^\s*declare\s", body, re.M)
    assert not re.search(r"\w\+=\(", body)
    assert "<<<" not in body


def test_both_shell_collectors_embed_the_same_redactor():
    """One redactor, two hosts: they must not drift apart."""
    assert extract_awk(MACOS) == extract_awk(LINUX)


def test_powershell_collector_avoids_automatic_variables():
    body = WINDOWS.read_text(encoding="utf-8")
    for name in ("profile", "home", "host", "input", "error"):
        assert not re.search(rf"^\s*\${name}\s*=", body, re.M | re.I), f"assigns ${name}"


def test_powershell_collector_declares_the_same_contract():
    body = WINDOWS.read_text(encoding="utf-8")
    assert "ENDPOINTSWEEP|$hostName|$($script:Findings)|$($script:MaxSeverity)" in body
    assert "ConvertTo-Json -Depth 30" in body


@pytest.mark.skipif(shutil.which("sh") is None, reason="no sh")
def test_shell_collectors_parse():
    assert subprocess.run(["sh", "-n", str(MACOS)]).returncode == 0
    assert subprocess.run(["bash", "-n", str(LINUX)]).returncode == 0


# ---------------------------------------------------------------------------
# Redactor behaviour
# ---------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("awk") is None, reason="no awk")
class TestRedactor:
    def redact(self, tmp_path: Path, text: str) -> subprocess.CompletedProcess:
        awk_file = tmp_path / "redact.awk"
        awk_file.write_text(extract_awk(LINUX), encoding="utf-8")
        src = tmp_path / "in.json"
        src.write_text(text, encoding="utf-8")
        return subprocess.run(
            ["awk", "-f", str(awk_file), str(src)], capture_output=True, text=True
        )

    def test_env_values_are_replaced_by_placeholders(self, tmp_path):
        doc = json.dumps(
            {"mcpServers": {"gh": {"command": "npx", "args": ["-y", "pkg"], "env": {"GITHUB_TOKEN": SECRETS[1], "PORT": 8080}}}}
        )
        result = self.redact(tmp_path, doc)
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        env = parsed["mcpServers"]["gh"]["env"]
        assert list(env) == ["GITHUB_TOKEN", "PORT"]
        assert set(env.values()) == {"[redacted]"}
        assert parsed["mcpServers"]["gh"]["args"] == ["-y", "pkg"]

    def test_credential_shaped_keys_are_redacted_anywhere(self, tmp_path):
        doc = json.dumps({"apiKey": SECRETS[0], "headers": {"Authorization": SECRETS[3]}, "name": "ok"})
        parsed = json.loads(self.redact(tmp_path, doc).stdout)
        assert parsed == {"apiKey": "[redacted]", "headers": {"Authorization": "[redacted]"}, "name": "ok"}

    def test_secret_arrays_are_redacted_elementwise(self, tmp_path):
        parsed = json.loads(self.redact(tmp_path, json.dumps({"secrets": ["a", "b"], "args": ["a", "b"]})).stdout)
        assert parsed["secrets"] == ["[redacted]", "[redacted]"]
        assert parsed["args"] == ["a", "b"]

    def test_jsonc_comments_and_trailing_commas_are_normalised(self, tmp_path):
        doc = '{\n  // line comment\n  "a": 1,\n  /* block */\n  "b": [1, 2,],\n}\n'
        parsed = json.loads(self.redact(tmp_path, doc).stdout)
        assert parsed == {"a": 1, "b": [1, 2]}

    def test_escapes_and_braces_inside_strings_survive(self, tmp_path):
        doc = json.dumps({"args": ['echo {"x":"}"} && ls'], "desc": 'say "hi" \\ ok'})
        parsed = json.loads(self.redact(tmp_path, doc).stdout)
        assert parsed["args"] == ['echo {"x":"}"} && ls']
        assert parsed["desc"] == 'say "hi" \\ ok'

    @pytest.mark.parametrize("bad", ['{"a": "unterminated', '{"a": 1,', '{"a": 1}}'])
    def test_malformed_json_fails_loudly(self, tmp_path, bad):
        """A broken fragment must never be embedded in the collector document."""
        assert self.redact(tmp_path, bad).returncode != 0


# ---------------------------------------------------------------------------
# Live Linux run
# ---------------------------------------------------------------------------


def seed_home(home: Path) -> None:
    (home / ".config/Claude").mkdir(parents=True)
    (home / ".config/Claude/claude_desktop_config.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "github": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github@latest"],
                        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": SECRETS[1]},
                    },
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor/mcp.json").write_text(
        json.dumps({"mcpServers": {"db": {"command": "uvx", "args": ["mcp-server-postgres==0.5.0"], "env": {"DATABASE_URL": SECRETS[2]}}}}),
        encoding="utf-8",
    )
    # JSONC, as VS Code actually writes it.
    (home / ".config/Code/User").mkdir(parents=True)
    (home / ".config/Code/User/settings.json").write_text(
        '{\n  // editor\n  "editor.fontSize": 13,\n  "mcp": { "servers": { "fetch": { "command": "uvx", "args": ["mcp-server-fetch"], } } },\n}\n',
        encoding="utf-8",
    )
    (home / ".bashrc").write_text(
        f'export ANTHROPIC_API_KEY="{SECRETS[0]}"\nexport EDITOR=vim\nalias ll="ls -l"\n',
        encoding="utf-8",
    )
    project = home / "Projects/service-api"
    project.mkdir(parents=True)
    (project / "package.json").write_text(
        json.dumps({"dependencies": {"openai": "^4.0.0", "langchain": "^0.2.0", "express": "^4.0.0"}}),
        encoding="utf-8",
    )
    (project / ".env").write_text(f"OPENAI_API_KEY={SECRETS[0]}\nPORT=3000\n", encoding="utf-8")
    # A deliberately broken config: recorded as present, never embedded.
    (home / ".continue").mkdir(parents=True)
    (home / ".continue/config.json").write_text('{"models": [', encoding="utf-8")


@pytest.fixture(scope="module")
def collected(tmp_path_factory):
    """Run the Linux collector once against a seeded fake home."""
    if sys.platform != "linux":
        pytest.skip("Linux collector")
    home = tmp_path_factory.mktemp("fakehome")
    seed_home(home)
    out = home.parent / "collect.json"
    env = dict(os.environ)
    env.update(
        {
            "HOME": str(home),
            "USER": "testuser",
            "ES_VERSION_PROBE": "0",
            "ES_SCAN_MANIFESTS": "1",
            "ES_MANIFEST_ROOTS": str(home / "Projects"),
        }
    )
    proc = subprocess.run(
        ["bash", str(LINUX), str(out)], capture_output=True, text=True, env=env, timeout=180
    )
    return proc, out, home


@pytest.mark.skipif(sys.platform != "linux", reason="Linux collector")
class TestLinuxCollectorRun:
    def test_exit_code_signals_findings(self, collected):
        proc, _, _ = collected
        assert proc.returncode in (0, 1), proc.stderr
        assert proc.returncode == 1, "seeded home should flag something"

    def test_summary_line_goes_to_stdout_when_a_path_is_given(self, collected):
        proc, _, _ = collected
        assert SUMMARY_RE.match(proc.stdout.strip()), proc.stdout
        assert len(proc.stdout.strip()) < 500, "must survive console truncation"

    def test_output_is_one_valid_json_document(self, collected):
        _, out, _ = collected
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["collector"]["name"] == "endpointsweep"
        assert data["host"]["os"] == "linux"
        assert data["host"]["hostname"]
        for key in (
            "client_configs",
            "agentic_tools",
            "model_runtimes",
            "ide_extensions",
            "package_manifests",
            "env_key_signals",
            "errors",
        ):
            assert isinstance(data[key], list), key

    def test_no_seeded_secret_survives_collection(self, collected):
        """The red line, tested end to end against real-looking secrets."""
        _, out, _ = collected
        text = out.read_text(encoding="utf-8")
        for secret in SECRETS:
            assert secret not in text, f"leaked: {secret[:12]}..."
        assert "hunter2" not in text
        assert "[redacted]" in text

    def test_configs_are_discovered_and_parse_into_servers(self, collected):
        _, out, _ = collected
        inventory = inventory_from_any(json.loads(out.read_text(encoding="utf-8")))
        names = {s.name for s in inventory.mcp_servers}
        assert {"github", "filesystem", "db", "fetch"} <= names
        github = next(s for s in inventory.mcp_servers if s.name == "github")
        assert github.env_var_names == ["GITHUB_PERSONAL_ACCESS_TOKEN"]

    def test_broken_config_is_recorded_not_embedded(self, collected):
        _, out, _ = collected
        data = json.loads(out.read_text(encoding="utf-8"))
        broken = [c for c in data["client_configs"] if c.get("parse_error")]
        assert broken and broken[0]["raw"] is None
        assert any("not parseable" in e["message"] for e in data["errors"])

    def test_credential_names_are_collected_without_values(self, collected):
        _, out, _ = collected
        data = json.loads(out.read_text(encoding="utf-8"))
        names = {n for sig in data["env_key_signals"] for n in sig["var_names"]}
        assert "ANTHROPIC_API_KEY" in names
        assert "EDITOR" not in names

    def test_ai_manifest_packages_are_names_only(self, collected):
        _, out, _ = collected
        data = json.loads(out.read_text(encoding="utf-8"))
        packages = {p for m in data["package_manifests"] for p in m["ai_packages"]}
        assert {"openai", "langchain"} <= packages
        assert "express" not in packages

    def test_analyzer_produces_the_expected_findings(self, collected):
        _, out, _ = collected
        inventory = inventory_from_any(json.loads(out.read_text(encoding="utf-8")))
        found = {f.id for f in analyze_host(inventory).findings}
        assert {"ES-102", "ES-301", "ES-401", "ES-402", "ES-404"} <= found

    def test_output_file_is_not_world_readable(self, collected):
        _, out, _ = collected
        assert oct(out.stat().st_mode)[-3:] == "600"

    def test_json_to_stdout_when_no_path_is_given(self, collected):
        _, _, home = collected
        env = dict(os.environ)
        env.update({"HOME": str(home), "USER": "testuser", "ES_VERSION_PROBE": "0", "ES_SCAN_MANIFESTS": "0"})
        proc = subprocess.run(["bash", str(LINUX)], capture_output=True, text=True, env=env, timeout=180)
        json.loads(proc.stdout)
        assert SUMMARY_RE.match(proc.stderr.strip().splitlines()[-1])


@pytest.mark.skipif(shutil.which("dash") is None, reason="dash (strict POSIX sh) not available")
def test_macos_collector_runs_under_strict_posix_sh(tmp_path):
    """Exercise the macOS collector under dash.

    It cannot find macOS-specific things on Linux, but it proves the script is
    genuinely POSIX — dash rejects the bashisms that bash-as-sh tolerates — and
    that the shared redaction path holds.
    """
    home = tmp_path / "machome"
    (home / "Library/Application Support/Claude").mkdir(parents=True)
    (home / "Library/Application Support/Claude/claude_desktop_config.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "gh": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github@latest"],
                        "env": {"GITHUB_TOKEN": SECRETS[1]},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (home / ".zshrc").write_text(
        f'export ANTHROPIC_API_KEY="{SECRETS[0]}"\nexport EDITOR=vi\n', encoding="utf-8"
    )

    out = tmp_path / "mac.json"
    env = dict(os.environ)
    env.update(
        {"HOME": str(home), "USER": "mactest", "ES_VERSION_PROBE": "0", "ES_SCAN_MANIFESTS": "0"}
    )
    proc = subprocess.run(
        ["dash", str(MACOS), str(out)], capture_output=True, text=True, env=env, timeout=180
    )
    assert proc.returncode in (0, 1), proc.stderr
    assert SUMMARY_RE.match(proc.stdout.strip()), proc.stdout

    text = out.read_text(encoding="utf-8")
    for secret in SECRETS[:2]:
        assert secret not in text
    data = json.loads(text)
    assert data["collector"]["platform"] == "macos"

    inventory = inventory_from_any(data)
    assert {s.name for s in inventory.mcp_servers} == {"gh"}
    assert inventory.mcp_servers[0].env_var_names == ["GITHUB_TOKEN"]
    assert {n for sig in inventory.env_key_signals for n in sig.var_names} == {"ANTHROPIC_API_KEY"}
