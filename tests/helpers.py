"""Paths and small builders shared by the test modules."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TESTDATA = ROOT / "testdata"
CONFIGS = TESTDATA / "configs"
HOSTS = TESTDATA / "hosts"
GOLDEN = TESTDATA / "golden"
COLLECTORS = ROOT / "collectors"


def load_config(name: str) -> dict:
    return json.loads((CONFIGS / name).read_text(encoding="utf-8"))


def config_block(name: str, *, client: str, user: str = "alex", path: str | None = None) -> dict:
    """Wrap a fixture config the way a collector would report it."""
    return {
        "client": client,
        "path": path or str(CONFIGS / name),
        "user": user,
        "elevated_scope": False,
        "raw": load_config(name),
    }


def make_server(name: str = "srv", **kwargs):
    from endpointsweep.schema import MCPServer

    defaults = {"client": "claude_desktop", "config_path": "/tmp/config.json"}
    defaults.update(kwargs)
    return MCPServer(name=name, **defaults)


def make_inventory(hostname: str = "test-host", **kwargs):
    from endpointsweep.schema import HostInventory, HostMeta

    return HostInventory(host=HostMeta(hostname=hostname), **kwargs)


def run_checks(inventory, ctx=None):
    from endpointsweep.checks import CheckContext, run_host_checks

    return run_host_checks(inventory, ctx or CheckContext())


def ids(findings) -> set[str]:
    return {f.id for f in findings}


def by_id(findings, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]
