"""Makes the repo importable without installing it, and exposes fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from helpers import GOLDEN, HOSTS, TESTDATA  # noqa: E402


@pytest.fixture(scope="session")
def testdata_dir() -> Path:
    return TESTDATA


@pytest.fixture(scope="session")
def host_files() -> list[Path]:
    return sorted(HOSTS.glob("*.json"))


@pytest.fixture(scope="session")
def golden_dir() -> Path:
    return GOLDEN


@pytest.fixture(scope="session")
def fleet():
    """The merged synthetic fleet, built once per test session."""
    from endpointsweep.checks import CheckContext
    from endpointsweep.merge import load_inventory, merge

    inventories = [load_inventory(p) for p in sorted(HOSTS.glob("*.json"))]
    return merge(inventories, CheckContext(), generated_at="2026-09-14T04:00:00Z")
