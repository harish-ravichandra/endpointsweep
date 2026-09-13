#!/usr/bin/env python3
"""Regenerate the golden expectations under ``testdata/golden/``.

Run this after a deliberate change to the check catalog, then read the diff:
if a check's behaviour changed, the diff is the review. Never run it to make a
failing test pass without reading what moved.

    python3 testdata/generate_golden.py
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from endpointsweep.checks import CheckContext  # noqa: E402
from endpointsweep.merge import load_inventory, merge  # noqa: E402

GOLDEN_DIR = ROOT / "testdata" / "golden"
HOSTS_DIR = ROOT / "testdata" / "hosts"

#: The seeded dirty host used by the single-host golden test (M2).
DIRTY_HOST = "ws-mac-1021"
FIXED_TIMESTAMP = "2026-09-14T04:00:00Z"


def build() -> tuple[dict, dict]:
    inventories = [load_inventory(p) for p in sorted(HOSTS_DIR.glob("*.json"))]
    fleet = merge(inventories, CheckContext(), generated_at=FIXED_TIMESTAMP)

    counts: Counter = Counter()
    for finding in fleet.all_findings:
        counts[f"{finding.id}:{finding.severity.value}"] += 1

    fleet_summary = {
        "host_count": fleet.host_count,
        "fleet_score": fleet.score,
        "finding_counts": dict(sorted(counts.items())),
        "fleet_finding_subjects": sorted(f"{f.id}:{f.subject}" for f in fleet.findings),
        "census_totals": fleet.census["totals"],
        "top_servers": [
            {"name": r["name"], "hosts": r["hosts"], "variants": r["variants"]}
            for r in fleet.census["top_servers"]
        ],
    }

    host = next(h for h in fleet.hosts if h.inventory.hostname == DIRTY_HOST)
    host_golden = {
        "hostname": host.inventory.hostname,
        "score": host.score,
        "max_severity": host.max_severity.value,
        "findings": sorted(
            f"{f.id}:{f.severity.value}:{f.subject}" for f in host.findings
        ),
    }
    return fleet_summary, host_golden


def main() -> None:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    fleet_summary, host_golden = build()
    (GOLDEN_DIR / "fleet_summary.json").write_text(
        json.dumps(fleet_summary, indent=2) + "\n", encoding="utf-8"
    )
    (GOLDEN_DIR / f"{DIRTY_HOST}.json").write_text(
        json.dumps(host_golden, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote golden files to {GOLDEN_DIR}")


if __name__ == "__main__":
    main()
