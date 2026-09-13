"""Documentation is part of the contract (brief §8).

Every check must be documented at merge time, and the rubric must describe every
vector the schema can emit. These tests make that a build failure, not a habit.
"""

from __future__ import annotations

import re

from endpointsweep.checks import REGISTRY, all_checks
from endpointsweep.schema import Vector

from helpers import ROOT

CHECKS_DOC = ROOT / "docs" / "checks.md"
RUBRIC_DOC = ROOT / "docs" / "rubric.md"
README = ROOT / "README.md"


def checks_text() -> str:
    return CHECKS_DOC.read_text(encoding="utf-8")


def test_every_check_has_a_documented_section():
    text = checks_text()
    for check in all_checks():
        assert f"### {check.meta.id} —" in text, f"{check.meta.id} has no section in docs/checks.md"


def test_catalog_table_matches_the_registry():
    """The summary table must not drift from the code."""
    table = re.findall(r"^\| (ES-\d+) \| (\w+) \| V(\d) \| (host|fleet) \|", checks_text(), re.M)
    assert table, "no catalog table found in docs/checks.md"
    documented = {row[0]: (row[1], int(row[2]), row[3]) for row in table}
    registered = {
        c.meta.id: (c.meta.severity.value, c.meta.vector.value, c.meta.scope) for c in all_checks()
    }
    assert documented == registered


def test_no_documented_check_is_missing_from_the_registry():
    documented = set(re.findall(r"^### (ES-\d+) —", checks_text(), re.M))
    assert documented == set(REGISTRY)


def test_every_check_documents_a_fix():
    text = checks_text()
    sections = re.split(r"^### ", text, flags=re.M)[1:]
    for section in sections:
        check_id = section.split(" ")[0]
        if check_id in ("ES-404", "ES-903"):  # informational: no fix to document
            continue
        assert "**Fix.**" in section, f"{check_id} documents no fix"


def test_rubric_covers_every_vector():
    text = RUBRIC_DOC.read_text(encoding="utf-8")
    for vector in Vector:
        assert f"V{vector.value}" in text, f"rubric does not mention V{vector.value}"
        assert vector.title in text, f"rubric does not name {vector.title!r}"


def test_rubric_states_the_scoring_weights():
    text = RUBRIC_DOC.read_text(encoding="utf-8")
    from endpointsweep.schema import Severity

    for severity in Severity:
        assert f"| {severity.value} | {severity.weight} |" in text, severity


def test_rubric_declares_coverage_for_every_vector():
    text = RUBRIC_DOC.read_text(encoding="utf-8")
    coverage = text.split("## 7. Coverage")[1]
    for vector in Vector:
        assert f"V{vector.value} {vector.title}" in coverage


def test_readme_documents_the_collector_contract():
    text = README.read_text(encoding="utf-8")
    assert "ENDPOINTSWEEP|" in text
    for name in ("endpointsweep_collect.sh", "endpointsweep_collect.bash", "endpointsweep_collect.ps1"):
        assert name in text
