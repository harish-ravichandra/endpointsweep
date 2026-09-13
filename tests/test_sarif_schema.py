"""EndpointSweep's SARIF must validate against the published SARIF 2.1.0 schema.

Skipped when ``jsonschema`` is not installed (it is in the ``dev`` extra); CI
runs the same validation with ``check-jsonschema`` against the same vendored
schema file.
"""

from __future__ import annotations

import json

import pytest

from endpointsweep.report import fleet_sarif, host_sarif

from helpers import HOSTS, ROOT

jsonschema = pytest.importorskip("jsonschema")

SCHEMA_FILE = ROOT / "testdata" / "schema" / "sarif-2.1.0.json"


@pytest.fixture(scope="module")
def validator():
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    return jsonschema.Draft7Validator(schema)


def test_vendored_schema_is_the_sarif_schema(validator):
    assert "sarif-schema-2.1.0.json" in validator.schema["$id"]


def test_fleet_sarif_validates(fleet, validator):
    document = json.loads(json.dumps(fleet_sarif(fleet)))
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.path))
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors[:5])


def test_host_sarif_validates(validator):
    from endpointsweep.merge import analyze_host, load_inventory

    report = analyze_host(load_inventory(HOSTS / "ws-win-1175.json"))
    document = json.loads(json.dumps(host_sarif(report)))
    errors = list(validator.iter_errors(document))
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors[:5])


def test_empty_fleet_still_produces_valid_sarif(validator):
    from endpointsweep.checks import CheckContext
    from endpointsweep.merge import merge

    document = json.loads(json.dumps(fleet_sarif(merge([], CheckContext()))))
    errors = list(validator.iter_errors(document))
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors[:5])
