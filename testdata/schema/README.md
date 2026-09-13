# Vendored schemas

`sarif-2.1.0.json` — the OASIS SARIF 2.1.0 JSON Schema, fetched from
<https://json.schemastore.org/sarif-2.1.0.json> (`$id`:
`https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json`)
on 2026-09-14.

Vendored so that `tests/test_sarif_schema.py` and CI validate EndpointSweep's SARIF
output offline and reproducibly, rather than against whatever the network
returns that day.
