# Deployment recipes

Four ways to get a collector onto endpoints and its JSON back to one place.

The collectors are built for these consoles, not adapted to them (brief §4.3):

| Constraint | How the collectors handle it |
|---|---|
| stdout is truncated (~500 chars) | JSON goes to a file given as `$1`; only the `ENDPOINTSWEEP\|host\|n\|severity` line goes to stdout |
| only the exit code is trusted | `0` = nothing flagged, `1` = something flagged, `2` = the collector failed |
| minimal PATH, root context | PATH is enriched before probing; per-user npm/nvm/bun paths are globbed when running as root |
| no dependencies may be installed | POSIX `sh` / `bash` / PowerShell 5.1, base system tools only |
| scripts run as root/SYSTEM | A binary under a user-writable path is **never executed** for a version probe |

Pick your console:

- [endpoint-central.md](endpoint-central.md) — ManageEngine Endpoint Central
- [jamf.md](jamf.md) — Jamf Pro (macOS)
- [intune.md](intune.md) — Microsoft Intune (Windows)
- [ssh.md](ssh.md) — a plain ssh loop, for servers and for testing

## Tunables

Every collector reads the same environment variables, so a console can change
behaviour without editing the script:

| Variable | Default | Effect |
|---|---|---|
| `ES_SCAN_MANIFESTS` | `1` | Scan project dirs for AI SDK dependency manifests |
| `ES_MANIFEST_ROOTS` | conventional dirs | Space-separated roots to scan (`;`-separated on Windows) |
| `ES_MANIFEST_DEPTH` | `3` | Maximum directory depth for manifest and `.env` discovery |
| `ES_MAX_MANIFESTS` | `200` | Hard cap on manifests inspected per host |
| `ES_VERSION_PROBE` | `1` | Run `<tool> --version`; set `0` to never execute anything |
| `ES_PROBE_TIMEOUT` | `5` | Seconds before a version probe is killed |
| `ES_MAX_CONFIG_BYTES` | `262144` | Config files larger than this are recorded but not parsed |

On a first fleet-wide run, `ES_VERSION_PROBE=0` is the conservative choice: the
collector then executes nothing at all and is a pure read.

## What comes back

One JSON document per host. Collect them into a directory and:

```sh
endpointsweep merge /path/to/collected/ -o fleet.json
endpointsweep report fleet.json -o fleet.md
endpointsweep report fleet.json -f sarif -o fleet.sarif
```

## Before a fleet-wide run

1. Run it on your own machine first: `endpointsweep scan`.
2. Run it on ten machines and read the JSON by eye. You are looking for
   surprises in scope, not for findings.
3. Confirm size: a busy developer machine produces a few hundred KB; cap it with
   `ES_MAX_CONFIG_BYTES` and `ES_SCAN_MANIFESTS=0` if your transport is fragile.
4. Tell the people whose machines you are scanning what it reads, and point them
   at the red line: names and paths, never values.
