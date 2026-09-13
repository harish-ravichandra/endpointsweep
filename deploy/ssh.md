# Plain ssh

For Linux servers, build agents, and for testing a collector change before it
goes anywhere near a console.

## One host

```sh
scp collectors/endpointsweep_collect.bash host1:/tmp/
ssh host1 'sudo bash /tmp/endpointsweep_collect.bash /tmp/endpointsweep.json; echo "exit=$?"'
scp host1:/tmp/endpointsweep.json collected/host1.json
```

## A list of hosts

```sh
#!/bin/bash
# sweep.sh — collect from every host in hosts.txt, in parallel, then report.
set -uo pipefail

COLLECTOR="collectors/endpointsweep_collect.bash"
OUTDIR="collected"
PARALLEL=10

mkdir -p "$OUTDIR"

collect_one() {
    host="$1"
    remote="/tmp/endpointsweep.$$.json"
    if ! scp -q -o ConnectTimeout=10 "$COLLECTOR" "$host:/tmp/endpointsweep_collect.bash"; then
        echo "SKIP $host (copy failed)" >&2
        return
    fi
    # Exit 1 means "found something", which is not a failure to collect.
    ssh -o ConnectTimeout=10 "$host" \
        "sudo ES_VERSION_PROBE=0 bash /tmp/endpointsweep_collect.bash $remote; \
         sudo chmod 644 $remote; rm -f /tmp/endpointsweep_collect.bash" \
        > "$OUTDIR/$host.summary" 2>/dev/null
    if scp -q "$host:$remote" "$OUTDIR/$host.json"; then
        ssh -o ConnectTimeout=10 "$host" "sudo rm -f $remote" 2>/dev/null
        echo "OK   $host $(cat "$OUTDIR/$host.summary")"
    else
        echo "FAIL $host (no output)" >&2
    fi
}
export -f collect_one
export COLLECTOR OUTDIR

xargs -P "$PARALLEL" -I{} bash -c 'collect_one "$@"' _ {} < hosts.txt

endpointsweep merge "$OUTDIR" -o fleet.json
endpointsweep report fleet.json -o fleet.md
echo "report: fleet.md"
```

Run it:

```sh
printf '%s\n' host1 host2 host3 > hosts.txt
bash sweep.sh
```

## macOS over ssh

Same shape, with the POSIX collector and `/bin/sh`:

```sh
ssh mac1 'sudo /bin/sh /tmp/endpointsweep_collect.sh /tmp/endpointsweep.json'
```

Remote Login sessions do not always have Full Disk Access. Paths the collector
cannot read are recorded in the `errors` array rather than silently skipped —
check it on the first host before trusting a fleet-wide result.

## Windows over ssh (OpenSSH server)

```powershell
scp collectors/endpointsweep_collect.ps1 win1:C:/Windows/Temp/
ssh win1 "powershell -NoProfile -ExecutionPolicy Bypass -File C:/Windows/Temp/endpointsweep_collect.ps1 C:/Windows/Temp/endpointsweep.json"
scp win1:C:/Windows/Temp/endpointsweep.json collected/win1.json
```

## Notes

- `sudo` is what makes the collector enumerate all user profiles. Without it you
  get the invoking user only — fine for a spot check, misleading for a fleet.
- `ES_VERSION_PROBE=0` is set above on purpose: over ssh you usually want a pure
  read.
- Exit code `1` means findings, not failure. Do not let `set -e` in your wrapper
  turn a successful collection into an error.
