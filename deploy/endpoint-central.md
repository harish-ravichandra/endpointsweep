# ManageEngine Endpoint Central

Endpoint Central runs a script per endpoint, shows you a truncated stdout, and
trusts the exit code. That is exactly the contract the collectors implement.

## 1. Upload the collector

**Configurations → Script Repository → Add Script**

| Field | macOS | Linux | Windows |
|---|---|---|---|
| Script file | `endpointsweep_collect.sh` | `endpointsweep_collect.bash` | `endpointsweep_collect.ps1` |
| Script type | Shell | Shell | PowerShell |
| Arguments | `/Library/Application Support/EndpointSweep/out.json` | `/var/tmp/endpointsweep/out.json` | `C:\ProgramData\EndpointSweep\out.json` |

Endpoint Central executes macOS shell scripts with `/bin/sh` — which is why the
macOS collector is strict POSIX with a `.sh` extension. Do not rename it to
`.bash`; the console picks the interpreter from the extension.

## 2. Create the output directory first

Add a pre-step (or a one-line wrapper) so the collector has somewhere to write:

```sh
# macOS / Linux
mkdir -p "$(dirname "$1")" && chmod 700 "$(dirname "$1")"
```

```powershell
# Windows
New-Item -ItemType Directory -Force -Path 'C:\ProgramData\EndpointSweep' | Out-Null
```

## 3. Deploy as a Computer Configuration

**Configurations → Add Configuration → Custom Script**

- **Execute as:** System/root. The collector expects this and enumerates every
  user profile when it sees uid 0 / SYSTEM.
- **Schedule:** weekly is enough — MCP configuration does not change hourly.
- **Retry:** on, exit code 2 means the collector itself failed.

## 4. Read the results in the console

The Execution Status column shows the single summary line:

```
ENDPOINTSWEEP|ws-mac-1042|7|HIGH
```

Sort by exit code to get the endpoints that flagged something. Treat this as
triage only — the collector runs a handful of cheap greps, and the analyzer is
the authority on findings.

## 5. Collect the JSON

Endpoint Central does not pull files back from a script. Two options:

**A. Collect on the next run.** Add a follow-up script that uploads the file to
a share you control:

```sh
#!/bin/sh
OUT="/var/tmp/endpointsweep/out.json"
[ -f "$OUT" ] || exit 2
curl --fail --silent --show-error \
  --upload-file "$OUT" \
  "https://files.internal.example/endpointsweep/$(hostname).json" || exit 2
rm -f "$OUT"
```

**B. Write to a path your inventory already collects** — many sites already pull
`/var/tmp/*.json` or a custom-attribute directory. Point `$1` at that.

## 6. Custom attribute (optional)

If you want the summary in the inventory database rather than in job output,
make a second one-line script that echoes the last summary:

```sh
#!/bin/sh
tail -n 1 /var/tmp/endpointsweep/summary.txt 2>/dev/null || echo "ENDPOINTSWEEP|$(hostname)|0|NONE"
```

## Notes

- The collector writes its output `0600`. If your transport needs another user to
  read it, `chmod` it in the wrapper — deliberately, not by default.
- Set `ES_VERSION_PROBE=0` in the script's environment for the first run so
  nothing is executed on the endpoint at all.
