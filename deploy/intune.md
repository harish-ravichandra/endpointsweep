# Microsoft Intune (Windows)

Two mechanisms work. **Remediations** (formerly Proactive Remediations) is the
better fit: it runs on a schedule, keeps the exit code, and surfaces output in
the console. **Platform scripts** work if you do not have the licence for
Remediations.

## Option A — Remediations (recommended)

**Devices → Remediations → Create script package**

### Detection script

The collector *is* the detection script: it exits `1` when it flags something.

- **Script file:** `endpointsweep_collect.ps1`
- **Run this script using the logged-on credentials:** **No** (run as SYSTEM —
  the collector enumerates every user profile when it sees SYSTEM)
- **Enforce script signature check:** No, unless you sign it — see below
- **Run script in 64-bit PowerShell:** **Yes**

Intune does not pass arguments to Remediation scripts, so wrap it:

```powershell
# EndpointSweep detection wrapper
$outDir = 'C:\ProgramData\EndpointSweep'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
& "$PSScriptRoot\endpointsweep_collect.ps1" (Join-Path $outDir 'out.json')
exit $LASTEXITCODE
```

In practice, paste the collector body into the wrapper and call the logic
directly — Remediations uploads a single file.

### Remediation script

Leave it empty, or use it to ship the JSON somewhere:

```powershell
$out = 'C:\ProgramData\EndpointSweep\out.json'
if (-not (Test-Path $out)) { exit 1 }
Invoke-RestMethod -Method Put -Uri "https://files.internal.example/endpointsweep/$env:COMPUTERNAME.json" -InFile $out
Remove-Item $out -Force
exit 0
```

EndpointSweep is a reporting tool (brief §4.2: no enforcement), so the "remediation"
here is transport, not change.

### Schedule and scope

- **Schedule:** weekly.
- **Scope:** a pilot group first. Read ten devices' JSON before going wide.

The console shows the summary line under **Device status → Pre-remediation
output**, truncated to 2048 characters — the line is far shorter than that:

```
ENDPOINTSWEEP|WS-WIN-1042|7|HIGH
```

## Option B — Platform script

**Devices → Scripts and remediations → Platform scripts → Add → Windows 10 and later**

- **Run this script using the logged-on credentials:** No
- **Enforce script signature check:** No
- **Run script in 64-bit PowerShell Host:** Yes

Platform scripts run **once** (and again only on failure or reassignment), so
schedule recurrence yourself with a scheduled task the script registers, or use
Remediations.

## Execution policy and signing

Intune invokes the script with `-ExecutionPolicy Bypass`, so an unsigned script
runs as-is. If your baseline requires **AllSigned**:

1. Sign `endpointsweep_collect.ps1` with your internal code-signing certificate.
2. Enable **Enforce script signature check**.
3. Re-sign on every change — the collector is one file precisely so this is one
   signature.

## PowerShell version

The collector targets **5.1** (`Set-StrictMode -Version 2.0`, no `??`, no
ternary, no `ConvertFrom-Json -AsHashtable`). It runs unchanged under PowerShell
7 if you have it.

## Notes

- Output is written with `[System.IO.File]::WriteAllText` and UTF-8 **without**
  BOM. A BOM breaks `json.loads` on the analyzer side, which is why
  `Out-File -Encoding utf8` is not used.
- `Get-NetTCPConnection` supplies listening addresses for the local model
  runtime check; on Server Core without that module the check records an error
  and continues.
- Set `ES_VERSION_PROBE=0` as a machine environment variable for a first run in
  which the collector executes nothing.
