# Jamf Pro (macOS)

## 1. Add the script

**Settings → Computer Management → Scripts → New**

- **Display Name:** EndpointSweep Collector
- **Category:** Security
- **Script:** paste `collectors/endpointsweep_collect.sh` verbatim.

Jamf passes `$1` `$2` `$3` as mount point, computer name and username, and your
own parameters start at `$4`. The collector reads its output path from `$1`, so
**wrap it** rather than editing the collector:

```sh
#!/bin/sh
# Jamf wrapper: parameter 4 = output path
OUT="${4:-/Library/Application Support/EndpointSweep/out.json}"
mkdir -p "$(dirname "$OUT")" || exit 2
/usr/local/bin/endpointsweep_collect.sh "$OUT"
```

Set **Parameter 4 Label** to `Output JSON path`.

## 2. Deploy the collector file

Either bundle `endpointsweep_collect.sh` in a signed package that installs it to
`/usr/local/bin/` (mode `0755`, owner `root:wheel`), or inline the whole
collector into the Jamf script and drop the wrapper.

## 3. Policy

**Computers → Policies → New**

- **Trigger:** Recurring Check-in
- **Execution Frequency:** Once per week
- **Scripts:** the wrapper, with Parameter 4 set
- **Scope:** start with a pilot smart group, not All Computers

## 4. Extension Attribute for the summary

**Settings → Computer Management → Extension Attributes → New**

- **Data Type:** String
- **Input Type:** Script

```sh
#!/bin/sh
OUT="/Library/Application Support/EndpointSweep/out.json"
if [ -f "$OUT" ]; then
    # Report what the last collection found, without re-running it.
    HOSTNAME_V=$(hostname)
    SERVERS=$(grep -c '"client":' "$OUT" 2>/dev/null || echo 0)
    echo "<result>ENDPOINTSWEEP|$HOSTNAME_V|configs:$SERVERS</result>"
else
    echo "<result>ENDPOINTSWEEP|not-collected</result>"
fi
```

Smart groups can then target "has an MCP config" without you reading a single
report.

## 5. Getting the JSON back

Jamf has no file-upload-from-script primitive. Pick one:

- **Files and Processes → Execute Command** in a follow-up policy that `curl`s
  the file to an internal collector endpoint.
- A **Jamf Pro API** upload from the wrapper, using a limited-scope account.
- If you already run an EDR with a file-collection action, use that — the
  collector deliberately writes one file at one predictable path.

## 6. Privacy and PPPC

The collector reads configuration files inside user home directories. On modern
macOS, reading `~/Library/Application Support/...` as root from a script that
Jamf launched works without a TCC prompt, but `~/Documents`, `~/Desktop` and
`~/Downloads` are protected.

- The default manifest roots include `~/Documents/GitHub`. If you have not
  granted Full Disk Access to the Jamf agent, that path is skipped and the
  collector records an error rather than failing.
- Grant FDA to `jamf` via a PPPC profile only if you want manifest coverage, and
  say so in your change record. It is a real permission increase.
- Set `ES_SCAN_MANIFESTS=0` if you would rather not.
