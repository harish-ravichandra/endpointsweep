<#
.SYNOPSIS
    EndpointSweep collector - Windows (PowerShell 5.1 compatible).

.DESCRIPTION
    Inventories MCP client configs, agentic CLI tools, local model runtimes, IDE
    AI extensions, AI SDK manifests and credential-shaped variable NAMES.

    Deployment contract (see deploy/intune.md):
        endpointsweep_collect.ps1 [OutputPath]
          - with an argument : JSON is written to that path, the one-line summary
                               goes to stdout (MDM consoles truncate at ~500 chars)
          - with no argument : JSON goes to stdout, the summary goes to stderr
        exit 0 = nothing flagged, 1 = something flagged, 2 = the collector failed

    Red line: this script reports variable NAMES and file PATHS. It never reads or
    transmits a variable value. Config files are embedded with every value under an
    env/headers/secret-shaped key replaced by "[redacted]" before anything is written.

.NOTES
    No modules beyond the Windows base install. Tolerates running as SYSTEM.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$OutputPath = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$script:CollectorVersion = '0.1.0'
$script:SchemaVersion = '1'
$script:Findings = 0
$script:MaxSeverity = 'NONE'
$script:MaxSeverityRank = 0
$script:Errors = New-Object System.Collections.ArrayList

# --- tunables (environment, so MDM consoles can set them without editing) ----
function Get-Tunable {
    param([string]$Name, $Default)
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrEmpty($value)) { return $Default }
    return $value
}
$ScanManifests = [int](Get-Tunable 'ES_SCAN_MANIFESTS' 1)
$VersionProbe = [int](Get-Tunable 'ES_VERSION_PROBE' 1)
$MaxConfigBytes = [int](Get-Tunable 'ES_MAX_CONFIG_BYTES' 262144)
$MaxManifests = [int](Get-Tunable 'ES_MAX_MANIFESTS' 200)
$ManifestDepth = [int](Get-Tunable 'ES_MANIFEST_DEPTH' 3)
$ProbeTimeout = [int](Get-Tunable 'ES_PROBE_TIMEOUT' 5)
$ManifestRootsOverride = Get-Tunable 'ES_MANIFEST_ROOTS' ''

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

function Add-CollectorError {
    param([string]$Scope, [string]$Message)
    $null = $script:Errors.Add([ordered]@{ scope = $Scope; message = $Message })
}

function Add-TriageFinding {
    param([ValidateSet('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')][string]$Severity)
    $script:Findings++
    $rank = @{ 'CRITICAL' = 4; 'HIGH' = 3; 'MEDIUM' = 2; 'LOW' = 1 }[$Severity]
    if ($rank -gt $script:MaxSeverityRank) {
        $script:MaxSeverityRank = $rank
        $script:MaxSeverity = $Severity
    }
}

function Test-KeyShapedName {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return $false }
    return ($Name -match '(?i)(api[_-]?key|access[_-]?key|secret|token|password|passwd|credential|private[_-]?key|bearer|session[_-]?key|auth|_key$|^key$|_pat$|^pat$)')
}

function Test-EnvContextName {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return $false }
    return ($Name -match '(?i)^(env|envVars|environment|environmentVariables|secrets|headers)$')
}

# ---------------------------------------------------------------------------
# JSONC -> JSON, then structural redaction
# ---------------------------------------------------------------------------

function Remove-JsonComment {
    <# Strips // and /* */ comments and trailing commas outside string literals. #>
    param([string]$Text)
    $out = New-Object System.Text.StringBuilder
    $i = 0
    $n = $Text.Length
    while ($i -lt $n) {
        $c = $Text[$i]
        if ($c -eq '"') {
            $null = $out.Append($c); $i++
            while ($i -lt $n) {
                $ch = $Text[$i]
                if ($ch -eq '\') {
                    $null = $out.Append($ch)
                    if ($i + 1 -lt $n) { $null = $out.Append($Text[$i + 1]) }
                    $i += 2
                    continue
                }
                $null = $out.Append($ch); $i++
                if ($ch -eq '"') { break }
            }
            continue
        }
        if ($c -eq '/' -and $i + 1 -lt $n) {
            $next = $Text[$i + 1]
            if ($next -eq '/') { while ($i -lt $n -and $Text[$i] -ne "`n") { $i++ }; continue }
            if ($next -eq '*') {
                $i += 2
                while ($i + 1 -lt $n -and -not ($Text[$i] -eq '*' -and $Text[$i + 1] -eq '/')) { $i++ }
                $i += 2
                continue
            }
        }
        if ($c -eq ',') {
            $j = $i + 1
            while ($j -lt $n -and ($Text[$j] -match '\s')) { $j++ }
            if ($j -lt $n -and ($Text[$j] -eq '}' -or $Text[$j] -eq ']')) { $i++; continue }
        }
        $null = $out.Append($c); $i++
    }
    return $out.ToString()
}

function Protect-ConfigNode {
    <# Returns a redacted copy of a parsed JSON node. Values under an env-ish or
       credential-shaped key never survive the copy. #>
    param($Node, [string]$ParentKey = '', [int]$Depth = 0)

    if ($Depth -gt 24) { return '[depth-limited]' }
    if ($null -eq $Node) { return $null }

    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        $copy = [ordered]@{}
        foreach ($prop in $Node.PSObject.Properties) {
            if ((Test-EnvContextName $prop.Name) -and ($prop.Value -is [System.Management.Automation.PSCustomObject])) {
                # Keep the variable NAMES, drop every value.
                $inner = [ordered]@{}
                foreach ($envProp in $prop.Value.PSObject.Properties) { $inner[$envProp.Name] = '[redacted]' }
                $copy[$prop.Name] = $inner
            }
            elseif ((Test-KeyShapedName $prop.Name) -or (Test-EnvContextName $prop.Name)) {
                $copy[$prop.Name] = '[redacted]'
            }
            else {
                $copy[$prop.Name] = Protect-ConfigNode -Node $prop.Value -ParentKey $prop.Name -Depth ($Depth + 1)
            }
        }
        return $copy
    }

    if ($Node -is [System.Array]) {
        if ((Test-KeyShapedName $ParentKey) -or (Test-EnvContextName $ParentKey)) {
            return @($Node | ForEach-Object { '[redacted]' })
        }
        return @($Node | ForEach-Object { Protect-ConfigNode -Node $_ -ParentKey $ParentKey -Depth ($Depth + 1) })
    }

    return $Node
}

# ---------------------------------------------------------------------------
# Host facts
# ---------------------------------------------------------------------------

$hostName = $env:COMPUTERNAME
if ([string]::IsNullOrEmpty($hostName)) { $hostName = 'unknown' }

$osVersion = ''
try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($osInfo) { $osVersion = "$($osInfo.Caption) $($osInfo.Version)".Trim() }
}
catch { $osVersion = [Environment]::OSVersion.VersionString }
if ([string]::IsNullOrEmpty($osVersion)) { $osVersion = [Environment]::OSVersion.VersionString }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isSystem = $identity.User.Value -eq 'S-1-5-18'
$collectorUid = if ($isSystem) { 0 } else { $null }

# Profiles to scan: every real user when SYSTEM/admin, otherwise just ours.
$userProfiles = @()
if ($isSystem -or $isElevated) {
    $usersRoot = Join-Path $env:SystemDrive 'Users'
    foreach ($dir in (Get-ChildItem -Path $usersRoot -Directory -ErrorAction SilentlyContinue)) {
        if ($dir.Name -in @('Public', 'Default', 'Default User', 'All Users', 'WDAGUtilityAccount')) { continue }
        $userProfiles += [pscustomobject]@{ Home = $dir.FullName; User = $dir.Name }
    }
}
if ($userProfiles.Count -eq 0) {
    $userProfiles = @([pscustomobject]@{ Home = $env:USERPROFILE; User = $env:USERNAME })
}

# ---------------------------------------------------------------------------
# Safety: never execute a user-writable binary from an elevated context.
# ---------------------------------------------------------------------------

function Test-SafeToExecute {
    param([string]$Path)
    if ($VersionProbe -ne 1) { return $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    if (-not ($isSystem -or $isElevated)) { return $true }
    $lower = $Path.ToLowerInvariant()
    foreach ($bad in @('\users\', '\temp\', '\appdata\', '\downloads\', '\programdata\')) {
        if ($lower.Contains($bad)) { return $false }
    }
    return $true
}

function Get-ToolVersion {
    param([string]$Path)
    if (-not (Test-SafeToExecute $Path)) { return '' }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Path
        $psi.Arguments = '--version'
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        if (-not $proc.WaitForExit($ProbeTimeout * 1000)) {
            $proc.Kill()
            Add-CollectorError 'version_probe' "$Path --version timed out after ${ProbeTimeout}s"
            return ''
        }
        $line = ($proc.StandardOutput.ReadToEnd() -split "`n")[0]
        if ($line.Length -gt 80) { $line = $line.Substring(0, 80) }
        return $line.Trim()
    }
    catch {
        return ''
    }
}

# ---------------------------------------------------------------------------
# MCP client configs
# ---------------------------------------------------------------------------

$clientConfigs = New-Object System.Collections.ArrayList
$commandIndex = [ordered]@{}
$commandNames = New-Object System.Collections.Generic.HashSet[string]

function Test-TriageConfig {
    param([string]$Json)
    if ($Json -match '(?i)"command"\s*:\s*"([^"]*[\\/])?(sh|bash|cmd|cmd\.exe|powershell|powershell\.exe|pwsh|wsl)"') { Add-TriageFinding 'HIGH' }
    if ($Json -match '(@latest"|"-y"|"--yes")') { Add-TriageFinding 'HIGH' }
    if ($Json -match '(?i)"[A-Za-z0-9_]*(api_?key|token|secret|password|credential)[A-Za-z0-9_]*"\s*:') { Add-TriageFinding 'HIGH' }
    if ($Json -match '"(/|~|[A-Za-z]:\\)"') { Add-TriageFinding 'HIGH' }
}

function Add-ClientConfig {
    param([string]$Client, [string]$Path, [string]$User)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $item) { Add-CollectorError 'config' "$Path not readable"; return }
    if ($item.Length -gt $MaxConfigBytes) {
        Add-CollectorError 'config' "$Path skipped: $($item.Length) bytes exceeds ES_MAX_CONFIG_BYTES"
        return
    }

    $elevatedScope = $Path -match '(?i)^[A-Z]:\\(Windows|ProgramData|Program Files)'
    $entry = [ordered]@{
        client         = $Client
        path           = $Path
        user           = $User
        elevated_scope = [bool]$elevatedScope
        bytes          = $item.Length
    }

    try {
        $text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $clean = Remove-JsonComment -Text $text
        $parsed = $clean | ConvertFrom-Json -ErrorAction Stop
        $redacted = Protect-ConfigNode -Node $parsed
        $entry['raw'] = $redacted
        Test-TriageConfig -Json ($redacted | ConvertTo-Json -Depth 20 -Compress)

        foreach ($match in [regex]::Matches($clean, '"command"\s*:\s*"([^"]*)"')) {
            $null = $commandNames.Add($match.Groups[1].Value)
        }
    }
    catch {
        Add-CollectorError 'config' "$Path present but not parseable as JSON; recorded as present only"
        $entry['parse_error'] = $true
        $entry['raw'] = $null
    }
    $null = $clientConfigs.Add($entry)
}

foreach ($userProfile in $userProfiles) {
    $profileHome = $userProfile.Home
    $profileUser = $userProfile.User
    $profileAppData = Join-Path $profileHome 'AppData\Roaming'

    Add-ClientConfig 'claude_desktop' (Join-Path $profileAppData 'Claude\claude_desktop_config.json') $profileUser
    Add-ClientConfig 'claude_code' (Join-Path $profileHome '.claude.json') $profileUser
    Add-ClientConfig 'claude_code' (Join-Path $profileHome '.claude\settings.json') $profileUser
    Add-ClientConfig 'claude_code' (Join-Path $profileHome '.claude\settings.local.json') $profileUser
    Add-ClientConfig 'cursor' (Join-Path $profileHome '.cursor\mcp.json') $profileUser
    Add-ClientConfig 'windsurf' (Join-Path $profileHome '.codeium\windsurf\mcp_config.json') $profileUser
    Add-ClientConfig 'vscode' (Join-Path $profileAppData 'Code\User\mcp.json') $profileUser
    Add-ClientConfig 'vscode' (Join-Path $profileAppData 'Code\User\settings.json') $profileUser
    Add-ClientConfig 'vscode' (Join-Path $profileAppData 'Code - Insiders\User\mcp.json') $profileUser
    Add-ClientConfig 'cline' (Join-Path $profileAppData 'Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json') $profileUser
    Add-ClientConfig 'cline' (Join-Path $profileAppData 'Cursor\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json') $profileUser
    Add-ClientConfig 'continue' (Join-Path $profileHome '.continue\config.json') $profileUser

    foreach ($generic in (Get-ChildItem -Path (Join-Path $profileHome '.config') -Filter 'mcp*.json' -Recurse -Depth 2 -File -ErrorAction SilentlyContinue | Select-Object -First 25)) {
        Add-ClientConfig 'generic' $generic.FullName $profileUser
    }
    foreach ($project in (Get-ChildItem -Path $profileHome -Filter '.mcp.json' -Recurse -Depth $ManifestDepth -File -ErrorAction SilentlyContinue | Select-Object -First 25)) {
        Add-ClientConfig 'generic' $project.FullName $profileUser
    }
}
Add-ClientConfig 'claude_desktop' (Join-Path $env:ProgramData 'Claude\claude_desktop_config.json') 'SYSTEM'

foreach ($cmd in $commandNames) {
    if ([string]::IsNullOrEmpty($cmd)) { continue }
    $resolved = ''
    if ($cmd -match '^[A-Za-z]:[\\/]' -or $cmd.StartsWith('\\')) {
        if (Test-Path -LiteralPath $cmd) { $resolved = $cmd }
    }
    else {
        $found = Get-Command $cmd -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found -and $found.Source) { $resolved = $found.Source }
    }
    if ([string]::IsNullOrEmpty($resolved)) { continue }
    $commandIndex[$cmd] = [ordered]@{ path = $resolved; mode = '' }
    if ($resolved -match '(?i)\\(Temp|Public|Downloads)\\') { Add-TriageFinding 'HIGH' }
}

# ---------------------------------------------------------------------------
# Agentic CLI tools
# ---------------------------------------------------------------------------

$agenticBins = @('claude', 'cline', 'aider', 'goose', 'codex', 'opencode', 'cursor-agent',
    'windsurf', 'amp', 'crush', 'continue', 'gemini', 'copilot', 'q', 'gptme', 'sgpt')
$agenticTools = New-Object System.Collections.ArrayList
$seenTools = New-Object System.Collections.Generic.HashSet[string]

foreach ($bin in $agenticBins) {
    $cmd = Get-Command $bin -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $cmd -or [string]::IsNullOrEmpty($cmd.Source)) { continue }
    if (-not $seenTools.Add($cmd.Source)) { continue }
    $null = $agenticTools.Add([ordered]@{
            name    = $bin
            path    = $cmd.Source
            version = (Get-ToolVersion $cmd.Source)
            user    = $env:USERNAME
            source  = 'path'
        })
}

foreach ($userProfile in $userProfiles) {
    $dirs = @(
        (Join-Path $userProfile.Home 'AppData\Roaming\npm'),
        (Join-Path $userProfile.Home '.local\bin'),
        (Join-Path $userProfile.Home '.bun\bin'),
        (Join-Path $userProfile.Home 'AppData\Local\Programs'),
        (Join-Path $userProfile.Home '.volta\bin')
    )
    foreach ($dir in $dirs) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($bin in $agenticBins) {
            foreach ($ext in @('.cmd', '.exe', '.ps1', '')) {
                $candidate = Join-Path $dir "$bin$ext"
                if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
                if (-not $seenTools.Add($candidate)) { continue }
                $null = $agenticTools.Add([ordered]@{
                        name    = $bin
                        path    = $candidate
                        version = (Get-ToolVersion $candidate)
                        user    = $userProfile.User
                        source  = 'package_manager'
                    })
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Local model runtimes
# ---------------------------------------------------------------------------

$modelRuntimes = New-Object System.Collections.ArrayList

function Get-ListenAddress {
    param([string]$ProcessName)
    $addresses = New-Object System.Collections.ArrayList
    try {
        $procIds = (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
        if ($procIds) {
            foreach ($conn in (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
                if ($procIds -contains $conn.OwningProcess) {
                    $null = $addresses.Add("$($conn.LocalAddress):$($conn.LocalPort)")
                }
            }
        }
    }
    catch {
        Add-CollectorError 'listen_addrs' "could not enumerate listening sockets for $ProcessName"
    }
    return @($addresses | Sort-Object -Unique)
}

function Get-OllamaModel {
    $models = New-Object System.Collections.ArrayList
    foreach ($userProfile in $userProfiles) {
        $manifests = Join-Path $userProfile.Home '.ollama\models\manifests'
        if (-not (Test-Path -LiteralPath $manifests)) { continue }
        foreach ($file in (Get-ChildItem -Path $manifests -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 100)) {
            $relative = $file.FullName.Substring($manifests.Length).TrimStart('\', '/')
            $relative = $relative -replace '^registry\.ollama\.ai[\\/]', '' -replace '^library[\\/]', ''
            $parts = $relative -split '[\\/]'
            if ($parts.Count -ge 2) {
                $tag = $parts[-1]
                $name = ($parts[0..($parts.Count - 2)] -join '/')
                $null = $models.Add("${name}:${tag}")
            }
        }
    }
    return @($models | Sort-Object -Unique)
}

$ollamaCmd = Get-Command ollama -ErrorAction SilentlyContinue | Select-Object -First 1
$ollamaInstalled = ($null -ne $ollamaCmd) -or (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'Programs\Ollama'))
if ($ollamaInstalled) {
    $ollamaRunning = $null -ne (Get-Process -Name ollama -ErrorAction SilentlyContinue)
    $addresses = Get-ListenAddress 'ollama'
    foreach ($addr in $addresses) {
        if ($addr -like '0.0.0.0:*' -or $addr -like '::*' -or $addr -like '*:::*') { Add-TriageFinding 'LOW'; break }
    }
    $ollamaPath = ''
    if ($ollamaCmd) { $ollamaPath = $ollamaCmd.Source }
    $null = $modelRuntimes.Add([ordered]@{
            name         = 'ollama'
            installed    = $true
            running      = $ollamaRunning
            listen_addrs = $addresses
            models       = (Get-OllamaModel)
            version      = (Get-ToolVersion $ollamaPath)
        })
}

foreach ($runtime in @('llama-server', 'localai', 'lmstudio', 'LM Studio')) {
    $proc = Get-Process -Name $runtime -ErrorAction SilentlyContinue
    $cmd = Get-Command $runtime -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $proc -and $null -eq $cmd) { continue }
    $null = $modelRuntimes.Add([ordered]@{
            name         = $runtime
            installed    = $true
            running      = ($null -ne $proc)
            listen_addrs = (Get-ListenAddress $runtime)
            models       = @()
            version      = ''
        })
}

# ---------------------------------------------------------------------------
# IDE AI extensions
# ---------------------------------------------------------------------------

$ideExtensions = New-Object System.Collections.ArrayList
$aiExtPattern = '(?i)(continue|cline|claude-dev|copilot|codeium|windsurf|tabnine|sourcegraph\.cody|amazon-q|augment|supermaven|twinny|geminicodeassist|roo-cline|kilocode|aider|codegpt|blackbox)'

foreach ($userProfile in $userProfiles) {
    foreach ($extRoot in @('.vscode\extensions', '.vscode-insiders\extensions', '.cursor\extensions', '.windsurf\extensions')) {
        $path = Join-Path $userProfile.Home $extRoot
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $ide = ($extRoot -split '\\')[0].TrimStart('.')
        foreach ($dir in (Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $aiExtPattern } | Select-Object -First 60)) {
            $extId = $dir.Name -replace '-\d+\.\d+\.\d+.*$', ''
            $extVersion = ''
            if ($dir.Name -match '-(\d+\.\d+\.\d+.*)$') { $extVersion = $Matches[1] }
            $null = $ideExtensions.Add([ordered]@{
                    ide          = $ide
                    extension_id = $extId
                    version      = $extVersion
                    user         = $userProfile.User
                    path         = $dir.FullName
                })
        }
    }
    $jetbrains = Join-Path $userProfile.Home 'AppData\Roaming\JetBrains'
    foreach ($plugin in (Get-ChildItem -Path $jetbrains -Directory -Recurse -Depth 2 -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "$aiExtPattern|aiassistant|junie" } | Select-Object -First 30)) {
        $null = $ideExtensions.Add([ordered]@{
                ide          = 'jetbrains'
                extension_id = $plugin.Name
                version      = ''
                user         = $userProfile.User
                path         = $plugin.FullName
            })
    }
}

# ---------------------------------------------------------------------------
# AI SDK manifests
# ---------------------------------------------------------------------------

$packageManifests = New-Object System.Collections.ArrayList
$aiPkgPattern = '(?i)([@a-z0-9_./-]*(openai|anthropic|langchain|llama-?index|modelcontextprotocol|ollama|cohere|mistralai|generative-ai|litellm|semantic-kernel|autogen|crewai|haystack-ai|ai-sdk)[@a-z0-9_./-]*)'

if ($ScanManifests -eq 1) {
    $manifestCount = 0
    foreach ($userProfile in $userProfiles) {
        $roots = if ([string]::IsNullOrEmpty($ManifestRootsOverride)) {
            @('Projects', 'source\repos', 'src', 'code', 'dev', 'work', 'repos', 'Documents\GitHub') |
            ForEach-Object { Join-Path $userProfile.Home $_ }
        }
        else { $ManifestRootsOverride -split ';' }

        foreach ($root in $roots) {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            $files = Get-ChildItem -Path $root -Recurse -Depth $ManifestDepth -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -in @('package.json', 'requirements.txt', 'pyproject.toml', 'Pipfile') -and $_.FullName -notmatch 'node_modules' } |
            Select-Object -First 40
            foreach ($file in $files) {
                if ($manifestCount -ge $MaxManifests) { break }
                $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction SilentlyContinue
                if ([string]::IsNullOrEmpty($content)) { continue }
                # Dependency NAMES only - never the file body.
                $packages = @([regex]::Matches($content, $aiPkgPattern) |
                    ForEach-Object { $_.Groups[1].Value.Trim('"', "'", ' ') } |
                    Sort-Object -Unique | Select-Object -First 20)
                if ($packages.Count -eq 0) { continue }
                $manifestCount++
                $eco = if ($file.Name -eq 'package.json') { 'npm' } else { 'pypi' }
                $null = $packageManifests.Add([ordered]@{
                        path        = $file.FullName
                        ecosystem   = $eco
                        user        = $userProfile.User
                        ai_packages = $packages
                    })
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Credential-shaped variable NAMES (names and paths only - never values)
# ---------------------------------------------------------------------------

$envKeySignals = New-Object System.Collections.ArrayList
$keyNamePattern = '(?i)(API_?KEY|ACCESS_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?|PRIVATE_?KEY|AUTH|BEARER|CLIENT_?SECRET|_PAT|_KEY)'

function Add-EnvKeySignal {
    param([string]$Path, [string]$User, [string]$Kind)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $names = New-Object System.Collections.Generic.HashSet[string]
    foreach ($line in (Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue | Select-Object -First 2000)) {
        # Cut at the first '=' or ' = ': a value never reaches the pipeline.
        if ($line -match '^\s*(?:\$env:|\$|export\s+|set\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=') {
            $name = $Matches[1]
            if ($name -match $keyNamePattern) { $null = $names.Add($name) }
        }
    }
    if ($names.Count -eq 0) { return }
    $null = $envKeySignals.Add([ordered]@{
            path      = $Path
            var_names = @($names | Sort-Object)
            user      = $User
            kind      = $Kind
        })
    Add-TriageFinding 'MEDIUM'
}

foreach ($userProfile in $userProfiles) {
    $profileScripts = @(
        'Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1',
        'Documents\PowerShell\Microsoft.PowerShell_profile.ps1',
        '.bashrc',
        '.profile'
    )
    foreach ($profileScript in $profileScripts) {
        Add-EnvKeySignal (Join-Path $userProfile.Home $script) $userProfile.User 'shell_rc'
    }
    foreach ($root in @('Projects', 'source\repos', 'src', 'code', 'dev', 'work', 'repos')) {
        $path = Join-Path $userProfile.Home $root
        if (-not (Test-Path -LiteralPath $path)) { continue }
        foreach ($dotenv in (Get-ChildItem -Path $path -Recurse -Depth $ManifestDepth -File -Filter '.env*' -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch 'node_modules' } | Select-Object -First 20)) {
            Add-EnvKeySignal $dotenv.FullName $userProfile.User 'dotenv'
        }
    }
}

# ---------------------------------------------------------------------------
# Assemble
# ---------------------------------------------------------------------------

$document = [ordered]@{
    collector         = [ordered]@{
        name     = 'endpointsweep'
        version  = $script:CollectorVersion
        schema   = $script:SchemaVersion
        platform = 'windows'
    }
    host              = [ordered]@{
        hostname         = $hostName
        os               = 'windows'
        os_version       = $osVersion
        arch             = $env:PROCESSOR_ARCHITECTURE
        collected_at     = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        collector_version = $script:CollectorVersion
        collector_schema = $script:SchemaVersion
        collector_uid    = $collectorUid
        elevated         = [bool]($isSystem -or $isElevated)
        users_scanned    = @($userProfiles | ForEach-Object { $_.User })
        tags             = @{}
    }
    command_index     = $commandIndex
    client_configs    = @($clientConfigs)
    agentic_tools     = @($agenticTools)
    model_runtimes    = @($modelRuntimes)
    ide_extensions    = @($ideExtensions)
    package_manifests = @($packageManifests)
    env_key_signals   = @($envKeySignals)
    errors            = @($script:Errors)
}

$json = $document | ConvertTo-Json -Depth 30
$summary = "ENDPOINTSWEEP|$hostName|$($script:Findings)|$($script:MaxSeverity)"

if (-not [string]::IsNullOrEmpty($OutputPath)) {
    try {
        $encoding = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($OutputPath, $json, $encoding)
        Write-Output $summary
    }
    catch {
        [Console]::Error.WriteLine("ENDPOINTSWEEP|$hostName|0|ERROR write failed: $OutputPath")
        exit 2
    }
}
else {
    Write-Output $json
    [Console]::Error.WriteLine($summary)
}

if ($script:Findings -gt 0) { exit 1 }
exit 0
