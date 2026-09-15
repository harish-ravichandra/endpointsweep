#!/bin/sh
# EndpointSweep collector — macOS
#
# Inventories MCP client configs, agentic CLI tools, local model runtimes, IDE
# AI extensions, AI SDK manifests and credential-shaped variable NAMES.
#
# Deployment contract (see deploy/*.md):
#   endpointsweep_collect.sh [OUTPUT_JSON_PATH]
#     - with an argument : JSON is written to that path, the one-line summary
#                          goes to stdout (EDR/MDM consoles truncate at ~500 chars)
#     - with no argument : JSON goes to stdout, the summary goes to stderr
#   exit 0 = nothing flagged, 1 = something flagged, 2 = the collector failed
#
# Red line: this script reports variable NAMES and file PATHS. It never reads or
# transmits a variable value. Config files are embedded with every value under an
# env/headers/secret-shaped key replaced by "[redacted]" before anything is written.
#
# Strict POSIX sh: no bashisms, no arrays, no `local`, no `[[`. Runs as root or
# as a user. Depends only on the macOS base system (sh, awk, sed, grep, find,
# stat, hostname, sw_vers, lsof).

set -u

ES_COLLECTOR_VERSION="0.1.1"
ES_SCHEMA_VERSION="1"
ES_OS="macos"

OUTFILE="${1:-}"

PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin:/opt/local/bin:${PATH:-}"
export PATH
LC_ALL=C
export LC_ALL
umask 077

# --- tunables (environment, so MDM consoles can set them without editing) ----
ES_SCAN_MANIFESTS="${ES_SCAN_MANIFESTS:-1}"     # 0 disables AI SDK manifest scan
ES_VERSION_PROBE="${ES_VERSION_PROBE:-1}"       # 0 disables `tool --version`
ES_MAX_CONFIG_BYTES="${ES_MAX_CONFIG_BYTES:-262144}"
ES_MAX_MANIFESTS="${ES_MAX_MANIFESTS:-200}"
ES_MANIFEST_DEPTH="${ES_MANIFEST_DEPTH:-3}"
ES_MANIFEST_ROOTS="${ES_MANIFEST_ROOTS:-}"      # space-separated; default below
ES_PROBE_TIMEOUT="${ES_PROBE_TIMEOUT:-5}"

ES_TMP=$(mktemp -d /tmp/endpointsweep.XXXXXX) || exit 2
trap 'rm -rf "$ES_TMP"' EXIT
trap 'rm -rf "$ES_TMP"; exit 2' HUP INT TERM

F_CONFIGS="$ES_TMP/configs"
F_TOOLS="$ES_TMP/tools"
F_RUNTIMES="$ES_TMP/runtimes"
F_EXTS="$ES_TMP/exts"
F_MANIFESTS="$ES_TMP/manifests"
F_ENVKEYS="$ES_TMP/envkeys"
F_ERRORS="$ES_TMP/errors"
F_CMDINDEX="$ES_TMP/cmdindex"
: > "$F_CONFIGS"; : > "$F_TOOLS"; : > "$F_RUNTIMES"; : > "$F_EXTS"
: > "$F_MANIFESTS"; : > "$F_ENVKEYS"; : > "$F_ERRORS"; : > "$F_CMDINDEX"

FINDINGS=0
MAXSEV_RANK=0
MAXSEV="NONE"

# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

# Escape stdin into a JSON string body (newlines become \n).
jesc() {
	sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' |
		tr -d '\000-\010\013\014\016-\037\177' |
		awk 'BEGIN { ORS = "" } { print sep $0; sep = "\\n" }'
}

# jstr VALUE -> "escaped value"
jstr() {
	printf '"%s"' "$(printf '%s' "$1" | jesc)"
}

# jrow FILE JSON_TEXT  — append one array element, comma-separated.
jrow() {
	if [ -s "$1" ]; then printf ',\n' >> "$1"; fi
	printf '%s' "$2" >> "$1"
}

add_error() {
	jrow "$F_ERRORS" "$(printf '{"scope":%s,"message":%s}' "$(jstr "$1")" "$(jstr "$2")")"
}

# note_finding SEVERITY — collector-side triage only. The analyzer is the
# authority on findings; this exists so EDR consoles get an exit code.
note_finding() {
	FINDINGS=$((FINDINGS + 1))
	nf_rank=0
	case "$1" in
	CRITICAL) nf_rank=4 ;;
	HIGH) nf_rank=3 ;;
	MEDIUM) nf_rank=2 ;;
	LOW) nf_rank=1 ;;
	esac
	if [ "$nf_rank" -gt "$MAXSEV_RANK" ]; then
		MAXSEV_RANK=$nf_rank
		MAXSEV="$1"
	fi
}

# ---------------------------------------------------------------------------
# JSONC -> JSON normaliser + secret redactor (shared with the Linux collector)
# ---------------------------------------------------------------------------

REDACT_AWK="$ES_TMP/redact.awk"
cat > "$REDACT_AWK" <<'AWKEOF'
# Reads a JSON/JSONC document; writes strict JSON with every value under an
# env/headers/credential-shaped key replaced by "[redacted]". Exits non-zero if
# the document does not parse, so the caller never embeds a broken fragment.
function keyshape(k,   lk) {
	lk = tolower(k)
	if (lk ~ /api[_-]?key|access[_-]?key|secret|token|password|passwd|credential|private[_-]?key|bearer|session[_-]?key|auth/) return 1
	if (lk ~ /_key$/ || lk == "key" || lk ~ /_pat$/ || lk == "pat") return 1
	return 0
}
function envctx(k,   lk) {
	lk = tolower(k)
	return (lk == "env" || lk == "envvars" || lk == "environment" || lk == "environmentvariables" || lk == "secrets" || lk == "headers")
}
function redacted_here() {
	return (envctx(keystack[depth]) || keyshape(curkey[depth]))
}
# Index of the next significant character at or after p (skips space+comments).
function nextsig(p,   ch, nx) {
	while (p <= n) {
		ch = substr(doc, p, 1)
		if (ch == " " || ch == "\t" || ch == "\r" || ch == "\n") { p++; continue }
		if (ch == "/") {
			nx = substr(doc, p + 1, 1)
			if (nx == "/") { while (p <= n && substr(doc, p, 1) != "\n") p++; continue }
			if (nx == "*") { p += 2; while (p <= n && substr(doc, p, 2) != "*/") p++; p += 2; continue }
		}
		return p
	}
	return 0
}
{ doc = doc $0 "\n" }
END {
	n = length(doc); i = 1; depth = 0; awaiting = 0; out = ""
	while (i <= n) {
		c = substr(doc, i, 1)
		if (c == "/") {
			nx = substr(doc, i + 1, 1)
			if (nx == "/") { while (i <= n && substr(doc, i, 1) != "\n") i++; continue }
			if (nx == "*") { i += 2; while (i <= n && substr(doc, i, 2) != "*/") i++; i += 2; continue }
		}
		if (c == "\"") {
			j = i + 1; s = "\""
			closed = 0
			while (j <= n) {
				ch = substr(doc, j, 1)
				if (ch == "\\") { s = s ch substr(doc, j + 1, 1); j += 2; continue }
				s = s ch
				j++
				if (ch == "\"") { closed = 1; break }
			}
			if (!closed) { exit 3 }
			if (awaiting == 1) {
				out = out (redacted_here() ? "\"[redacted]\"" : s)
				awaiting = 0
			} else if (isobj[depth] == 1) {
				curkey[depth] = substr(s, 2, length(s) - 2)
				out = out s
			} else {
				# array element: a value, judged by the key that opened the array
				out = out ((envctx(keystack[depth]) || keyshape(keystack[depth])) ? "\"[redacted]\"" : s)
			}
			i = j; continue
		}
		if (c == ":") { awaiting = 1; out = out c; i++; continue }
		if (c == ",") {
			p = nextsig(i + 1)
			nc = (p > 0) ? substr(doc, p, 1) : ""
			if (nc != "}" && nc != "]") out = out c     # drop trailing commas
			awaiting = 0; i++; continue
		}
		if (c == "{" || c == "[") {
			depth++
			keystack[depth] = curkey[depth - 1]
			curkey[depth] = ""
			isobj[depth] = (c == "{") ? 1 : 0
			awaiting = 0; out = out c; i++; continue
		}
		if (c == "}" || c == "]") {
			depth--
			if (depth < 0) { exit 3 }
			awaiting = 0; out = out c; i++; continue
		}
		if (awaiting == 1 && c ~ /[-0-9tfn]/) {
			j = i; tok = ""
			while (j <= n) {
				ch = substr(doc, j, 1)
				if (ch == " " || ch == "\t" || ch == "\r" || ch == "\n" || ch == "," || ch == "]" || ch == "}") break
				tok = tok ch; j++
			}
			out = out (redacted_here() ? "\"[redacted]\"" : tok)
			awaiting = 0; i = j; continue
		}
		out = out c; i++
	}
	if (depth != 0) { exit 3 }
	printf "%s", out
}
AWKEOF

# ---------------------------------------------------------------------------
# Host facts
# ---------------------------------------------------------------------------

HOSTNAME_V=$(hostname 2>/dev/null || uname -n 2>/dev/null || printf 'unknown')
OS_VERSION=$(sw_vers -productVersion 2>/dev/null || printf '')
ARCH=$(uname -m 2>/dev/null || printf '')
COLLECTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf '')
UID_V=$(id -u 2>/dev/null || printf '')
ELEVATED=false
[ "$UID_V" = "0" ] && ELEVATED=true

# Home directories to scan: every real user when root, otherwise just ours.
USER_HOMES=""
if [ "$UID_V" = "0" ]; then
	for uh in /Users/*; do
		[ -d "$uh" ] || continue
		case "$uh" in
		/Users/Shared | /Users/Guest | /Users/.*) continue ;;
		esac
		[ -d "$uh/Library" ] || [ -f "$uh/.zshrc" ] || [ -f "$uh/.bashrc" ] || continue
		USER_HOMES="$USER_HOMES $uh"
	done
	# Root's own configuration counts too, and it is the elevated scope.
	[ -d /var/root ] && USER_HOMES="$USER_HOMES /var/root"
else
	USER_HOMES="${HOME:-}"
fi
[ -n "$USER_HOMES" ] || USER_HOMES="${HOME:-/tmp}"

USERS_SCANNED=""
for uh in $USER_HOMES; do
	un=$(basename "$uh")
	[ "$uh" = "/var/root" ] && un="root"
	if [ -z "$USERS_SCANNED" ]; then USERS_SCANNED="$un"; else USERS_SCANNED="$USERS_SCANNED $un"; fi
done

# ---------------------------------------------------------------------------
# Safety: never execute a binary that a normal user can rewrite, as root.
# ---------------------------------------------------------------------------

safe_to_exec() {
	ste_path="$1"
	[ -x "$ste_path" ] || return 1
	[ "$ES_VERSION_PROBE" = "1" ] || return 1
	if [ "$UID_V" = "0" ]; then
		case "$ste_path" in
		/Users/* | /home/* | /tmp/* | /private/tmp/* | /var/tmp/* | /var/folders/*) return 1 ;;
		esac
		ste_mode=$(stat -f '%Lp' "$ste_path" 2>/dev/null || printf '')
		case "$ste_mode" in
		*[2367]) return 1 ;;
		esac
		ste_owner=$(stat -f '%Su' "$ste_path" 2>/dev/null || printf 'root')
		[ "$ste_owner" = "root" ] || return 1
	fi
	return 0
}

# probe_version BINARY — bounded `--version`, never blocks the fleet script.
probe_version() {
	pv_bin="$1"
	safe_to_exec "$pv_bin" || return 0
	: > "$ES_TMP/ver"
	"$pv_bin" --version < /dev/null > "$ES_TMP/ver" 2>/dev/null &
	pv_pid=$!
	pv_waited=0
	pv_limit=$((ES_PROBE_TIMEOUT * 10))
	while [ "$pv_waited" -lt "$pv_limit" ]; do
		kill -0 "$pv_pid" 2>/dev/null || break
		sleep 0.1
		pv_waited=$((pv_waited + 1))
	done
	if kill -0 "$pv_pid" 2>/dev/null; then
		kill -9 "$pv_pid" 2>/dev/null
		add_error "version_probe" "$pv_bin --version timed out after ${ES_PROBE_TIMEOUT}s"
	fi
	wait "$pv_pid" 2>/dev/null
	head -n 1 "$ES_TMP/ver" 2>/dev/null | tr -d '\r' | cut -c1-80
}

# ---------------------------------------------------------------------------
# MCP client configs
# ---------------------------------------------------------------------------

# triage_config REDACTED_JSON — cheap local severity signal, analyzer decides.
triage_config() {
	tc_file="$1"
	if grep -Eq '"command"[[:space:]]*:[[:space:]]*"([^"]*/)?(sh|bash|zsh|dash|cmd|cmd\.exe|powershell|pwsh|osascript)"' "$tc_file" 2>/dev/null; then
		note_finding HIGH
	fi
	if grep -Eq '(@latest"|"-y"|"--yes")' "$tc_file" 2>/dev/null; then
		note_finding HIGH
	fi
	if grep -Eqi '"[A-Za-z0-9_]*(api_?key|token|secret|password|credential)[A-Za-z0-9_]*"[[:space:]]*:' "$tc_file" 2>/dev/null; then
		note_finding HIGH
	fi
	if grep -Eq '"(/|~|/Users|/home)"' "$tc_file" 2>/dev/null; then
		note_finding HIGH
	fi
}

emit_config() {
	ec_client="$1"
	ec_path="$2"
	ec_user="$3"
	[ -f "$ec_path" ] || return 0
	[ -r "$ec_path" ] || {
		add_error "config" "$ec_path not readable"
		return 0
	}
	ec_size=$(wc -c < "$ec_path" 2>/dev/null | tr -d ' ')
	[ -n "$ec_size" ] || ec_size=0
	if [ "$ec_size" -gt "$ES_MAX_CONFIG_BYTES" ]; then
		add_error "config" "$ec_path skipped: $ec_size bytes exceeds ES_MAX_CONFIG_BYTES"
		return 0
	fi
	ec_elevated=false
	case "$ec_path" in
	/Library/* | /etc/* | /var/root/* | /opt/*) ec_elevated=true ;;
	esac

	if awk -f "$REDACT_AWK" "$ec_path" > "$ES_TMP/raw.json" 2>/dev/null && [ -s "$ES_TMP/raw.json" ]; then
		triage_config "$ES_TMP/raw.json"
		grep -Eo '"command"[[:space:]]*:[[:space:]]*"[^"]*"' "$ES_TMP/raw.json" 2>/dev/null |
			sed -e 's/.*:[[:space:]]*"//' -e 's/"$//' >> "$F_CMDINDEX"
		jrow "$F_CONFIGS" "$(
			printf '{"client":%s,"path":%s,"user":%s,"elevated_scope":%s,"bytes":%s,"raw":' \
				"$(jstr "$ec_client")" "$(jstr "$ec_path")" "$(jstr "$ec_user")" "$ec_elevated" "$ec_size"
			cat "$ES_TMP/raw.json"
			printf '}'
		)"
	else
		add_error "config" "$ec_path present but not parseable as JSON; recorded as present only"
		jrow "$F_CONFIGS" "$(printf '{"client":%s,"path":%s,"user":%s,"elevated_scope":%s,"bytes":%s,"parse_error":true,"raw":null}' \
			"$(jstr "$ec_client")" "$(jstr "$ec_path")" "$(jstr "$ec_user")" "$ec_elevated" "$ec_size")"
	fi
}

scan_user_configs() {
	suc_home="$1"
	suc_user="$2"
	suc_as="$suc_home/Library/Application Support"

	emit_config claude_desktop "$suc_as/Claude/claude_desktop_config.json" "$suc_user"
	emit_config claude_code "$suc_home/.claude.json" "$suc_user"
	emit_config claude_code "$suc_home/.claude/settings.json" "$suc_user"
	emit_config claude_code "$suc_home/.claude/settings.local.json" "$suc_user"
	emit_config cursor "$suc_home/.cursor/mcp.json" "$suc_user"
	emit_config windsurf "$suc_home/.codeium/windsurf/mcp_config.json" "$suc_user"
	emit_config vscode "$suc_as/Code/User/mcp.json" "$suc_user"
	emit_config vscode "$suc_as/Code/User/settings.json" "$suc_user"
	emit_config vscode "$suc_as/Code - Insiders/User/mcp.json" "$suc_user"
	emit_config cline "$suc_as/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" "$suc_user"
	emit_config cline "$suc_as/Cursor/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" "$suc_user"
	emit_config continue "$suc_home/.continue/config.json" "$suc_user"

	# JetBrains keeps MCP settings in XML; record presence without parsing.
	for jb in "$suc_as"/JetBrains/*/options/mcp*.xml; do
		[ -f "$jb" ] || continue
		jrow "$F_CONFIGS" "$(printf '{"client":"jetbrains","path":%s,"user":%s,"elevated_scope":false,"format":"xml","raw":null}' \
			"$(jstr "$jb")" "$(jstr "$suc_user")")"
	done

	# Generic long tail: ~/.config/**/mcp*.json and per-project .mcp.json.
	for gen in $(find "$suc_home/.config" -maxdepth 3 -type f -name 'mcp*.json' 2>/dev/null | head -n 25); do
		emit_config generic "$gen" "$suc_user"
	done
	for proj in $(find "$suc_home" -maxdepth "$ES_MANIFEST_DEPTH" \( -name '.mcp.json' -o -path '*/.cursor/mcp.json' \) -type f 2>/dev/null | head -n 25); do
		emit_config generic "$proj" "$suc_user"
	done
}

# System-wide (elevated) scopes.
emit_config claude_desktop "/Library/Application Support/Claude/claude_desktop_config.json" "root"
emit_config generic "/etc/endpointsweep/mcp.json" "root"

for uh in $USER_HOMES; do
	un=$(basename "$uh")
	[ "$uh" = "/var/root" ] && un="root"
	scan_user_configs "$uh" "$un"
done

# ---------------------------------------------------------------------------
# Agentic CLI tools
# ---------------------------------------------------------------------------

AGENTIC_BINS="claude cline aider goose codex opencode cursor-agent windsurf amp crush continue gemini copilot q devin gptme sgpt"

emit_tool() {
	et_name="$1"
	et_path="$2"
	et_user="$3"
	et_source="$4"
	et_version=$(probe_version "$et_path")
	jrow "$F_TOOLS" "$(printf '{"name":%s,"path":%s,"version":%s,"user":%s,"source":%s}' \
		"$(jstr "$et_name")" "$(jstr "$et_path")" "$(jstr "${et_version:-}")" \
		"$(jstr "$et_user")" "$(jstr "$et_source")")"
}

SEEN_TOOLS="$ES_TMP/seen_tools"
: > "$SEEN_TOOLS"

for bin in $AGENTIC_BINS; do
	found=$(command -v "$bin" 2>/dev/null || printf '')
	# `command -v` resolves builtins and keywords to their own name, and
	# `continue` is a POSIX shell builtin — matching it unguarded invents an
	# agentic CLI on every host on earth. Only an absolute path counts.
	case "$found" in
	/*) [ -x "$found" ] || found="" ;;
	*) found="" ;;
	esac
	if [ -n "$found" ] && ! grep -Fxq "$found" "$SEEN_TOOLS" 2>/dev/null; then
		printf '%s\n' "$found" >> "$SEEN_TOOLS"
		emit_tool "$bin" "$found" "${USER:-unknown}" path
	fi
done

# Per-user npm/nvm/pipx/bun install locations — invisible to root's PATH.
for uh in $USER_HOMES; do
	un=$(basename "$uh")
	[ "$uh" = "/var/root" ] && un="root"
	for dir in "$uh/.local/bin" "$uh/bin" "$uh/.bun/bin" "$uh/.npm-global/bin" "$uh"/.nvm/versions/node/*/bin "$uh/.volta/bin"; do
		[ -d "$dir" ] || continue
		for bin in $AGENTIC_BINS; do
			cand="$dir/$bin"
			[ -f "$cand" ] || continue
			grep -Fxq "$cand" "$SEEN_TOOLS" 2>/dev/null && continue
			printf '%s\n' "$cand" >> "$SEEN_TOOLS"
			emit_tool "$bin" "$cand" "$un" package_manager
		done
	done
done

# GUI clients ship as app bundles, not binaries on PATH.
for app in "/Applications/Claude.app" "/Applications/Cursor.app" "/Applications/Windsurf.app" "/Applications/ChatGPT.app" "/Applications/Ollama.app"; do
	[ -d "$app" ] || continue
	app_name=$(basename "$app" .app)
	app_ver=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist" 2>/dev/null || printf '')
	jrow "$F_TOOLS" "$(printf '{"name":%s,"path":%s,"version":%s,"user":"","source":"app_bundle"}' \
		"$(jstr "$app_name")" "$(jstr "$app")" "$(jstr "$app_ver")")"
done

# ---------------------------------------------------------------------------
# Local model runtimes
# ---------------------------------------------------------------------------

listen_addrs_for() {
	# Listening TCP endpoints for a process name, as a JSON array.
	la_proc="$1"
	la_out=""
	for addr in $(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk -v p="$la_proc" 'tolower($1) ~ tolower(p) { print $9 }' | sed 's/.*->//' | sort -u); do
		if [ -z "$la_out" ]; then la_out="$(jstr "$addr")"; else la_out="$la_out,$(jstr "$addr")"; fi
	done
	printf '[%s]' "$la_out"
}

models_for_ollama() {
	mfo_out=""
	for home in $USER_HOMES /usr/share/ollama; do
		mdir="$home/.ollama/models/manifests"
		[ -d "$mdir" ] || continue
		# Model identity is the manifest path; no model file is ever opened.
		for mf in $(find "$mdir" -type f 2>/dev/null | head -n 100); do
			name=$(printf '%s' "$mf" | sed -e "s|$mdir/||" -e 's|^registry.ollama.ai/||' -e 's|^library/||' -e 's|/\([^/]*\)$|:\1|')
			if [ -z "$mfo_out" ]; then mfo_out="$(jstr "$name")"; else mfo_out="$mfo_out,$(jstr "$name")"; fi
		done
	done
	printf '[%s]' "$mfo_out"
}

emit_runtime() {
	er_name="$1"
	er_installed="$2"
	er_running="$3"
	er_addrs="$4"
	er_models="$5"
	er_version="$6"
	jrow "$F_RUNTIMES" "$(printf '{"name":%s,"installed":%s,"running":%s,"listen_addrs":%s,"models":%s,"version":%s}' \
		"$(jstr "$er_name")" "$er_installed" "$er_running" "$er_addrs" "$er_models" "$(jstr "$er_version")")"
}

OLLAMA_BIN=$(command -v ollama 2>/dev/null || printf '')
OLLAMA_INSTALLED=false
[ -n "$OLLAMA_BIN" ] && OLLAMA_INSTALLED=true
[ -d "/Applications/Ollama.app" ] && OLLAMA_INSTALLED=true
if [ "$OLLAMA_INSTALLED" = "true" ]; then
	OLLAMA_RUNNING=false
	pgrep -x ollama > /dev/null 2>&1 && OLLAMA_RUNNING=true
	OLLAMA_ADDRS=$(listen_addrs_for ollama)
	case "$OLLAMA_ADDRS" in
	*'0.0.0.0'* | *'*:'*) note_finding LOW ;;
	esac
	emit_runtime ollama true "$OLLAMA_RUNNING" "$OLLAMA_ADDRS" "$(models_for_ollama)" "$(probe_version "${OLLAMA_BIN:-/usr/local/bin/ollama}")"
fi

for lb in llama-server llama-cli localai lmstudio vllm; do
	lb_path=$(command -v "$lb" 2>/dev/null || printf '')
	[ -n "$lb_path" ] || continue
	lb_running=false
	pgrep -x "$lb" > /dev/null 2>&1 && lb_running=true
	emit_runtime "$lb" true "$lb_running" "$(listen_addrs_for "$lb")" '[]' "$(probe_version "$lb_path")"
done
[ -d "$HOME/.lmstudio" ] && emit_runtime lmstudio true false '[]' '[]' ''

# ---------------------------------------------------------------------------
# IDE AI extensions
# ---------------------------------------------------------------------------

AI_EXT_PATTERN='continue|cline|claude-dev|copilot|codeium|windsurf|tabnine|sourcegraph.cody|amazonwebservices.amazon-q|augment|supermaven|twinny|geminicodeassist|roo-cline|kilocode|aider|sweep|codegpt|blackbox'

for uh in $USER_HOMES; do
	un=$(basename "$uh")
	[ "$uh" = "/var/root" ] && un="root"
	for extroot in "$uh/.vscode/extensions" "$uh/.vscode-insiders/extensions" "$uh/.cursor/extensions" "$uh/.windsurf/extensions" "$uh/.vscodium/extensions"; do
		[ -d "$extroot" ] || continue
		ide=$(basename "$(dirname "$extroot")" | sed 's/^\.//')
		ext_count=0
		# Glob rather than `ls | grep`: extension directory names can contain
		# spaces, which word-splitting would tear apart.
		for extpath in "$extroot"/*; do
			[ -d "$extpath" ] || continue
			[ "$ext_count" -lt 60 ] || break
			ext=$(basename "$extpath")
			printf '%s' "$ext" | grep -Eqi "$AI_EXT_PATTERN" || continue
			ext_count=$((ext_count + 1))
			ext_id=$(printf '%s' "$ext" | sed -E 's/-[0-9]+\.[0-9]+\.[0-9]+.*$//')
			ext_ver=$(printf '%s' "$ext" | sed -nE 's/.*-([0-9]+\.[0-9]+\.[0-9]+.*)$/\1/p')
			jrow "$F_EXTS" "$(printf '{"ide":%s,"extension_id":%s,"version":%s,"user":%s,"path":%s}' \
				"$(jstr "$ide")" "$(jstr "$ext_id")" "$(jstr "$ext_ver")" "$(jstr "$un")" "$(jstr "$extroot/$ext")")"
		done
	done
	for jbplug in "$uh/Library/Application Support/JetBrains"/*/plugins/*; do
		[ -d "$jbplug" ] || continue
		pname=$(basename "$jbplug")
		printf '%s' "$pname" | grep -Eqi "$AI_EXT_PATTERN|aiassistant|junie" || continue
		jrow "$F_EXTS" "$(printf '{"ide":"jetbrains","extension_id":%s,"version":"","user":%s,"path":%s}' \
			"$(jstr "$pname")" "$(jstr "$un")" "$(jstr "$jbplug")")"
	done
done

# ---------------------------------------------------------------------------
# AI SDK manifests (best-effort; ES_SCAN_MANIFESTS=0 disables)
# ---------------------------------------------------------------------------

AI_PKG_PATTERN='openai|anthropic|langchain|llama-?index|@modelcontextprotocol|mcp|ollama|cohere|mistralai|google-generativeai|@google/generative-ai|transformers|litellm|instructor|semantic-kernel|autogen|crewai|haystack-ai|vercel/ai|@ai-sdk'

if [ "$ES_SCAN_MANIFESTS" = "1" ]; then
	MANIFEST_COUNT=0
	for uh in $USER_HOMES; do
		un=$(basename "$uh")
		[ "$uh" = "/var/root" ] && un="root"
		roots="$ES_MANIFEST_ROOTS"
		[ -n "$roots" ] || roots="$uh/Projects $uh/projects $uh/src $uh/code $uh/dev $uh/work $uh/repos $uh/git $uh/Developer $uh/Documents/GitHub"
		for root in $roots; do
			[ -d "$root" ] || continue
			for mf in $(find "$root" -maxdepth "$ES_MANIFEST_DEPTH" -type f \( -name package.json -o -name requirements.txt -o -name pyproject.toml -o -name Pipfile \) 2>/dev/null | grep -v '/node_modules/' | head -n 40); do
				[ "$MANIFEST_COUNT" -ge "$ES_MAX_MANIFESTS" ] && break 3
				# Dependency NAMES only — never the file body.
				pkgs=$(grep -Eio "[\"']?[@a-z0-9_./-]*($AI_PKG_PATTERN)[@a-z0-9_./-]*[\"']?" "$mf" 2>/dev/null |
					tr -d '"'"'" | sed -E 's/[=<>~^].*$//' | sort -u | head -n 20)
				[ -n "$pkgs" ] || continue
				MANIFEST_COUNT=$((MANIFEST_COUNT + 1))
				eco=npm
				case "$mf" in *requirements.txt | *pyproject.toml | *Pipfile) eco=pypi ;; esac
				pkg_json=""
				for p in $pkgs; do
					if [ -z "$pkg_json" ]; then pkg_json="$(jstr "$p")"; else pkg_json="$pkg_json,$(jstr "$p")"; fi
				done
				jrow "$F_MANIFESTS" "$(printf '{"path":%s,"ecosystem":%s,"user":%s,"ai_packages":[%s]}' \
					"$(jstr "$mf")" "$(jstr "$eco")" "$(jstr "$un")" "$pkg_json")"
			done
		done
	done
fi

# ---------------------------------------------------------------------------
# Credential-shaped variable NAMES (names and paths only — never values)
# ---------------------------------------------------------------------------

KEY_NAME_PATTERN='(API_?KEY|ACCESS_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?|PRIVATE_?KEY|AUTH|BEARER|CLIENT_?SECRET|_PAT|_KEY)'

emit_env_keys() {
	eek_path="$1"
	eek_user="$2"
	eek_kind="$3"
	[ -f "$eek_path" ] && [ -r "$eek_path" ] || return 0
	# Cut at '=' first: a value never reaches the pipeline.
	eek_names=$(sed -E 's/^[[:space:]]*(export[[:space:]]+|set[[:space:]]+-x[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=.*$/\2/;t;d' "$eek_path" 2>/dev/null |
		grep -Ei "$KEY_NAME_PATTERN" | sort -u | head -n 40)
	[ -n "$eek_names" ] || return 0
	eek_json=""
	for n in $eek_names; do
		if [ -z "$eek_json" ]; then eek_json="$(jstr "$n")"; else eek_json="$eek_json,$(jstr "$n")"; fi
	done
	jrow "$F_ENVKEYS" "$(printf '{"path":%s,"var_names":[%s],"user":%s,"kind":%s}' \
		"$(jstr "$eek_path")" "$eek_json" "$(jstr "$eek_user")" "$(jstr "$eek_kind")")"
	note_finding MEDIUM
}

for uh in $USER_HOMES; do
	un=$(basename "$uh")
	[ "$uh" = "/var/root" ] && un="root"
	for rc in .zshrc .zshenv .zprofile .bashrc .bash_profile .profile .kshrc; do
		emit_env_keys "$uh/$rc" "$un" shell_rc
	done
	roots="$ES_MANIFEST_ROOTS"
	[ -n "$roots" ] || roots="$uh/Projects $uh/src $uh/code $uh/dev $uh/work $uh/repos"
	for root in $roots; do
		[ -d "$root" ] || continue
		for dotenv in $(find "$root" -maxdepth "$ES_MANIFEST_DEPTH" -type f -name '.env*' 2>/dev/null | grep -v '/node_modules/' | head -n 20); do
			emit_env_keys "$dotenv" "$un" dotenv
		done
	done
done

# ---------------------------------------------------------------------------
# Command index: resolved path + mode for each command seen in a config
# ---------------------------------------------------------------------------

CMDINDEX_JSON=""
for cmd in $(sort -u "$F_CMDINDEX" 2>/dev/null | head -n 60); do
	case "$cmd" in
	/*) cpath="$cmd" ;;
	*) cpath=$(command -v "$cmd" 2>/dev/null || printf '') ;;
	esac
	[ -n "$cpath" ] || continue
	[ -e "$cpath" ] || continue
	cmode=$(stat -f '%Lp' "$cpath" 2>/dev/null || printf '')
	entry=$(printf '%s:{"path":%s,"mode":%s}' "$(jstr "$cmd")" "$(jstr "$cpath")" "$(jstr "$cmode")")
	if [ -z "$CMDINDEX_JSON" ]; then CMDINDEX_JSON="$entry"; else CMDINDEX_JSON="$CMDINDEX_JSON,$entry"; fi
	case "$cpath" in
	/tmp/* | /private/tmp/* | /var/tmp/* | /Users/Shared/*) note_finding HIGH ;;
	esac
done

# ---------------------------------------------------------------------------
# Assemble the document
# ---------------------------------------------------------------------------

USERS_JSON=""
for un in $USERS_SCANNED; do
	if [ -z "$USERS_JSON" ]; then USERS_JSON="$(jstr "$un")"; else USERS_JSON="$USERS_JSON,$(jstr "$un")"; fi
done

DOCFILE="$ES_TMP/endpointsweep.json"
{
	printf '{\n'
	printf '  "collector": {"name":"endpointsweep","version":%s,"schema":%s,"platform":%s},\n' \
		"$(jstr "$ES_COLLECTOR_VERSION")" "$(jstr "$ES_SCHEMA_VERSION")" "$(jstr "$ES_OS")"
	printf '  "host": {"hostname":%s,"os":%s,"os_version":%s,"arch":%s,"collected_at":%s,"collector_version":%s,"collector_schema":%s,"collector_uid":%s,"elevated":%s,"users_scanned":[%s],"tags":{}},\n' \
		"$(jstr "$HOSTNAME_V")" "$(jstr "$ES_OS")" "$(jstr "$OS_VERSION")" "$(jstr "$ARCH")" \
		"$(jstr "$COLLECTED_AT")" "$(jstr "$ES_COLLECTOR_VERSION")" "$(jstr "$ES_SCHEMA_VERSION")" \
		"${UID_V:-null}" "$ELEVATED" "$USERS_JSON"
	printf '  "command_index": {%s},\n' "$CMDINDEX_JSON"
	printf '  "client_configs": [\n'; cat "$F_CONFIGS"; printf '\n  ],\n'
	printf '  "agentic_tools": [\n'; cat "$F_TOOLS"; printf '\n  ],\n'
	printf '  "model_runtimes": [\n'; cat "$F_RUNTIMES"; printf '\n  ],\n'
	printf '  "ide_extensions": [\n'; cat "$F_EXTS"; printf '\n  ],\n'
	printf '  "package_manifests": [\n'; cat "$F_MANIFESTS"; printf '\n  ],\n'
	printf '  "env_key_signals": [\n'; cat "$F_ENVKEYS"; printf '\n  ],\n'
	printf '  "errors": [\n'; cat "$F_ERRORS"; printf '\n  ]\n'
	printf '}\n'
} > "$DOCFILE"

SUMMARY="ENDPOINTSWEEP|$HOSTNAME_V|$FINDINGS|$MAXSEV"

if [ -n "$OUTFILE" ]; then
	if cp "$DOCFILE" "$OUTFILE" 2>/dev/null; then
		chmod 600 "$OUTFILE" 2>/dev/null
		printf '%s\n' "$SUMMARY"
	else
		printf 'ENDPOINTSWEEP|%s|0|ERROR write failed: %s\n' "$HOSTNAME_V" "$OUTFILE" >&2
		exit 2
	fi
else
	cat "$DOCFILE"
	printf '%s\n' "$SUMMARY" >&2
fi

[ "$FINDINGS" -gt 0 ] && exit 1
exit 0
