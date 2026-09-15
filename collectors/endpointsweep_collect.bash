#!/bin/bash
# EndpointSweep collector — Linux
#
# Inventories MCP client configs, agentic CLI tools, local model runtimes, IDE
# AI extensions, AI SDK manifests and credential-shaped variable NAMES.
#
# Deployment contract (see deploy/*.md):
#   endpointsweep_collect.bash [OUTPUT_JSON_PATH]
#     - with an argument : JSON is written to that path, the one-line summary
#                          goes to stdout (EDR/MDM consoles truncate at ~500 chars)
#     - with no argument : JSON goes to stdout, the summary goes to stderr
#   exit 0 = nothing flagged, 1 = something flagged, 2 = the collector failed
#
# Red line: this script reports variable NAMES and file PATHS. It never reads or
# transmits a variable value. Config files are embedded with every value under an
# env/headers/secret-shaped key replaced by "[redacted]" before anything is written.
#
# Depends only on a base Linux system: bash, awk, sed, grep, find, stat,
# getent/passwd, and ss or netstat when present.

set -u
set -o pipefail

ES_COLLECTOR_VERSION="0.1.1"
ES_SCHEMA_VERSION="1"
ES_OS="linux"

OUTFILE="${1:-}"

PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/snap/bin:/opt/bin:${PATH:-}"
export PATH
LC_ALL=C
export LC_ALL
umask 077

ES_SCAN_MANIFESTS="${ES_SCAN_MANIFESTS:-1}"
ES_VERSION_PROBE="${ES_VERSION_PROBE:-1}"
ES_MAX_CONFIG_BYTES="${ES_MAX_CONFIG_BYTES:-262144}"
ES_MAX_MANIFESTS="${ES_MAX_MANIFESTS:-200}"
ES_MANIFEST_DEPTH="${ES_MANIFEST_DEPTH:-3}"
ES_MANIFEST_ROOTS="${ES_MANIFEST_ROOTS:-}"
ES_PROBE_TIMEOUT="${ES_PROBE_TIMEOUT:-5}"

ES_TMP=$(mktemp -d /tmp/endpointsweep.XXXXXX) || exit 2
trap 'rm -rf "$ES_TMP"' EXIT
trap 'rm -rf "$ES_TMP"; exit 2' HUP INT TERM

F_CONFIGS="$ES_TMP/configs"; F_TOOLS="$ES_TMP/tools"; F_RUNTIMES="$ES_TMP/runtimes"
F_EXTS="$ES_TMP/exts"; F_MANIFESTS="$ES_TMP/manifests"; F_ENVKEYS="$ES_TMP/envkeys"
F_ERRORS="$ES_TMP/errors"; F_CMDINDEX="$ES_TMP/cmdindex"
: > "$F_CONFIGS"; : > "$F_TOOLS"; : > "$F_RUNTIMES"; : > "$F_EXTS"
: > "$F_MANIFESTS"; : > "$F_ENVKEYS"; : > "$F_ERRORS"; : > "$F_CMDINDEX"

FINDINGS=0
MAXSEV_RANK=0
MAXSEV="NONE"

# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

jesc() {
	sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' |
		tr -d '\000-\010\013\014\016-\037\177' |
		awk 'BEGIN { ORS = "" } { print sep $0; sep = "\\n" }'
}

jstr() { printf '"%s"' "$(printf '%s' "$1" | jesc)"; }

jrow() {
	[[ -s "$1" ]] && printf ',\n' >> "$1"
	printf '%s' "$2" >> "$1"
}

add_error() {
	jrow "$F_ERRORS" "$(printf '{"scope":%s,"message":%s}' "$(jstr "$1")" "$(jstr "$2")")"
}

note_finding() {
	FINDINGS=$((FINDINGS + 1))
	local rank=0
	case "$1" in
	CRITICAL) rank=4 ;;
	HIGH) rank=3 ;;
	MEDIUM) rank=2 ;;
	LOW) rank=1 ;;
	esac
	if ((rank > MAXSEV_RANK)); then
		MAXSEV_RANK=$rank
		MAXSEV="$1"
	fi
}

# ---------------------------------------------------------------------------
# JSONC -> JSON normaliser + secret redactor (identical to the macOS collector)
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
OS_VERSION=""
if [[ -r /etc/os-release ]]; then
	OS_VERSION=$(awk -F= '/^PRETTY_NAME=/ { gsub(/"/, "", $2); print $2 }' /etc/os-release 2>/dev/null)
fi
[[ -n "$OS_VERSION" ]] || OS_VERSION=$(uname -r 2>/dev/null || printf '')
ARCH=$(uname -m 2>/dev/null || printf '')
COLLECTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf '')
UID_V=$(id -u 2>/dev/null || printf '')
ELEVATED=false
[[ "$UID_V" == "0" ]] && ELEVATED=true

declare -a USER_HOMES=() USER_NAMES=()
if [[ "$UID_V" == "0" ]]; then
	while IFS=: read -r pw_name _ pw_uid _ _ pw_home pw_shell; do
		[[ "$pw_uid" =~ ^[0-9]+$ ]] || continue
		if ((pw_uid != 0 && (pw_uid < 1000 || pw_uid >= 65534))); then continue; fi
		case "$pw_shell" in */nologin | */false | "") continue ;; esac
		[[ -d "$pw_home" ]] || continue
		USER_HOMES+=("$pw_home")
		USER_NAMES+=("$pw_name")
	done < <(getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null)
fi
if ((${#USER_HOMES[@]} == 0)); then
	USER_HOMES=("${HOME:-/tmp}")
	USER_NAMES=("${USER:-$(id -un 2>/dev/null || printf 'unknown')}")
fi

# ---------------------------------------------------------------------------
# Safety: never execute a user-writable binary while running as root.
# ---------------------------------------------------------------------------

safe_to_exec() {
	local path="$1" mode owner
	[[ -x "$path" ]] || return 1
	[[ "$ES_VERSION_PROBE" == "1" ]] || return 1
	if [[ "$UID_V" == "0" ]]; then
		case "$path" in
		/home/* | /root/* | /tmp/* | /var/tmp/* | /dev/shm/*) return 1 ;;
		esac
		mode=$(stat -c '%a' "$path" 2>/dev/null || printf '')
		[[ "$mode" =~ [2367]$ ]] && return 1
		owner=$(stat -c '%U' "$path" 2>/dev/null || printf 'root')
		[[ "$owner" == "root" ]] || return 1
	fi
	return 0
}

probe_version() {
	local bin="$1" out
	safe_to_exec "$bin" || return 0
	if command -v timeout > /dev/null 2>&1; then
		out=$(timeout "$ES_PROBE_TIMEOUT" "$bin" --version < /dev/null 2>/dev/null | head -n 1)
		if [[ -z "$out" ]]; then
			out=$(timeout "$ES_PROBE_TIMEOUT" "$bin" version < /dev/null 2>/dev/null | head -n 1)
		fi
	else
		out=$("$bin" --version < /dev/null 2>/dev/null | head -n 1)
	fi
	printf '%s' "${out:0:80}" | tr -d '\r'
}

# ---------------------------------------------------------------------------
# MCP client configs
# ---------------------------------------------------------------------------

triage_config() {
	local file="$1"
	grep -Eq '"command"[[:space:]]*:[[:space:]]*"([^"]*/)?(sh|bash|zsh|dash|cmd|cmd\.exe|powershell|pwsh)"' "$file" 2>/dev/null && note_finding HIGH
	grep -Eq '(@latest"|"-y"|"--yes")' "$file" 2>/dev/null && note_finding HIGH
	grep -Eqi '"[A-Za-z0-9_]*(api_?key|token|secret|password|credential)[A-Za-z0-9_]*"[[:space:]]*:' "$file" 2>/dev/null && note_finding HIGH
	grep -Eq '"(/|~|/home|/root)"' "$file" 2>/dev/null && note_finding HIGH
	return 0
}

emit_config() {
	local client="$1" path="$2" user="$3" size elevated=false
	[[ -f "$path" ]] || return 0
	[[ -r "$path" ]] || {
		add_error "config" "$path not readable"
		return 0
	}
	size=$(wc -c < "$path" 2>/dev/null | tr -d ' ')
	[[ -n "$size" ]] || size=0
	if ((size > ES_MAX_CONFIG_BYTES)); then
		add_error "config" "$path skipped: $size bytes exceeds ES_MAX_CONFIG_BYTES"
		return 0
	fi
	case "$path" in /etc/* | /opt/* | /usr/* | /root/*) elevated=true ;; esac

	if awk -f "$REDACT_AWK" "$path" > "$ES_TMP/raw.json" 2>/dev/null && [[ -s "$ES_TMP/raw.json" ]]; then
		triage_config "$ES_TMP/raw.json"
		grep -Eo '"command"[[:space:]]*:[[:space:]]*"[^"]*"' "$ES_TMP/raw.json" 2>/dev/null |
			sed -e 's/.*:[[:space:]]*"//' -e 's/"$//' >> "$F_CMDINDEX"
		jrow "$F_CONFIGS" "$(
			printf '{"client":%s,"path":%s,"user":%s,"elevated_scope":%s,"bytes":%s,"raw":' \
				"$(jstr "$client")" "$(jstr "$path")" "$(jstr "$user")" "$elevated" "$size"
			cat "$ES_TMP/raw.json"
			printf '}'
		)"
	else
		add_error "config" "$path present but not parseable as JSON; recorded as present only"
		jrow "$F_CONFIGS" "$(printf '{"client":%s,"path":%s,"user":%s,"elevated_scope":%s,"bytes":%s,"parse_error":true,"raw":null}' \
			"$(jstr "$client")" "$(jstr "$path")" "$(jstr "$user")" "$elevated" "$size")"
	fi
}

scan_user_configs() {
	local home="$1" user="$2" cfg="$1/.config"

	emit_config claude_desktop "$cfg/Claude/claude_desktop_config.json" "$user"
	emit_config claude_code "$home/.claude.json" "$user"
	emit_config claude_code "$home/.claude/settings.json" "$user"
	emit_config claude_code "$home/.claude/settings.local.json" "$user"
	emit_config cursor "$home/.cursor/mcp.json" "$user"
	emit_config windsurf "$home/.codeium/windsurf/mcp_config.json" "$user"
	emit_config vscode "$cfg/Code/User/mcp.json" "$user"
	emit_config vscode "$cfg/Code/User/settings.json" "$user"
	emit_config vscode "$cfg/Code - Insiders/User/mcp.json" "$user"
	emit_config vscode "$cfg/VSCodium/User/settings.json" "$user"
	emit_config cline "$cfg/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" "$user"
	emit_config cline "$cfg/Cursor/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json" "$user"
	emit_config continue "$home/.continue/config.json" "$user"

	local jb
	for jb in "$cfg"/JetBrains/*/options/mcp*.xml; do
		[[ -f "$jb" ]] || continue
		jrow "$F_CONFIGS" "$(printf '{"client":"jetbrains","path":%s,"user":%s,"elevated_scope":false,"format":"xml","raw":null}' \
			"$(jstr "$jb")" "$(jstr "$user")")"
	done

	local gen
	while IFS= read -r gen; do
		[[ -n "$gen" ]] && emit_config generic "$gen" "$user"
	done < <(find "$cfg" -maxdepth 3 -type f -name 'mcp*.json' 2>/dev/null | head -n 25)
	while IFS= read -r gen; do
		[[ -n "$gen" ]] && emit_config generic "$gen" "$user"
	done < <(find "$home" -maxdepth "$ES_MANIFEST_DEPTH" \( -name '.mcp.json' -o -path '*/.cursor/mcp.json' \) -type f 2>/dev/null | head -n 25)
}

emit_config claude_desktop "/etc/claude/claude_desktop_config.json" root
emit_config generic "/etc/endpointsweep/mcp.json" root

for idx in "${!USER_HOMES[@]}"; do
	scan_user_configs "${USER_HOMES[$idx]}" "${USER_NAMES[$idx]}"
done

# ---------------------------------------------------------------------------
# Agentic CLI tools
# ---------------------------------------------------------------------------

AGENTIC_BINS="claude cline aider goose codex opencode cursor-agent windsurf amp crush continue gemini copilot q gptme sgpt"

emit_tool() {
	local name="$1" path="$2" user="$3" source="$4" version
	version=$(probe_version "$path")
	jrow "$F_TOOLS" "$(printf '{"name":%s,"path":%s,"version":%s,"user":%s,"source":%s}' \
		"$(jstr "$name")" "$(jstr "$path")" "$(jstr "${version:-}")" "$(jstr "$user")" "$(jstr "$source")")"
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
	if [[ -n "$found" ]] && ! grep -Fxq "$found" "$SEEN_TOOLS" 2>/dev/null; then
		printf '%s\n' "$found" >> "$SEEN_TOOLS"
		emit_tool "$bin" "$found" "${USER:-unknown}" path
	fi
done

for idx in "${!USER_HOMES[@]}"; do
	home="${USER_HOMES[$idx]}"
	user="${USER_NAMES[$idx]}"
	for dir in "$home/.local/bin" "$home/bin" "$home/.bun/bin" "$home/.npm-global/bin" "$home"/.nvm/versions/node/*/bin "$home/.volta/bin" "$home/.cargo/bin"; do
		[[ -d "$dir" ]] || continue
		for bin in $AGENTIC_BINS; do
			cand="$dir/$bin"
			[[ -f "$cand" ]] || continue
			grep -Fxq "$cand" "$SEEN_TOOLS" 2>/dev/null && continue
			printf '%s\n' "$cand" >> "$SEEN_TOOLS"
			emit_tool "$bin" "$cand" "$user" package_manager
		done
	done
done

# ---------------------------------------------------------------------------
# Local model runtimes
# ---------------------------------------------------------------------------

listen_addrs_for() {
	local proc="$1" out="" addr
	local -a addrs=()
	if command -v ss > /dev/null 2>&1; then
		mapfile -t addrs < <(ss -H -ltnp 2>/dev/null | awk -v p="$proc" 'tolower($0) ~ tolower(p) { print $4 }' | sort -u)
	elif command -v netstat > /dev/null 2>&1; then
		mapfile -t addrs < <(netstat -ltnp 2>/dev/null | awk -v p="$proc" 'tolower($0) ~ tolower(p) { print $4 }' | sort -u)
	fi
	for addr in "${addrs[@]}"; do
		[[ -n "$addr" ]] || continue
		if [[ -z "$out" ]]; then out="$(jstr "$addr")"; else out="$out,$(jstr "$addr")"; fi
	done
	printf '[%s]' "$out"
}

models_for_ollama() {
	local out="" mdir name mf home
	local -a ollama_roots=("${USER_HOMES[@]}" /usr/share/ollama /var/lib/ollama)
	for home in "${ollama_roots[@]}"; do
		mdir="$home/.ollama/models/manifests"
		[[ -d "$mdir" ]] || continue
		while IFS= read -r mf; do
			[[ -n "$mf" ]] || continue
			name="${mf#"$mdir"/}"
			name="${name#registry.ollama.ai/}"
			name="${name#library/}"
			name="${name%/*}:${name##*/}"
			if [[ -z "$out" ]]; then out="$(jstr "$name")"; else out="$out,$(jstr "$name")"; fi
		done < <(find "$mdir" -type f 2>/dev/null | head -n 100)
	done
	printf '[%s]' "$out"
}

emit_runtime() {
	jrow "$F_RUNTIMES" "$(printf '{"name":%s,"installed":%s,"running":%s,"listen_addrs":%s,"models":%s,"version":%s}' \
		"$(jstr "$1")" "$2" "$3" "$4" "$5" "$(jstr "$6")")"
}

OLLAMA_BIN=$(command -v ollama 2>/dev/null || printf '')
if [[ -n "$OLLAMA_BIN" ]] || [[ -d /usr/share/ollama ]] || [[ -f /etc/systemd/system/ollama.service ]]; then
	OLLAMA_RUNNING=false
	pgrep -x ollama > /dev/null 2>&1 && OLLAMA_RUNNING=true
	OLLAMA_ADDRS=$(listen_addrs_for ollama)
	[[ "$OLLAMA_ADDRS" == *'0.0.0.0'* || "$OLLAMA_ADDRS" == *'[::]'* || "$OLLAMA_ADDRS" == *'*:'* ]] && note_finding LOW
	emit_runtime ollama true "$OLLAMA_RUNNING" "$OLLAMA_ADDRS" "$(models_for_ollama)" "$(probe_version "${OLLAMA_BIN:-/usr/local/bin/ollama}")"
fi

for lb in llama-server llama-cli localai vllm text-generation-launcher; do
	lb_path=$(command -v "$lb" 2>/dev/null || printf '')
	[[ -n "$lb_path" ]] || continue
	lb_running=false
	pgrep -x "$lb" > /dev/null 2>&1 && lb_running=true
	emit_runtime "$lb" true "$lb_running" "$(listen_addrs_for "$lb")" '[]' "$(probe_version "$lb_path")"
done

# ---------------------------------------------------------------------------
# IDE AI extensions
# ---------------------------------------------------------------------------

AI_EXT_PATTERN='continue|cline|claude-dev|copilot|codeium|windsurf|tabnine|sourcegraph.cody|amazonwebservices.amazon-q|augment|supermaven|twinny|geminicodeassist|roo-cline|kilocode|aider|codegpt|blackbox'

for idx in "${!USER_HOMES[@]}"; do
	home="${USER_HOMES[$idx]}"
	user="${USER_NAMES[$idx]}"
	for extroot in "$home/.vscode/extensions" "$home/.vscode-insiders/extensions" "$home/.cursor/extensions" "$home/.windsurf/extensions" "$home/.vscode-oss/extensions"; do
		[[ -d "$extroot" ]] || continue
		ide=$(basename "$(dirname "$extroot")")
		ide="${ide#.}"
		ext_count=0
		# Glob rather than `ls | grep`: extension directory names can contain
		# spaces, which word-splitting would tear apart.
		for extpath in "$extroot"/*; do
			[[ -d "$extpath" ]] || continue
			((ext_count < 60)) || break
			ext=$(basename "$extpath")
			grep -Eqi "$AI_EXT_PATTERN" <<< "$ext" || continue
			ext_count=$((ext_count + 1))
			ext_id=$(sed -E 's/-[0-9]+\.[0-9]+\.[0-9]+.*$//' <<< "$ext")
			ext_ver=$(sed -nE 's/.*-([0-9]+\.[0-9]+\.[0-9]+.*)$/\1/p' <<< "$ext")
			jrow "$F_EXTS" "$(printf '{"ide":%s,"extension_id":%s,"version":%s,"user":%s,"path":%s}' \
				"$(jstr "$ide")" "$(jstr "$ext_id")" "$(jstr "$ext_ver")" "$(jstr "$user")" "$(jstr "$extroot/$ext")")"
		done
	done
	for jbplug in "$home/.local/share/JetBrains"/*/*; do
		[[ -d "$jbplug" ]] || continue
		pname=$(basename "$jbplug")
		grep -Eqi "$AI_EXT_PATTERN|aiassistant|junie" <<< "$pname" || continue
		jrow "$F_EXTS" "$(printf '{"ide":"jetbrains","extension_id":%s,"version":"","user":%s,"path":%s}' \
			"$(jstr "$pname")" "$(jstr "$user")" "$(jstr "$jbplug")")"
	done
done

# ---------------------------------------------------------------------------
# AI SDK manifests
# ---------------------------------------------------------------------------

AI_PKG_PATTERN='openai|anthropic|langchain|llama-?index|@modelcontextprotocol|mcp|ollama|cohere|mistralai|google-generativeai|@google/generative-ai|transformers|litellm|instructor|semantic-kernel|autogen|crewai|haystack-ai|vercel/ai|@ai-sdk'

if [[ "$ES_SCAN_MANIFESTS" == "1" ]]; then
	MANIFEST_COUNT=0
	for idx in "${!USER_HOMES[@]}"; do
		home="${USER_HOMES[$idx]}"
		user="${USER_NAMES[$idx]}"
		roots="$ES_MANIFEST_ROOTS"
		[[ -n "$roots" ]] || roots="$home/Projects $home/projects $home/src $home/code $home/dev $home/work $home/repos $home/git"
		for root in $roots; do
			[[ -d "$root" ]] || continue
			while IFS= read -r mf; do
				[[ -n "$mf" ]] || continue
				((MANIFEST_COUNT >= ES_MAX_MANIFESTS)) && break 3
				pkgs=$(grep -Eio "[\"']?[@a-z0-9_./-]*($AI_PKG_PATTERN)[@a-z0-9_./-]*[\"']?" "$mf" 2>/dev/null |
					tr -d '"'"'" | sed -E 's/[=<>~^].*$//' | sort -u | head -n 20)
				[[ -n "$pkgs" ]] || continue
				MANIFEST_COUNT=$((MANIFEST_COUNT + 1))
				eco=npm
				case "$mf" in *requirements.txt | *pyproject.toml | *Pipfile) eco=pypi ;; esac
				pkg_json=""
				for p in $pkgs; do
					if [[ -z "$pkg_json" ]]; then pkg_json="$(jstr "$p")"; else pkg_json="$pkg_json,$(jstr "$p")"; fi
				done
				jrow "$F_MANIFESTS" "$(printf '{"path":%s,"ecosystem":%s,"user":%s,"ai_packages":[%s]}' \
					"$(jstr "$mf")" "$(jstr "$eco")" "$(jstr "$user")" "$pkg_json")"
			done < <(find "$root" -maxdepth "$ES_MANIFEST_DEPTH" -type f \( -name package.json -o -name requirements.txt -o -name pyproject.toml -o -name Pipfile \) 2>/dev/null | grep -v '/node_modules/' | head -n 40)
		done
	done
fi

# ---------------------------------------------------------------------------
# Credential-shaped variable NAMES (names and paths only — never values)
# ---------------------------------------------------------------------------

KEY_NAME_PATTERN='(API_?KEY|ACCESS_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?|PRIVATE_?KEY|AUTH|BEARER|CLIENT_?SECRET|_PAT|_KEY)'

emit_env_keys() {
	local path="$1" user="$2" kind="$3" names json="" n
	[[ -f "$path" && -r "$path" ]] || return 0
	names=$(sed -E 's/^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=.*$/\2/;t;d' "$path" 2>/dev/null |
		grep -Ei "$KEY_NAME_PATTERN" | sort -u | head -n 40)
	[[ -n "$names" ]] || return 0
	for n in $names; do
		if [[ -z "$json" ]]; then json="$(jstr "$n")"; else json="$json,$(jstr "$n")"; fi
	done
	jrow "$F_ENVKEYS" "$(printf '{"path":%s,"var_names":[%s],"user":%s,"kind":%s}' \
		"$(jstr "$path")" "$json" "$(jstr "$user")" "$(jstr "$kind")")"
	note_finding MEDIUM
}

for idx in "${!USER_HOMES[@]}"; do
	home="${USER_HOMES[$idx]}"
	user="${USER_NAMES[$idx]}"
	for rc in .bashrc .bash_profile .profile .zshrc .zshenv .zprofile .kshrc; do
		emit_env_keys "$home/$rc" "$user" shell_rc
	done
	roots="$ES_MANIFEST_ROOTS"
	[[ -n "$roots" ]] || roots="$home/Projects $home/src $home/code $home/dev $home/work $home/repos"
	for root in $roots; do
		[[ -d "$root" ]] || continue
		while IFS= read -r dotenv; do
			[[ -n "$dotenv" ]] && emit_env_keys "$dotenv" "$user" dotenv
		done < <(find "$root" -maxdepth "$ES_MANIFEST_DEPTH" -type f -name '.env*' 2>/dev/null | grep -v '/node_modules/' | head -n 20)
	done
done

# ---------------------------------------------------------------------------
# Command index
# ---------------------------------------------------------------------------

CMDINDEX_JSON=""
while IFS= read -r cmd; do
	[[ -n "$cmd" ]] || continue
	case "$cmd" in
	/*) cpath="$cmd" ;;
	*) cpath=$(command -v "$cmd" 2>/dev/null || printf '') ;;
	esac
	[[ -n "$cpath" && -e "$cpath" ]] || continue
	cmode=$(stat -c '%a' "$cpath" 2>/dev/null || printf '')
	entry=$(printf '%s:{"path":%s,"mode":%s}' "$(jstr "$cmd")" "$(jstr "$cpath")" "$(jstr "$cmode")")
	if [[ -z "$CMDINDEX_JSON" ]]; then CMDINDEX_JSON="$entry"; else CMDINDEX_JSON="$CMDINDEX_JSON,$entry"; fi
	case "$cpath" in /tmp/* | /var/tmp/* | /dev/shm/*) note_finding HIGH ;; esac
done < <(sort -u "$F_CMDINDEX" 2>/dev/null | head -n 60)

# ---------------------------------------------------------------------------
# Assemble
# ---------------------------------------------------------------------------

USERS_JSON=""
for un in "${USER_NAMES[@]}"; do
	if [[ -z "$USERS_JSON" ]]; then USERS_JSON="$(jstr "$un")"; else USERS_JSON="$USERS_JSON,$(jstr "$un")"; fi
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

if [[ -n "$OUTFILE" ]]; then
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

((FINDINGS > 0)) && exit 1
exit 0
