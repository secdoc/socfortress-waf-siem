#!/usr/bin/env bash
# SOCFortress WAF -> SIEM feed (cron-safe wrapper).
#
# One pull cycle (run e.g. every 15 min):
#   collector (read-only incremental pull from the WAF management API, JWT auth) ->
#   deliver NEW events to Graylog (GELF/TCP) + the Wazuh WAF localfile.
#
# High-water + txid state means each run ships only new events. Emits one-line JSON
# status to stdout + a log file.
set -u

ENVF="${WAF_SIEM_ENV:-./.env}"          # path to your .env (WAF_*, GRAYLOG_HOST, WAZUH_*)
REPO="$(cd "$(dirname "$0")/.." && pwd)" # repo root
PYBIN="${PYBIN:-/usr/bin/python3}"       # stdlib-only collector; no venv needed
LOG="${WAF_SIEM_LOG:-/var/log/waf-pull.log}"

status() {  # status <ok|error> <message> [extra-json]
  local st="$1" msg="$2" extra="${3:-}"
  local ts; ts=$(date -u +%FT%TZ)
  local line="{\"job\":\"waf-pull\",\"time\":\"$ts\",\"status\":\"$st\",\"message\":\"$msg\"${extra:+,$extra}}"
  echo "$line"; mkdir -p "$(dirname "$LOG")" 2>/dev/null; echo "$line" >> "$LOG" 2>/dev/null
}

[ -f "$ENVF" ] || { status error "env not found: $ENVF"; exit 1; }
[ -x "$PYBIN" ] || PYBIN=$(command -v python3)

# export the env so the collector picks it up (it also reads ./.env by default)
set -a; . "$ENVF"; set +a

OUT=$(cd "$REPO" && "$PYBIN" collector/waf_pipeline.py \
        --graylog-port "${GRAYLOG_WAF_PORT:-12203}" \
        --wazuh-path "${WAZUH_WAF_LOCALFILE:-/var/ossec/logs/waf/events.jsonl}" 2>&1)
RC=$?

COLLECTED=$(printf '%s\n' "$OUT" | grep -oE 'collected [0-9]+' | grep -oE '[0-9]+' | head -1)
DELIV=$(printf '%s\n' "$OUT" | grep -oE 'delivered [0-9]+' | grep -oE '[0-9]+' | head -1)

if [ "$RC" -ne 0 ]; then
  status error "pipeline exited $RC" "\"tail\":\"$(printf '%s' "$OUT" | tail -1 | tr '\"' \' | cut -c1-160)\""
  exit "$RC"
fi
status ok "waf pull complete" "\"collected\":${COLLECTED:-0},\"delivered\":${DELIV:-0}"
