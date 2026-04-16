#!/usr/bin/env bash
# DNS sinkhole via /etc/hosts. Idempotent — entries are tagged with the
# report_id so we can identify our own lines without stomping on others.
#
# Usage: dns_block.sh [report.json]   (if omitted, uses newest in output/)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# OUTPUT_DIR, HOSTS_FILE and LOG_FILE can be overridden by the environment so
# tests can point the script at a tmp path and skip the root check with
# TEST_MODE=1. Without the override, stale reports in the real `output/` dir
# would leak into test runs and the seed-only assertions would fail.
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_DIR/output}"
HOSTS_FILE="${HOSTS_FILE:-/etc/hosts}"
LOG_FILE="${LOG_FILE:-/var/log/threat-intel-blocks.log}"

# Seed domains — confirmed active infrastructure, always blocked even if the
# latest report lost them. Order is preserved for stable /etc/hosts diffs.
SEED_DOMAINS=(
    monicasue.app.n8n.cloud
    pagepoinnc.app.n8n.cloud
    tti.app.n8n.cloud
    swift-wallat-usdt-send.netlify.app
    send-usdt-09-admin.netlify.app
    get-proton-vpn.com
    vpn-proton-setup.com
    files.catbox.moe
)

if [[ "${EUID}" -ne 0 && "${TEST_MODE:-0}" != "1" ]]; then
    echo "ERROR: dns_block.sh requires root (modifies $HOSTS_FILE). Set TEST_MODE=1 for test fixtures." >&2
    exit 1
fi

# ── Pick report ──────────────────────────────────────────────────────────────
if [[ $# -ge 1 ]]; then
    report="$1"
else
    report="$(find "$OUTPUT_DIR" -maxdepth 1 -type f -name 'TIA-*.json' \
              ! -name '*_iocs.json' -printf '%T@ %p\n' 2>/dev/null \
              | sort -nr | head -1 | awk '{print $2}')"
fi

if [[ -z "${report:-}" || ! -f "$report" ]]; then
    echo "WARN: no report found; using seed domains only" >&2
    report=""
fi

report_stem="$(basename "${report:-no-report}" .json)"
report_id="${report_stem%_*}"          # drop the _YYYYMMDD_HHMMSS suffix
report_id="${report_id%_*}"            # (timestamp is HH*MM*SS, so trim twice)
[[ -z "$report_id" || "$report_id" == "no-report" ]] && report_id="seed-only"

# ── Extract domains (sidecar → threat_clusters fallback → seeds) ─────────────
domains_from_data=""
if [[ -n "$report" ]]; then
    sidecar="${report%.json}_iocs.json"
    if [[ -f "$sidecar" ]]; then
        domains_from_data="$(python3 -c "
import json, sys
d = json.load(open('$sidecar'))
for r in d:
    if r.get('ioc_type') == 'domain' and (r.get('malicious') or r.get('confidence', 0) >= 0.7):
        print(r['value'])
" 2>/dev/null || true)"
    else
        domains_from_data="$(python3 -c "
import json, re
d = json.load(open('$report'))
dom = re.compile(r'^(?=.{1,253}\$)(?!\d+\.\d+\.\d+\.\d+\$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\$')
seen = set()
for c in d.get('threat_clusters', []):
    sev = str(c.get('severity','')).upper()
    if sev not in ('CRITICAL','HIGH'):
        continue
    for tid in c.get('threat_ids', []):
        if dom.match(tid) and tid not in seen:
            seen.add(tid); print(tid)
" 2>/dev/null || true)"
    fi
fi

# Combine: seeds + data, dedup, preserve order
declare -A added_set=()
all_domains=()
for d in "${SEED_DOMAINS[@]}"; do
    [[ -z "${added_set[$d]:-}" ]] && { all_domains+=("$d"); added_set[$d]=1; }
done
while IFS= read -r d; do
    [[ -z "$d" ]] && continue
    d="${d,,}"
    [[ -z "${added_set[$d]:-}" ]] && { all_domains+=("$d"); added_set[$d]=1; }
done <<< "$domains_from_data"

# ── Load existing /etc/hosts entries (tagged and untagged) ───────────────────
declare -A host_present=()
while IFS= read -r line; do
    # skip blanks and comments (but lines with trailing comments are fine)
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    # second field is the hostname
    name="$(awk '{print $2}' <<< "$line")"
    [[ -n "$name" ]] && host_present["${name,,}"]=1
done < "$HOSTS_FILE"

# ── Append missing entries ───────────────────────────────────────────────────
added=0
skipped=0
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
touch "$LOG_FILE"
chmod 0640 "$LOG_FILE" 2>/dev/null || true

for d in "${all_domains[@]}"; do
    if [[ -n "${host_present[$d]:-}" ]]; then
        ((skipped++)) || true
        continue
    fi
    printf '0.0.0.0\t%s\t# threat-intel-aggregator %s\n' "$d" "$report_id" >> "$tmp"
    printf '%s dns_block %s (report=%s)\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$d" "$report_id" >> "$LOG_FILE"
    ((added++)) || true
done

if [[ $added -gt 0 ]]; then
    # Append atomically — cat is simpler than sed -i and avoids mangling
    # symlinks (/etc/hosts is a plain file on Fedora, but be defensive).
    cat "$tmp" >> "$HOSTS_FILE"
fi

echo "Hosts file:     $HOSTS_FILE"
echo "Report:         $(basename "${report:-n/a}")"
echo "Targeted:       ${#all_domains[@]}"
echo "Added:          $added"
echo "Already-present: $skipped"
echo "Log file:       $LOG_FILE"
