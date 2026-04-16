#!/usr/bin/env bash
# Orchestrator: newest report -> extract_iocs.py -> nftables_block.sh -> Wazuh syslog
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# OUTPUT_DIR is env-overridable for parity with dns_block.sh — lets tests
# and staging runs point at an isolated tmp dir without touching the shared
# `output/` on the host.
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_DIR/output}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: auto_block.sh must be run as root (sudo)." >&2
    exit 1
fi

# ── Pick newest report, excluding blocklist and sidecar files ────────────────
latest="$(find "$OUTPUT_DIR" -maxdepth 1 -type f -name 'TIA-*.json' \
          ! -name '*_iocs.json' -printf '%T@ %p\n' 2>/dev/null \
          | sort -nr | head -1 | awk '{print $2}')"

if [[ -z "$latest" ]]; then
    echo "ERROR: no TIA-*.json reports found in $OUTPUT_DIR" >&2
    exit 1
fi

echo "[auto_block] latest report: $(basename "$latest")"

# ── Extract ───────────────────────────────────────────────────────────────────
extract_out="$(python3 "$SCRIPT_DIR/extract_iocs.py" "$latest")"
extract_rc=$?
echo "$extract_out"
if [[ $extract_rc -ne 0 ]]; then
    echo "ERROR: extract_iocs.py failed (rc=$extract_rc)" >&2
    exit 1
fi

report_stem="$(basename "$latest" .json)"
blocklist="$OUTPUT_DIR/blocklist_${report_stem}.txt"
if [[ ! -s "$blocklist" ]]; then
    echo "ERROR: blocklist is empty or missing: $blocklist" >&2
    exit 1
fi

ip_count="$(wc -l < "$blocklist")"

# ── Block ─────────────────────────────────────────────────────────────────────
block_out="$(bash "$SCRIPT_DIR/nftables_block.sh" "$blocklist")"
block_rc=$?
echo "$block_out"
if [[ $block_rc -ne 0 ]]; then
    echo "ERROR: nftables_block.sh failed (rc=$block_rc)" >&2
    exit 1
fi

added="$(echo "$block_out"   | awk -F: '/^Added:/          {gsub(/ /,"",$2); print $2}')"
skipped="$(echo "$block_out" | awk -F: '/^Already-present:/ {gsub(/ /,"",$2); print $2}')"
set_size="$(echo "$block_out" | awk -F: '/^Set size now:/   {gsub(/ /,"",$2); print $2}')"

# ── DNS blocks ────────────────────────────────────────────────────────────────
dns_out="$(bash "$SCRIPT_DIR/dns_block.sh" "$latest" 2>&1)" || true
echo "$dns_out"
dns_added="$(echo "$dns_out"   | awk -F: '/^Added:/          {gsub(/ /,"",$2); print $2}')"
dns_skipped="$(echo "$dns_out" | awk -F: '/^Already-present:/ {gsub(/ /,"",$2); print $2}')"

# ── Wazuh NDJSON forward (per-alert UDP syslog RFC 5424) ─────────────────────
ndjson="$OUTPUT_DIR/${report_stem}_siem_alerts.ndjson"
wazuh_sent="false"
wazuh_msg="skipped (no ndjson)"
if [[ -f "$ndjson" ]]; then
    if wazuh_out="$(cd "$PROJECT_DIR" && PYTHONPATH="$PROJECT_DIR" .venv/bin/python3 -m src.integrations.wazuh_client "$ndjson" 2>&1)"; then
        wazuh_sent="true"
        wazuh_msg="$(echo "$wazuh_out" | tail -1)"
    else
        wazuh_msg="$(echo "$wazuh_out" | tail -1)"
    fi
    echo "$wazuh_out"
fi

summary="report=${report_stem} ips_extracted=${ip_count} ips_added=${added:-0} ips_already=${skipped:-0} set_size=${set_size:-?} dns_added=${dns_added:-0} dns_already=${dns_skipped:-0} wazuh_sent=${wazuh_sent}"
echo "[auto_block] summary: $summary"

# ── Classic syslog summary line (safety net for minimal Wazuh configs) ───────
logger -p local0.warning -t threat-intel "BLOCKED: ${summary}"
echo "[auto_block] sent summary to syslog (local0.warning tag=threat-intel)"

exit 0
