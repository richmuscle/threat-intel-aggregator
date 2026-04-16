#!/usr/bin/env bash
# Load IPs from a blocklist .txt into nftables set `threat-intel-block`
# Idempotent: safe to re-run. Creates inet filter table/chains/set if missing.
set -euo pipefail

TABLE_FAMILY="inet"
TABLE_NAME="filter"
SET_NAME="threat-intel-block"
LOG_FILE="/var/log/threat-intel-blocks.log"

usage() { echo "Usage: $0 <blocklist.txt>" >&2; exit 2; }

[[ $# -eq 1 ]] || usage
BLOCKLIST="$1"

[[ -f "$BLOCKLIST" ]] || { echo "ERROR: blocklist not found: $BLOCKLIST" >&2; exit 1; }

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: nftables changes require root. Run with sudo." >&2
    exit 1
fi

command -v nft >/dev/null || { echo "ERROR: nft binary not found" >&2; exit 1; }

# ── Ensure table ──────────────────────────────────────────────────────────────
if ! nft list table "$TABLE_FAMILY" "$TABLE_NAME" >/dev/null 2>&1; then
    nft add table "$TABLE_FAMILY" "$TABLE_NAME"
fi

# ── Ensure chains (input + output, filter hook, priority 0) ───────────────────
ensure_chain() {
    local chain="$1"
    if ! nft list chain "$TABLE_FAMILY" "$TABLE_NAME" "$chain" >/dev/null 2>&1; then
        nft "add chain $TABLE_FAMILY $TABLE_NAME $chain { type filter hook $chain priority 0 ; policy accept ; }"
    fi
}
ensure_chain input
ensure_chain output

# ── Ensure set ────────────────────────────────────────────────────────────────
if ! nft list set "$TABLE_FAMILY" "$TABLE_NAME" "$SET_NAME" >/dev/null 2>&1; then
    nft "add set $TABLE_FAMILY $TABLE_NAME $SET_NAME { type ipv4_addr ; flags interval ; }"
fi

# ── Ensure drop rules (one per direction) reference the set ───────────────────
ensure_drop_rule() {
    local chain="$1" dir="$2"
    if ! nft -a list chain "$TABLE_FAMILY" "$TABLE_NAME" "$chain" \
         | grep -q "ip $dir @$SET_NAME"; then
        nft "add rule $TABLE_FAMILY $TABLE_NAME $chain ip $dir @$SET_NAME counter drop"
    fi
}
ensure_drop_rule input  saddr
ensure_drop_rule output daddr

# ── Load IPs ──────────────────────────────────────────────────────────────────
# Snapshot current members (JSON), diff against desired, only add missing.
existing="$(nft -j list set "$TABLE_FAMILY" "$TABLE_NAME" "$SET_NAME" \
            | python3 -c 'import json,sys
d=json.load(sys.stdin)
for o in d.get("nftables",[]):
    s=o.get("set")
    if s and "elem" in s:
        for e in s["elem"]:
            if isinstance(e,str): print(e)
            elif isinstance(e,dict) and "prefix" in e: print(e["prefix"]["addr"])
' || true)"

declare -A present=()
while IFS= read -r ip; do
    [[ -n "$ip" ]] && present["$ip"]=1
done <<< "$existing"

added=0
skipped=0
invalid=0
touch "$LOG_FILE"
chmod 0640 "$LOG_FILE" 2>/dev/null || true

while IFS= read -r ip || [[ -n "$ip" ]]; do
    ip="${ip//[[:space:]]/}"
    [[ -z "$ip" || "$ip" =~ ^# ]] && continue
    if ! [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        ((invalid++)) || true
        continue
    fi
    if [[ -n "${present[$ip]:-}" ]]; then
        ((skipped++)) || true
        continue
    fi
    if nft add element "$TABLE_FAMILY" "$TABLE_NAME" "$SET_NAME" "{ $ip }" 2>/dev/null; then
        printf '%s added %s (source=%s)\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$ip" "$(basename "$BLOCKLIST")" \
            >> "$LOG_FILE"
        ((added++)) || true
    else
        # Race: another run added it between snapshot and insert.
        ((skipped++)) || true
    fi
done < "$BLOCKLIST"

total_in_set="$(nft -j list set "$TABLE_FAMILY" "$TABLE_NAME" "$SET_NAME" \
    | python3 -c 'import json,sys
d=json.load(sys.stdin)
c=0
for o in d.get("nftables",[]):
    s=o.get("set")
    if s and "elem" in s: c+=len(s["elem"])
print(c)')"

echo "Blocklist:      $BLOCKLIST"
echo "Table:          $TABLE_FAMILY $TABLE_NAME set=$SET_NAME"
echo "Added:          $added"
echo "Already-present: $skipped"
echo "Invalid lines:   $invalid"
echo "Set size now:   $total_in_set"
echo "Log file:       $LOG_FILE"
