#!/usr/bin/env bash
# Verify: all IPs from the latest blocklist are present in nftables set,
# and a drop rule referencing the set exists on both input and output chains.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$PROJECT_DIR/output"

TABLE_FAMILY="inet"
TABLE_NAME="filter"
SET_NAME="threat-intel-block"
HOSTS_FILE="/etc/hosts"
HOSTS_TAG="threat-intel-aggregator"

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: verify_blocks.sh must be run as root (sudo) — nft list requires it." >&2
    exit 1
fi

command -v nft >/dev/null || { echo "ERROR: nft not installed" >&2; exit 1; }

# ── Latest blocklist ──────────────────────────────────────────────────────────
latest_blocklist="$(find "$OUTPUT_DIR" -maxdepth 1 -type f -name 'blocklist_*.txt' \
                    -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | awk '{print $2}')"

if [[ -z "$latest_blocklist" ]]; then
    echo "FAIL: no blocklist_*.txt found in $OUTPUT_DIR" >&2
    exit 1
fi

echo "Latest blocklist: $(basename "$latest_blocklist")"

# ── Set members ───────────────────────────────────────────────────────────────
if ! nft list set "$TABLE_FAMILY" "$TABLE_NAME" "$SET_NAME" >/dev/null 2>&1; then
    echo "FAIL: set $TABLE_FAMILY $TABLE_NAME $SET_NAME does not exist" >&2
    exit 1
fi

set_members="$(nft -j list set "$TABLE_FAMILY" "$TABLE_NAME" "$SET_NAME" \
    | python3 -c 'import json,sys
d=json.load(sys.stdin)
for o in d.get("nftables",[]):
    s=o.get("set")
    if s and "elem" in s:
        for e in s["elem"]:
            if isinstance(e,str): print(e)
            elif isinstance(e,dict) and "prefix" in e: print(e["prefix"]["addr"])
' | sort -u)"

set_count="$(echo "$set_members" | grep -c '.' || true)"
echo "Set size:         $set_count"
echo "Currently blocked IPs:"
echo "$set_members" | sed 's/^/  /'

# ── Cross-reference ───────────────────────────────────────────────────────────
expected="$(grep -vE '^\s*(#|$)' "$latest_blocklist" | sort -u)"
expected_count="$(echo "$expected" | grep -c '.' || true)"
missing="$(comm -23 <(echo "$expected") <(echo "$set_members"))"
missing_count="$(echo "$missing" | grep -c '.' || true)"

echo ""
echo "Blocklist size:   $expected_count"
echo "Missing from set: $missing_count"
if [[ $missing_count -gt 0 ]]; then
    echo "$missing" | sed 's/^/  MISSING: /'
fi

# ── Drop rules ────────────────────────────────────────────────────────────────
input_rule=$(nft list chain "$TABLE_FAMILY" "$TABLE_NAME" input  2>/dev/null \
             | grep -c "ip saddr @$SET_NAME" || true)
output_rule=$(nft list chain "$TABLE_FAMILY" "$TABLE_NAME" output 2>/dev/null \
              | grep -c "ip daddr @$SET_NAME" || true)
total_rules=$((input_rule + output_rule))

echo ""
echo "Drop rules:       input=$input_rule output=$output_rule (total=$total_rules)"

# ── /etc/hosts DNS block check ────────────────────────────────────────────────
hosts_tagged=$(grep -cF "# $HOSTS_TAG" "$HOSTS_FILE" 2>/dev/null || true)
hosts_tagged="${hosts_tagged:-0}"
echo ""
echo "DNS sinkhole:"
echo "  /etc/hosts entries tagged '$HOSTS_TAG': $hosts_tagged"
if [[ $hosts_tagged -gt 0 ]]; then
    grep -F "# $HOSTS_TAG" "$HOSTS_FILE" | awk '{print "    "$2}' | head -20
fi

# ── Verdict ───────────────────────────────────────────────────────────────────
if [[ $missing_count -eq 0 && $input_rule -ge 1 && $output_rule -ge 1 && $hosts_tagged -ge 1 ]]; then
    echo ""
    echo "PASS: all $expected_count IPs present; drop rules active on input + output; DNS sinkhole has $hosts_tagged entries."
    exit 0
fi

echo ""
echo "FAIL: blocklist/nftables/hosts state inconsistent."
[[ $hosts_tagged -eq 0 ]] && echo "  - no DNS sinkhole entries found in $HOSTS_FILE"
exit 1
