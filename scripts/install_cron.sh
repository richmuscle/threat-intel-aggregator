#!/usr/bin/env bash
# Install a 6-hour cron job that runs the swarm and then auto_block.
# Idempotent: re-running leaves the crontab with exactly one entry.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$PROJECT_DIR/logs"
TAG="# threat-intel-aggregator"

mkdir -p "$LOG_DIR"

# The swarm itself is a user process, but auto_block.sh writes nftables and
# /etc/hosts — it needs sudo. We use the cron entry's `sudo` invocation which
# requires a passwordless sudoers rule (admin sets that once; not our job).
PY="$(command -v python3)"
CMD="cd $PROJECT_DIR && $PY main.py --keywords ransomware phishing c2 authentication-bypass --max-cves 100 >> $LOG_DIR/cron.log 2>&1 && sudo bash $SCRIPT_DIR/auto_block.sh >> $LOG_DIR/cron.log 2>&1"

CRON_LINE="0 */6 * * * $CMD $TAG"

# Snapshot current crontab (empty is fine)
current="$(crontab -l 2>/dev/null || true)"

# Strip any previous entries we own, plus the MAILTO line we manage.
# grep -v without -F so we match the tag at end of line.
filtered="$(printf '%s\n' "$current" | grep -vE "$TAG\$" | grep -vE '^MAILTO="?"?$' || true)"

# Compose: MAILTO empty + one cron entry
new_crontab="$(printf 'MAILTO=""\n%s\n%s\n' "$filtered" "$CRON_LINE")"
# Collapse duplicate blank lines / trailing noise
new_crontab="$(printf '%s\n' "$new_crontab" | awk 'NF || prev; {prev=NF}')"

printf '%s\n' "$new_crontab" | crontab -

echo "Installed cron entry:"
echo "  $CRON_LINE"
echo ""
echo "Current crontab:"
crontab -l
