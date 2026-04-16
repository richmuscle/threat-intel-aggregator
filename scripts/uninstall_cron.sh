#!/usr/bin/env bash
# Remove the threat-intel cron entry cleanly. No-op if none is installed.
set -euo pipefail

TAG="# threat-intel-aggregator"

current="$(crontab -l 2>/dev/null || true)"
if [[ -z "$current" ]]; then
    echo "No crontab installed — nothing to remove."
    exit 0
fi

filtered="$(printf '%s\n' "$current" | grep -vE "$TAG\$" || true)"
# Drop the MAILTO="" we added if nothing else is left that needs it.
remaining_entries="$(printf '%s\n' "$filtered" | grep -vE '^MAILTO="?"?$' | grep -vE '^\s*$' || true)"
if [[ -z "$remaining_entries" ]]; then
    filtered=""
fi

if [[ -z "$(printf '%s' "$filtered" | tr -d '[:space:]')" ]]; then
    crontab -r 2>/dev/null || true
    echo "Removed threat-intel cron entry (crontab now empty)."
else
    printf '%s\n' "$filtered" | crontab -
    echo "Removed threat-intel cron entry. Remaining crontab:"
    crontab -l
fi
