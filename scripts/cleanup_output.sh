#!/usr/bin/env bash
# Prune old report artifacts from output/, keeping the N newest reports and
# all files that share their report-id prefix (.md, .json, _iocs.json,
# _siem_alerts.ndjson, blocklist_*.txt).
#
# Default is dry-run — prints what would be deleted. Pass --execute to commit.
# Override retention with --keep N (default 10).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$PROJECT_DIR/output"

KEEP=10
EXECUTE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep)    KEEP="$2"; shift 2 ;;
        --execute) EXECUTE=1; shift ;;
        -h|--help)
            echo "Usage: $0 [--keep N] [--execute]"
            echo "  --keep N    Retain the N most recent reports (default: 10)"
            echo "  --execute   Actually delete (default is dry-run)"
            exit 0
            ;;
        *) echo "Unknown flag: $1" >&2; exit 2 ;;
    esac
done

if ! [[ "$KEEP" =~ ^[0-9]+$ ]]; then
    echo "ERROR: --keep must be a non-negative integer" >&2
    exit 2
fi

if [[ ! -d "$OUTPUT_DIR" ]]; then
    echo "Nothing to clean — $OUTPUT_DIR does not exist."
    exit 0
fi

# Collect reports (main .json files, excluding sidecars), newest first.
mapfile -t reports < <(find "$OUTPUT_DIR" -maxdepth 1 -type f -name 'TIA-*.json' \
    ! -name '*_iocs.json' -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk '{print $2}')

total=${#reports[@]}
if [[ $total -le $KEEP ]]; then
    echo "Have $total report(s); keeping up to $KEEP — nothing to prune."
    exit 0
fi

prune_reports=("${reports[@]:$KEEP}")
echo "Found $total reports; keeping newest $KEEP, pruning ${#prune_reports[@]}."
if [[ $EXECUTE -eq 0 ]]; then
    echo "(dry-run — pass --execute to actually delete)"
fi
echo ""

deleted_files=0
for report in "${prune_reports[@]}"; do
    stem="$(basename "$report" .json)"
    report_id="${stem%_*}"          # drop trailing _HHMMSS
    report_id="${report_id%_*}"     # (the timestamp is _DATE_TIME, so twice)
    # Match every artifact that shares this stem.
    mapfile -t siblings < <(find "$OUTPUT_DIR" -maxdepth 1 -type f \
        \( -name "${stem}*" -o -name "blocklist_${stem}.txt" \) 2>/dev/null)
    for f in "${siblings[@]}"; do
        echo "  $([[ $EXECUTE -eq 1 ]] && echo 'DEL' || echo 'would delete') $f"
        if [[ $EXECUTE -eq 1 ]]; then
            rm -f -- "$f"
            ((deleted_files++)) || true
        fi
    done
done

echo ""
if [[ $EXECUTE -eq 1 ]]; then
    echo "Deleted $deleted_files file(s). Retained newest $KEEP reports."
else
    echo "Dry-run complete. Re-run with --execute to delete."
fi
