#!/usr/bin/env bash
# Dispatcher for the threat-intel-aggregator container.
#
# Modes:
#   cli [args...]   → python main.py "$@"   (one-shot runs, cron-style)
#   api             → uvicorn src.api.app:app  (long-running dashboard)
#   dry-run         → python main.py --dry-run  (startup smoke check)
#   shell           → drop to bash for debugging
#
# All modes respect env vars from the running container (compose, k8s Secret,
# docker run --env-file). SecretStr wrapping inside the app ensures keys
# never appear in repr() logs — see src/tools/base_client.py::unwrap_secret.

set -euo pipefail

mode="${1:-api}"
shift || true

case "$mode" in
    cli)
        exec python main.py "$@"
        ;;
    dry-run)
        exec python main.py --dry-run
        ;;
    api)
        # `--proxy-headers` + `--forwarded-allow-ips` let us sit behind an
        # ingress that terminates TLS without losing the client IP in logs.
        exec uvicorn src.api.app:app \
            --host "${API_HOST:-0.0.0.0}" \
            --port "${API_PORT:-8000}" \
            --proxy-headers \
            --forwarded-allow-ips='*' \
            --log-level "${LOG_LEVEL:-info}" \
            "$@"
        ;;
    shell)
        exec bash
        ;;
    *)
        echo "usage: $(basename "$0") {cli|api|dry-run|shell} [args...]" >&2
        exit 2
        ;;
esac
