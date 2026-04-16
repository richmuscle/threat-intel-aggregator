"""Wazuh forwarder — sends ECS-aligned NDJSON alerts to Wazuh's syslog listener.

Wazuh binds both TCP and UDP port 1514 for remote forwarders. We speak UDP
syslog (RFC 5424) because it's fire-and-forget and Wazuh's JSON decoder
parses the MSG body directly — no decoder changes needed.

Graceful skip: if the Wazuh port isn't reachable (agent down, firewall, wrong
host), the sender logs a warning and returns False. It never raises; the
autoblock pipeline must not fail because the SIEM is offline.
"""
from __future__ import annotations

import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 1514

# syslog PRI = facility * 8 + severity — local0 (16) + warning (4) = 132.
SYSLOG_PRI_LOCAL0_WARNING = (16 << 3) | 4


def _syslog_rfc5424(msg: str, app: str = "threat-intel", hostname: str | None = None) -> bytes:
    """Format `msg` as a single RFC 5424 syslog frame."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    host = hostname or socket.gethostname()
    # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    frame = f"<{SYSLOG_PRI_LOCAL0_WARNING}>1 {ts} {host} {app} - - - {msg}"
    return frame.encode("utf-8")


def _port_reachable(host: str, port: int, timeout: float = 0.5) -> bool:
    """TCP probe on the same port — Wazuh binds both TCP/UDP 1514 by default.

    UDP cannot be health-checked directly (it's connectionless), but Wazuh's
    remote listener on a live manager always has the TCP socket open too, so
    TCP-connect is a reliable proxy for "Wazuh is up."
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def send_ndjson(
    ndjson_path: Path | str,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    probe_port: bool = True,
) -> tuple[int, int]:
    """Send each line of the NDJSON file as one UDP syslog packet.

    Returns (sent, skipped). If the port probe fails, returns (0, 0) after
    logging a warning — does not raise.
    """
    path = Path(ndjson_path)
    if not path.exists():
        logger.warning("wazuh_ndjson_missing", path=str(path))
        return 0, 0

    if probe_port and not _port_reachable(host, port):
        logger.warning(
            "wazuh_port_unreachable",
            host=host,
            port=port,
            message="Wazuh port not reachable — skipping forward",
        )
        return 0, 0

    sent = 0
    skipped = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    # Validate JSON before forwarding — malformed lines are
                    # logged and skipped, never sent to the SIEM.
                    json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    continue
                try:
                    sock.sendto(_syslog_rfc5424(line), (host, port))
                    sent += 1
                except OSError as exc:
                    logger.warning("wazuh_udp_send_failed", error=str(exc))
                    skipped += 1
    finally:
        sock.close()

    logger.info("wazuh_forwarded", path=str(path), sent=sent, skipped=skipped)
    return sent, skipped


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("Usage: wazuh_client.py <ndjson_path> [host] [port]", file=sys.stderr)
        return 2
    ndjson = argv[0]
    host = argv[1] if len(argv) > 1 else DEFAULT_HOST
    port = int(argv[2]) if len(argv) > 2 else DEFAULT_PORT
    sent, skipped = send_ndjson(ndjson, host=host, port=port)
    print(f"wazuh forwarded sent={sent} skipped={skipped} host={host} port={port}")
    # Exit 0 whether or not the port was up — graceful skip is a feature.
    return 0


if __name__ == "__main__":
    sys.exit(main())
