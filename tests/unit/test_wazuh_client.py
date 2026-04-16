"""Wazuh forwarder — graceful skip and message framing."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from unittest.mock import patch

from src.integrations.wazuh_client import (
    SYSLOG_PRI_LOCAL0_WARNING,
    _port_reachable,
    _syslog_rfc5424,
    send_ndjson,
)


def _free_port() -> int:
    """Return a port that's almost-certainly unbound right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestPortProbe:
    def test_unreachable_returns_false(self) -> None:
        # Bind and immediately close — the port should now refuse connections.
        port = _free_port()
        assert _port_reachable("127.0.0.1", port, timeout=0.2) is False


class TestGracefulSkip:
    def test_send_ndjson_when_port_unreachable(self, tmp_path: Path) -> None:
        ndjson = tmp_path / "alerts.ndjson"
        ndjson.write_text(json.dumps({"rule": {"name": "test"}}) + "\n")
        # Point at a certainly-dead port and confirm no exception escapes.
        sent, skipped = send_ndjson(ndjson, host="127.0.0.1", port=_free_port())
        assert sent == 0
        assert skipped == 0

    def test_missing_file_returns_zero_zero(self, tmp_path: Path) -> None:
        sent, skipped = send_ndjson(tmp_path / "nope.ndjson")
        assert (sent, skipped) == (0, 0)


class TestSyslogFraming:
    def test_pri_is_local0_warning(self) -> None:
        # local0 (16) << 3 | warning (4) == 132
        assert SYSLOG_PRI_LOCAL0_WARNING == 132

    def test_rfc5424_starts_with_pri_version(self) -> None:
        frame = _syslog_rfc5424("hello", app="threat-intel", hostname="host")
        assert frame.startswith(b"<132>1 ")
        assert b" host threat-intel - - - hello" in frame


class TestSendWithFakeListener:
    def test_sends_one_packet_per_line(self, tmp_path: Path) -> None:
        """Stand up a UDP listener on an ephemeral port and verify each
        NDJSON line is delivered as one syslog packet."""
        # Bind a UDP receiver
        recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv.bind(("127.0.0.1", 0))
        recv.settimeout(1.0)
        port = recv.getsockname()[1]

        # send_ndjson probes TCP on the same port — stub the probe out so it
        # doesn't block on a non-existent TCP listener.
        ndjson = tmp_path / "alerts.ndjson"
        payloads = [{"rule": {"name": "r1"}}, {"rule": {"name": "r2"}}]
        ndjson.write_text("\n".join(json.dumps(p) for p in payloads) + "\n")

        with patch("src.integrations.wazuh_client._port_reachable", return_value=True):
            sent, skipped = send_ndjson(ndjson, host="127.0.0.1", port=port)

        assert sent == 2
        assert skipped == 0

        received = []
        for _ in range(2):
            try:
                pkt, _ = recv.recvfrom(65535)
                received.append(pkt)
            except TimeoutError:
                break
        recv.close()
        assert len(received) == 2
        assert all(pkt.startswith(b"<132>1 ") for pkt in received)

    def test_malformed_json_is_skipped(self, tmp_path: Path) -> None:
        ndjson = tmp_path / "alerts.ndjson"
        ndjson.write_text('{"ok": true}\nnot-json\n')
        with patch("src.integrations.wazuh_client._port_reachable", return_value=True):
            # Send to a discard port — we only care about the sent/skipped counts.
            # Use a bound-and-closed port so sendto succeeds locally (UDP drops).
            recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            recv.bind(("127.0.0.1", 0))
            port = recv.getsockname()[1]
            sent, skipped = send_ndjson(ndjson, host="127.0.0.1", port=port)
            recv.close()
        assert sent == 1
        assert skipped == 1
