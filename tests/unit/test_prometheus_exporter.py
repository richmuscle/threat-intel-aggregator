"""Prometheus pushgateway exporter — payload shape and graceful skip."""
from __future__ import annotations

import builtins
import socket
from datetime import UTC, datetime
from typing import Any

import pytest

from src.models import (
    AgentResult,
    CorrelatedIntelReport,
    NormalizedThreat,
    Severity,
    SwarmState,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def populated_state() -> SwarmState:
    """A SwarmState with a CVE, an IOC, agent results and a small report."""
    cve = NormalizedThreat(
        threat_type="cve",
        title="CVE-2024-12345 — Critical RCE in ExampleLib",
        description="rce",
        severity=Severity.CRITICAL,
        cve_ids=["CVE-2024-12345"],
        cvss_score=9.8,
    )
    ioc_v4 = NormalizedThreat(
        threat_type="ioc",
        title="Malicious IPv4 1.2.3.4",
        description="abuseipdb confidence 95",
        severity=Severity.HIGH,
        ioc_values=["1.2.3.4"],
    )
    ioc_domain = NormalizedThreat(
        threat_type="ioc",
        title="phish.example.com",
        description="otx pulse 12",
        severity=Severity.MEDIUM,
        ioc_values=["phish.example.com"],
    )
    report = CorrelatedIntelReport(
        report_id="TIA-TEST0001",
        executive_summary="x",
        critical_findings=["one"],
        threat_clusters=[{"cluster_name": "c1", "severity": "CRITICAL", "cve_ids": []}],
        siem_alerts=[
            {"rule_name": "r1", "severity": "CRITICAL"},
            {"rule_name": "r2", "severity": "HIGH"},
        ],
        total_threats_processed=3,
        severity_breakdown={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1},
    )
    return SwarmState(
        run_id="run-1",
        normalized_threats=[cve, ioc_v4, ioc_domain],
        agent_results=[
            AgentResult(
                agent_name="cve_scraper",
                success=True,
                items_fetched=10,
                duration_ms=1234.0,
            ),
            AgentResult(
                agent_name="ioc_extractor",
                success=True,
                items_fetched=5,
                duration_ms=789.5,
            ),
        ],
        report=report,
    )


def _free_port() -> int:
    """A port that's almost-certainly unbound — for refused-connection tests."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


# ── Payload shape via captured handler ────────────────────────────────────────

class _Captured:
    """Captures the most recent push payload so the test can introspect it."""

    def __init__(self) -> None:
        self.url: str | None = None
        self.method: str | None = None
        self.timeout: float | None = None
        self.headers: list[tuple[str, str]] | None = None
        self.body: str = ""

    def handler_factory(self) -> Any:
        captured = self

        def factory(
            url: str,
            method: str,
            timeout: float | None,
            headers: list[tuple[str, str]],
            data: bytes,
        ) -> Any:
            captured.url = url
            captured.method = method
            captured.timeout = timeout
            captured.headers = headers
            captured.body = data.decode("utf-8")

            def _do() -> None:
                return None

            return _do

        return factory


class TestPushPayload:
    """End-to-end: feed a real SwarmState through push_metrics with a captured handler."""

    def test_all_metric_names_present(
        self, populated_state: SwarmState, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = _Captured()
        # Patch the underlying push so we never touch the network.
        from src.integrations import prometheus_exporter as mod

        original = __import__("prometheus_client").push_to_gateway

        def patched_push(
            gateway: str,
            job: str,
            registry: Any,
            grouping_key: dict[str, Any] | None = None,
            timeout: float | None = 30,
            handler: Any = None,
            compression: Any = None,
        ) -> None:
            original(
                gateway,
                job=job,
                registry=registry,
                timeout=timeout,
                handler=captured.handler_factory(),
            )
            return None

        monkeypatch.setattr(
            "prometheus_client.push_to_gateway", patched_push, raising=True
        )

        ok = mod.push_metrics(populated_state, run_duration_seconds=12.5)
        assert ok is True

        body = captured.body
        for name in (
            "threat_intel_run_duration_seconds",
            "threat_intel_iocs_total",
            "threat_intel_cves_total",
            "threat_intel_clusters_total",
            "threat_intel_siem_alerts_total",
            "threat_intel_agent_duration_seconds",
            "threat_intel_agent_records_total",
            "threat_intel_blocked_ips_total",
            "threat_intel_blocked_domains_total",
        ):
            assert name in body, f"missing metric {name} in push body"

    def test_labels_severity_ioc_type_agent(
        self, populated_state: SwarmState, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = _Captured()
        from src.integrations import prometheus_exporter as mod

        original = __import__("prometheus_client").push_to_gateway

        def patched_push(
            gateway: str,
            job: str,
            registry: Any,
            grouping_key: dict[str, Any] | None = None,
            timeout: float | None = 30,
            handler: Any = None,
            compression: Any = None,
        ) -> None:
            original(
                gateway,
                job=job,
                registry=registry,
                timeout=timeout,
                handler=captured.handler_factory(),
            )
            return None

        monkeypatch.setattr(
            "prometheus_client.push_to_gateway", patched_push, raising=True
        )

        mod.push_metrics(populated_state, run_duration_seconds=1.0)
        body = captured.body

        # IOC labels — the ipv4 1.2.3.4 should be classified as ipv4 with HIGH.
        assert 'ioc_type="ipv4"' in body
        assert 'ioc_type="domain"' in body
        assert 'severity="HIGH"' in body
        assert 'severity="MEDIUM"' in body

        # CVE label
        assert 'severity="CRITICAL"' in body

        # Agent labels
        assert 'agent="cve_scraper"' in body
        assert 'agent="ioc_extractor"' in body

        # Job label is set on the URL path component, not on samples.
        assert "/job/threat_intel_aggregator" in (captured.url or "")


# ── Graceful-skip paths ───────────────────────────────────────────────────────

class TestGracefulSkip:
    def test_skip_on_connection_refused(
        self,
        populated_state: SwarmState,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from src.integrations import prometheus_exporter as mod

        # Point at a port that's almost certainly closed.
        bad_url = f"http://127.0.0.1:{_free_port()}"
        monkeypatch.setenv("PUSHGATEWAY_URL", bad_url)

        ok = mod.push_metrics(populated_state, run_duration_seconds=0.1)
        assert ok is False

    def test_skip_when_prometheus_client_missing(
        self,
        populated_state: SwarmState,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from src.integrations import prometheus_exporter as mod

        real_import = builtins.__import__

        def fake_import(
            name: str,
            globals: Any = None,
            locals: Any = None,
            fromlist: Any = (),
            level: int = 0,
        ) -> Any:
            if name.startswith("prometheus_client"):
                raise ImportError("simulated: prometheus_client unavailable")
            return real_import(name, globals, locals, fromlist, level)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        ok = mod.push_metrics(populated_state, run_duration_seconds=0.1)
        assert ok is False


# ── Side-channel probes (nft + /etc/hosts) ────────────────────────────────────

class TestSideChannelProbes:
    def test_blocked_ips_count_zero_when_nft_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.integrations import prometheus_exporter as mod

        monkeypatch.setattr("src.integrations.prometheus_exporter.shutil.which", lambda _: None)
        assert mod._count_blocked_ips() == 0

    def test_blocked_domains_count_zero_when_hosts_unreadable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.integrations import prometheus_exporter as mod

        def boom(*_a: object, **_kw: object) -> Any:
            raise OSError("simulated permission denied")

        monkeypatch.setattr("builtins.open", boom)
        assert mod._count_blocked_domains() == 0


class TestIOCClassifier:
    def test_classify_ipv4(self) -> None:
        from src.integrations.prometheus_exporter import _classify_ioc_value

        assert _classify_ioc_value("8.8.8.8") == "ipv4"

    def test_classify_domain(self) -> None:
        from src.integrations.prometheus_exporter import _classify_ioc_value

        assert _classify_ioc_value("evil.example.com") == "domain"

    def test_classify_url(self) -> None:
        from src.integrations.prometheus_exporter import _classify_ioc_value

        assert _classify_ioc_value("https://example.com/x") == "url"

    def test_classify_sha256(self) -> None:
        from src.integrations.prometheus_exporter import _classify_ioc_value

        h = "0" * 64
        assert _classify_ioc_value(h) == "sha256"

    def test_classify_unknown(self) -> None:
        from src.integrations.prometheus_exporter import _classify_ioc_value

        assert _classify_ioc_value("") == "unknown"


# ── Datetime sanity ───────────────────────────────────────────────────────────

class TestRunMeta:
    def test_runs_with_no_report(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.integrations import prometheus_exporter as mod

        # No report at all — clusters should be 0, siem_alerts metric absent
        # (no labels emitted), still pushes successfully.
        captured = _Captured()
        original = __import__("prometheus_client").push_to_gateway

        def patched_push(
            gateway: str,
            job: str,
            registry: Any,
            grouping_key: dict[str, Any] | None = None,
            timeout: float | None = 30,
            handler: Any = None,
            compression: Any = None,
        ) -> None:
            original(
                gateway,
                job=job,
                registry=registry,
                timeout=timeout,
                handler=captured.handler_factory(),
            )
            return None

        monkeypatch.setattr(
            "prometheus_client.push_to_gateway", patched_push, raising=True
        )

        empty_state = SwarmState(
            run_id="empty-run",
            triggered_at=datetime.now(UTC),
        )
        ok = mod.push_metrics(empty_state, run_duration_seconds=0.5)
        assert ok is True
        assert "threat_intel_clusters_total 0" in captured.body
        assert "threat_intel_run_duration_seconds 0.5" in captured.body
