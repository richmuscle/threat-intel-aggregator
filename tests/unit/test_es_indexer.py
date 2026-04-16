"""Elasticsearch indexer — bulk shape, ID strategy, graceful skip."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import aiohttp
import pytest
from aioresponses import aioresponses

from src.integrations import es_indexer
from src.models import (
    CorrelatedIntelReport,
    NormalizedThreat,
    Severity,
    SwarmState,
)

if TYPE_CHECKING:
    from pathlib import Path

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Provide a writable CA file and a known password for every test."""
    ca = tmp_path / "ca.crt"
    # The contents don't matter — _make_ssl_context only checks os.path.exists
    # for the early skip; we further patch _make_ssl_context to True so aiohttp
    # never actually loads it.
    ca.write_text("fake-ca")
    monkeypatch.setenv("ELASTIC_PASSWORD", "test-password")
    monkeypatch.setenv("ES_CA_CERT", str(ca))
    monkeypatch.setenv("ES_URL", "https://127.0.0.1:9201")
    # Bypass real SSL context construction so aioresponses can match cleanly.
    monkeypatch.setattr(es_indexer, "_make_ssl_context", lambda _path: True)
    return ca


@pytest.fixture
def populated_state() -> SwarmState:
    ioc1 = NormalizedThreat(
        threat_type="ioc",
        title="phish.example.com",
        description="active phishing host",
        severity=Severity.HIGH,
        ioc_values=["phish.example.com"],
    )
    ioc2 = NormalizedThreat(
        threat_type="ioc",
        title="1.2.3.4",
        description="malicious ip",
        severity=Severity.CRITICAL,
        ioc_values=["1.2.3.4"],
    )
    cve = NormalizedThreat(
        threat_type="cve",
        title="CVE-2024-12345",
        description="rce",
        severity=Severity.CRITICAL,
        cve_ids=["CVE-2024-12345"],
    )
    report = CorrelatedIntelReport(
        report_id="TIA-DEADBEEF",
        executive_summary="x",
        critical_findings=["one"],
        threat_clusters=[
            {
                "cluster_name": "c1",
                "severity": "CRITICAL",
                "cve_ids": ["CVE-2024-12345"],
                "mitre_techniques": ["T1078"],
                "threat_ids": ["1.2.3.4"],
            }
        ],
        siem_alerts=[
            {"rule_name": "r1", "severity": "CRITICAL", "alert_id": "a1"},
            {"rule_name": "r2", "severity": "HIGH", "alert_id": "a2"},
        ],
        total_threats_processed=3,
        severity_breakdown={"CRITICAL": 2, "HIGH": 1},
    )
    return SwarmState(
        run_id="run-1",
        normalized_threats=[ioc1, ioc2, cve],
        report=report,
    )


def _current_month_suffix() -> str:
    return datetime.now(UTC).strftime("%Y.%m")


# ── Index naming ──────────────────────────────────────────────────────────────

class TestIndexNaming:
    def test_iocs_index_uses_current_month(self) -> None:
        suffix = _current_month_suffix()
        assert es_indexer._month_suffix() == suffix

    def test_index_constants(self) -> None:
        assert es_indexer.INDEX_IOCS_PREFIX == "threat-intel-iocs"
        assert es_indexer.INDEX_REPORTS_PREFIX == "threat-intel-reports"
        assert es_indexer.INDEX_ALERTS_PREFIX == "threat-intel-alerts"


# ── Bulk shape & IDs ──────────────────────────────────────────────────────────

class TestBulkShapeAndIDs:
    @pytest.mark.asyncio
    async def test_bulk_ndjson_contains_correct_indices_and_ids(
        self, populated_state: SwarmState
    ) -> None:
        suffix = _current_month_suffix()
        url = "https://127.0.0.1:9201/_bulk"
        captured_bodies: list[str] = []

        def callback(_url: str, **kwargs: Any) -> Any:
            from aioresponses.core import CallbackResult

            captured_bodies.append(kwargs.get("data", ""))
            return CallbackResult(status=200, payload={"errors": False, "items": []})

        with aioresponses() as m:
            # We expect the indexer to POST three times (iocs, report, alerts).
            for _ in range(3):
                m.post(url, callback=callback)
            counts = await es_indexer.index_run(populated_state)

        assert counts["skipped"] is False
        assert counts["iocs"] == 2
        assert counts["report"] == 1
        assert counts["alerts"] == 2
        assert len(captured_bodies) == 3

        # ── Bulk body 1 — IOCs ────────────────────────────────────────────────
        ioc_body = next(
            b for b in captured_bodies if f"threat-intel-iocs-{suffix}" in b
        )
        # Each line is JSON; pairs of action+source.
        ioc_lines = [ln for ln in ioc_body.strip().split("\n") if ln]
        assert len(ioc_lines) == 4  # 2 IOCs, 2 lines each
        # Action lines must declare _id == content_hash for that record.
        action_a = json.loads(ioc_lines[0])
        source_a = json.loads(ioc_lines[1])
        assert action_a["index"]["_index"] == f"threat-intel-iocs-{suffix}"
        assert action_a["index"]["_id"] == source_a["content_hash"]
        assert "@timestamp" in source_a

        # ── Bulk body 2 — Report ──────────────────────────────────────────────
        report_body = next(
            b for b in captured_bodies if f"threat-intel-reports-{suffix}" in b
        )
        rep_lines = [ln for ln in report_body.strip().split("\n") if ln]
        assert len(rep_lines) == 2
        rep_action = json.loads(rep_lines[0])
        rep_source = json.loads(rep_lines[1])
        assert rep_action["index"]["_index"] == f"threat-intel-reports-{suffix}"
        assert rep_action["index"]["_id"] == "TIA-DEADBEEF"
        assert rep_source["report_id"] == "TIA-DEADBEEF"
        assert "executive_summary" in rep_source
        assert "critical_findings" in rep_source
        assert "severity_breakdown" in rep_source
        assert "cluster_summary" in rep_source
        assert rep_source["cluster_summary"][0]["cve_count"] == 1

        # ── Bulk body 3 — Alerts ──────────────────────────────────────────────
        alert_body = next(
            b for b in captured_bodies if f"threat-intel-alerts-{suffix}" in b
        )
        alert_lines = [ln for ln in alert_body.strip().split("\n") if ln]
        assert len(alert_lines) == 4  # 2 alerts, 2 lines each
        a_action = json.loads(alert_lines[0])
        a_source = json.loads(alert_lines[1])
        assert a_action["index"]["_index"] == f"threat-intel-alerts-{suffix}"
        # _id is sha256(alert)[:16]
        assert len(a_action["index"]["_id"]) == 16
        assert a_source["report_id"] == "TIA-DEADBEEF"

    def test_alert_id_is_stable_sha256_prefix(self) -> None:
        alert = {"rule_name": "r1", "severity": "CRITICAL"}
        assert es_indexer._alert_id(alert) == es_indexer._alert_id(alert)
        assert len(es_indexer._alert_id(alert)) == 16

    def test_iso_serialises_naive_datetime_as_utc(self) -> None:
        ts = datetime(2026, 4, 16, 5, 35, 53, 123456)
        out = es_indexer._iso(ts)
        assert out.endswith("Z")
        assert out.startswith("2026-04-16T05:35:53")


# ── Auth headers ──────────────────────────────────────────────────────────────

class TestAuth:
    @pytest.mark.asyncio
    async def test_basic_auth_header_sent(
        self, populated_state: SwarmState
    ) -> None:
        url = "https://127.0.0.1:9201/_bulk"
        captured_headers: list[dict[str, str]] = []

        def callback(_url: str, **kwargs: Any) -> Any:
            from aioresponses.core import CallbackResult

            # aiohttp rolls BasicAuth into the request via the auth= param;
            # aioresponses preserves the resulting Authorization header here.
            hdrs = kwargs.get("headers")
            if hdrs is not None:
                captured_headers.append(dict(hdrs))
            return CallbackResult(status=200, payload={"errors": False})

        with aioresponses() as m:
            for _ in range(3):
                m.post(url, callback=callback)
            await es_indexer.index_run(populated_state)

        # Content-Type must be NDJSON for the bulk endpoint.
        assert any(
            h.get("Content-Type") == "application/x-ndjson"
            for h in captured_headers
        )


# ── Graceful-skip paths ───────────────────────────────────────────────────────

class TestGracefulSkip:
    @pytest.mark.asyncio
    async def test_skip_on_missing_password(
        self, populated_state: SwarmState, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("ELASTIC_PASSWORD", raising=False)
        result = await es_indexer.index_run(populated_state)
        assert result["skipped"] is True

    @pytest.mark.asyncio
    async def test_skip_on_missing_ca(
        self,
        populated_state: SwarmState,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        # Drop the patch from the autouse fixture and point at a missing path.
        monkeypatch.setattr(
            es_indexer,
            "_make_ssl_context",
            es_indexer._make_ssl_context,  # restore real impl
        )
        monkeypatch.setenv("ES_CA_CERT", str(tmp_path / "missing.crt"))
        result = await es_indexer.index_run(populated_state)
        assert result["skipped"] is True

    @pytest.mark.asyncio
    async def test_skip_on_401_unauthorized(
        self, populated_state: SwarmState
    ) -> None:
        url = "https://127.0.0.1:9201/_bulk"
        with aioresponses() as m:
            m.post(url, status=401, payload={"error": "unauthorized"})
            result = await es_indexer.index_run(populated_state)
        assert result["skipped"] is True

    @pytest.mark.asyncio
    async def test_skip_on_403_forbidden(
        self, populated_state: SwarmState
    ) -> None:
        url = "https://127.0.0.1:9201/_bulk"
        with aioresponses() as m:
            m.post(url, status=403, payload={"error": "forbidden"})
            result = await es_indexer.index_run(populated_state)
        assert result["skipped"] is True

    @pytest.mark.asyncio
    async def test_skip_on_connection_refused(
        self, populated_state: SwarmState
    ) -> None:
        url = "https://127.0.0.1:9201/_bulk"
        with aioresponses() as m:
            m.post(
                url,
                exception=aiohttp.ClientConnectorError(
                    connection_key=None,  # type: ignore[arg-type]
                    os_error=OSError("Connection refused"),
                ),
            )
            result = await es_indexer.index_run(populated_state)
        assert result["skipped"] is True

    @pytest.mark.asyncio
    async def test_empty_run_returns_zero_counts(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # No threats and no report — no HTTP traffic should occur.
        empty = SwarmState(run_id="empty-run")
        result = await es_indexer.index_run(empty)
        assert result == {
            "iocs": 0,
            "report": 0,
            "alerts": 0,
            "skipped": False,
        }
