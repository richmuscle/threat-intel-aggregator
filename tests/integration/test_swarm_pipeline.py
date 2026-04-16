"""
Integration tests — full swarm pipeline with mocked external APIs.
Tests the complete flow: agents → normalize → correlate → report.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models import (
    ATTACKTechnique,
    CVERecord,
    IOCRecord,
    Severity,
    SwarmState,
    ThreatFeedItem,
    ThreatSource,
)

MOCK_CLAUDE_RESPONSE = {
    "content": [
        {
            "type": "tool_use",
            "name": "produce_intel_report",
            "input": {
                "executive_summary": (
                    "The current threat landscape shows active exploitation of critical "
                    "vulnerabilities in widely deployed software. Ransomware actors continue "
                    "to leverage known CVEs. Immediate patching is recommended."
                ),
                "critical_findings": [
                    "CVE-2024-00001 actively exploited by ransomware groups",
                    "Multiple C2 infrastructure IPs identified in ABUSEIPDB",
                    "MITRE T1059 (Command and Scripting Interpreter) linked to active campaigns",
                ],
                "threat_clusters": [
                    {
                        "cluster_name": "Ransomware Campaign Alpha",
                        "severity": "CRITICAL",
                        "threat_ids": ["CVE-2024-00001"],
                        "narrative": "Active ransomware campaign exploiting RCE vulnerability.",
                        "mitre_techniques": ["T1059", "T1486"],
                        "cve_ids": ["CVE-2024-00001"],
                    }
                ],
                "recommended_actions": [
                    "Patch CVE-2024-00001 immediately on all affected systems",
                    "Block identified C2 IPs at perimeter firewall",
                    "Enable detection rules for T1059 in SIEM",
                ],
                "siem_alerts": [
                    {
                        "alert_id": "ALERT-001",
                        "rule_name": "Critical CVE Detection",
                        "severity": "CRITICAL",
                        "description": "CVE-2024-00001 exploitation attempt detected",
                        "tags": ["ransomware", "rce"],
                        "mitre_technique": "T1059",
                        "cve_ref": "CVE-2024-00001",
                    }
                ],
            },
        }
    ]
}


@pytest.fixture
def mock_cves() -> list[CVERecord]:
    return [
        CVERecord(
            cve_id="CVE-2024-00001",
            description="Critical RCE in ExampleLib used by ransomware groups.",
            published=datetime(2024, 1, 15, tzinfo=UTC),
            last_modified=datetime(2024, 1, 20, tzinfo=UTC),
            cvss_v3_score=9.8,
            source=ThreatSource.NVD,
        )
    ]


@pytest.fixture
def mock_techniques() -> list[ATTACKTechnique]:
    return [
        ATTACKTechnique(
            technique_id="T1059",
            name="Command and Scripting Interpreter",
            tactic="execution",
            description="Adversaries abuse command interpreters.",
            platforms=["Windows"],
            source=ThreatSource.MITRE_ATTACK,
        )
    ]


@pytest.fixture
def mock_iocs() -> list[IOCRecord]:
    return [
        IOCRecord(
            ioc_type="ipv4",
            value="10.10.10.10",
            confidence=0.98,
            malicious=True,
            abuse_score=98,
            sources=[ThreatSource.ABUSEIPDB],
        )
    ]


@pytest.fixture
def mock_feed_items() -> list[ThreatFeedItem]:
    return [
        ThreatFeedItem(
            title="CVE-2024-00001: ExampleLib RCE in CISA KEV",
            description="CISA confirms active exploitation.",
            url="https://cisa.gov/kev",
            published=datetime(2024, 1, 22, tzinfo=UTC),
            severity=Severity.CRITICAL,
            cve_refs=["CVE-2024-00001"],
            source=ThreatSource.CISA_KEV,
        )
    ]


@pytest.mark.asyncio
async def test_full_swarm_pipeline_happy_path(
    mock_cves: list[CVERecord],
    mock_techniques: list[ATTACKTechnique],
    mock_iocs: list[IOCRecord],
    mock_feed_items: list[ThreatFeedItem],
    tmp_path: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full pipeline: all 4 agents + normalization + correlation + report."""
    monkeypatch.chdir(tmp_path)

    # Mock all 4 ingestion agents
    nvd_mock = AsyncMock()
    nvd_mock.__aenter__ = AsyncMock(return_value=nvd_mock)
    nvd_mock.__aexit__ = AsyncMock(return_value=None)
    nvd_mock.fetch_recent_cves = AsyncMock(return_value=mock_cves)

    attack_mock = AsyncMock()
    attack_mock.__aenter__ = AsyncMock(return_value=attack_mock)
    attack_mock.__aexit__ = AsyncMock(return_value=None)
    attack_mock.fetch_techniques = AsyncMock(return_value=mock_techniques)

    # Mock Claude structured response
    claude_response = MagicMock()
    claude_content = MagicMock()
    claude_content.type = "tool_use"
    claude_content.input = MOCK_CLAUDE_RESPONSE["content"][0]["input"]
    claude_response.content = [claude_content]

    anthropic_mock = MagicMock()
    anthropic_mock.messages = MagicMock()
    anthropic_mock.messages.create = AsyncMock(return_value=claude_response)

    with (
        patch("src.agents.cve_scraper.NVDClient", return_value=nvd_mock),
        patch("src.agents.attack_mapper.MITREATTACKClient", return_value=attack_mock),
        patch("src.agents.ioc_extractor._fetch_otx", new=AsyncMock(return_value=mock_iocs)),
        patch("src.agents.ioc_extractor._fetch_abuseipdb", new=AsyncMock(return_value=[])),
        patch(
            "src.agents.feed_aggregator._fetch_cisa_kev",
            new=AsyncMock(return_value=mock_feed_items),
        ),
        patch("src.agents.feed_aggregator._fetch_greynoise", new=AsyncMock(return_value=[])),
        patch("src.agents.correlation_agent.anthropic.AsyncAnthropic", return_value=anthropic_mock),
    ):
        from src.graph.swarm import run_swarm

        state = await run_swarm(
            query_keywords=["ransomware"],
            max_cves=10,
            max_iocs=10,
            config={"configurable": {"anthropic_api_key": "test-key"}},
        )

    # Validate swarm completed successfully
    assert state.completed is True
    # V2 runs the 4 ingestion agents plus enrichment/reflection, and the
    # supervisor can route through the enrichment fan-out more than once, so
    # exact count isn't stable — just require the 4 ingest agents are present.
    ingest_agents = {"cve_scraper", "attack_mapper", "ioc_extractor", "feed_aggregator"}
    seen = {r.agent_name for r in state.agent_results}
    assert ingest_agents.issubset(seen)
    assert all(r.success for r in state.agent_results)

    # Validate normalization
    assert len(state.normalized_threats) > 0
    assert state.total_raw_records > 0

    # Validate correlation report
    assert state.report is not None
    assert state.report.report_id.startswith("TIA-")
    assert len(state.report.critical_findings) > 0
    assert len(state.report.threat_clusters) > 0
    assert len(state.report.siem_alerts) > 0
    assert state.report.total_threats_processed == len(state.normalized_threats)

    # Validate output files were written
    output_dir = tmp_path / "output"
    assert output_dir.exists()
    md_files = list(output_dir.glob("*.md"))
    all_json = list(output_dir.glob("*.json"))
    iocs_sidecar = [p for p in all_json if p.name.endswith("_iocs.json")]
    json_files = [p for p in all_json if not p.name.endswith("_iocs.json")]
    ndjson_files = list(output_dir.glob("*.ndjson"))
    assert len(md_files) == 1
    assert len(json_files) == 1
    assert len(ndjson_files) == 1
    assert len(iocs_sidecar) == 1

    # Validate markdown content
    md_content = md_files[0].read_text()
    assert "# Threat Intelligence Report" in md_content
    assert "Executive Summary" in md_content
    assert "SIEM Alerts" in md_content

    # Sidecar is derived from normalized IOC threats; must contain at least
    # the mock IOCs injected above.
    import json as _json

    sidecar_data = _json.loads(iocs_sidecar[0].read_text())
    assert len(sidecar_data) >= 1
    assert all(r.get("ioc_type") and r.get("value") for r in sidecar_data)


@pytest.mark.asyncio
async def test_swarm_handles_all_agents_failing(
    tmp_path: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pipeline should not crash when all agents fail — errors surface cleanly."""
    monkeypatch.chdir(tmp_path)

    with (
        patch(
            "src.agents.ioc_extractor._fetch_otx", new=AsyncMock(side_effect=Exception("timeout"))
        ),
        patch(
            "src.agents.ioc_extractor._fetch_abuseipdb",
            new=AsyncMock(side_effect=Exception("timeout")),
        ),
        patch("src.agents.cve_scraper.NVDClient", side_effect=Exception("NVD down")),
        patch("src.agents.attack_mapper.MITREATTACKClient", side_effect=Exception("MITRE down")),
        patch(
            "src.agents.feed_aggregator._fetch_cisa_kev",
            new=AsyncMock(side_effect=Exception("CISA down")),
        ),
        patch(
            "src.agents.feed_aggregator._fetch_greynoise",
            new=AsyncMock(side_effect=Exception("GN down")),
        ),
    ):
        from src.graph.swarm import run_swarm

        state = await run_swarm(
            query_keywords=[],
            config={"configurable": {"anthropic_api_key": "test-key"}},
        )

    # Should not raise; errors should be captured
    assert isinstance(state, SwarmState)
