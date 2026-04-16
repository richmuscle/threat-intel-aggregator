"""Unit tests — swarm agents with mocked tool clients."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from src.agents.attack_mapper import attack_mapper_agent
from src.agents.cve_scraper import cve_scraper_agent
from src.agents.ioc_extractor import ioc_extractor_agent
from src.models import (
    ATTACKTechnique,
    CVERecord,
    IOCRecord,
    SwarmState,
    ThreatSource,
)

# ── Shared fixtures ───────────────────────────────────────────────────────────


@pytest.fixture
def base_state() -> SwarmState:
    return SwarmState(run_id="test-run-001", query_keywords=["ransomware"])


@pytest.fixture
def base_config() -> dict:
    return {
        "configurable": {
            "nvd_api_key": "test-nvd-key",
            "otx_api_key": "test-otx-key",
            "abuseipdb_api_key": "test-abuse-key",
            "greynoise_api_key": "test-gn-key",
            "anthropic_api_key": "test-anthropic-key",
            "cve_days_back": 7,
            "attack_platform": "Windows",
        }
    }


@pytest.fixture
def sample_cves() -> list[CVERecord]:
    return [
        CVERecord(
            cve_id=f"CVE-2024-{i:05d}",
            description=f"Test CVE {i} ransomware related.",
            published=datetime(2024, 1, i + 1, tzinfo=UTC),
            last_modified=datetime(2024, 1, i + 2, tzinfo=UTC),
            cvss_v3_score=float(7 + (i % 3)),
            source=ThreatSource.NVD,
        )
        for i in range(1, 4)
    ]


@pytest.fixture
def sample_techniques() -> list[ATTACKTechnique]:
    return [
        ATTACKTechnique(
            technique_id=f"T10{i:02d}",
            name=f"Technique {i}",
            tactic="execution",
            description=f"Description for technique {i}.",
            platforms=["Windows"],
            source=ThreatSource.MITRE_ATTACK,
        )
        for i in range(1, 4)
    ]


@pytest.fixture
def sample_iocs() -> list[IOCRecord]:
    return [
        IOCRecord(
            ioc_type="ipv4",
            value=f"10.0.0.{i}",
            confidence=0.9,
            malicious=True,
            abuse_score=85 + i,
            sources=[ThreatSource.ABUSEIPDB],
        )
        for i in range(1, 4)
    ]


# ── CVE Scraper Agent ─────────────────────────────────────────────────────────


class TestCVEScraperAgent:
    @pytest.mark.asyncio
    async def test_success_returns_agent_result(
        self, base_state: SwarmState, base_config: dict, sample_cves: list[CVERecord]
    ) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.fetch_recent_cves = AsyncMock(return_value=sample_cves)

        with patch("src.agents.cve_scraper.NVDClient", return_value=mock_client):
            result_dict = await cve_scraper_agent(base_state, base_config)

        results = result_dict["agent_results"]
        assert len(results) == 1
        agent_result = results[0]
        assert agent_result.success is True
        assert agent_result.agent_name == "cve_scraper"
        assert agent_result.items_fetched == 3
        assert len(agent_result.records) == 3

    @pytest.mark.asyncio
    async def test_failure_returns_error_result(
        self, base_state: SwarmState, base_config: dict
    ) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.fetch_recent_cves = AsyncMock(side_effect=ConnectionError("NVD unreachable"))

        with patch("src.agents.cve_scraper.NVDClient", return_value=mock_client):
            result_dict = await cve_scraper_agent(base_state, base_config)

        agent_result = result_dict["agent_results"][0]
        assert agent_result.success is False
        assert "NVD unreachable" in agent_result.error
        assert agent_result.items_fetched == 0


# ── ATT&CK Mapper Agent ───────────────────────────────────────────────────────


class TestATTACKMapperAgent:
    @pytest.mark.asyncio
    async def test_success_returns_normalized_techniques(
        self, base_state: SwarmState, base_config: dict, sample_techniques: list[ATTACKTechnique]
    ) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.fetch_techniques = AsyncMock(return_value=sample_techniques)

        with patch("src.agents.attack_mapper.MITREATTACKClient", return_value=mock_client):
            result_dict = await attack_mapper_agent(base_state, base_config)

        agent_result = result_dict["agent_results"][0]
        assert agent_result.success is True
        assert agent_result.agent_name == "attack_mapper"

    @pytest.mark.asyncio
    async def test_keyword_filter_applied(
        self, base_config: dict, sample_techniques: list[ATTACKTechnique]
    ) -> None:
        state = SwarmState(run_id="kw-test", query_keywords=["Technique 2"])
        # Only Technique 2 matches keyword
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.fetch_techniques = AsyncMock(return_value=sample_techniques)

        with patch("src.agents.attack_mapper.MITREATTACKClient", return_value=mock_client):
            result_dict = await attack_mapper_agent(state, base_config)

        agent_result = result_dict["agent_results"][0]
        assert agent_result.items_fetched == 1


# ── IOC Extractor Agent ───────────────────────────────────────────────────────


class TestIOCExtractorAgent:
    @pytest.mark.asyncio
    async def test_merges_otx_and_abuseipdb(
        self, base_state: SwarmState, base_config: dict, sample_iocs: list[IOCRecord]
    ) -> None:
        otx_iocs = sample_iocs[:2]
        abuse_iocs = sample_iocs[2:]

        with (
            patch("src.agents.ioc_extractor._fetch_otx", new=AsyncMock(return_value=otx_iocs)),
            patch(
                "src.agents.ioc_extractor._fetch_abuseipdb", new=AsyncMock(return_value=abuse_iocs)
            ),
        ):
            result_dict = await ioc_extractor_agent(base_state, base_config)

        agent_result = result_dict["agent_results"][0]
        assert agent_result.success is True
        assert agent_result.items_fetched == 3

    @pytest.mark.asyncio
    async def test_deduplicates_same_ioc_value(
        self, base_state: SwarmState, base_config: dict
    ) -> None:
        duplicate_ioc = IOCRecord(
            ioc_type="ipv4",
            value="10.0.0.1",
            confidence=0.9,
            malicious=True,
            sources=[ThreatSource.OTX],
        )
        same_from_abuse = IOCRecord(
            ioc_type="ipv4",
            value="10.0.0.1",
            confidence=0.95,
            malicious=True,
            sources=[ThreatSource.ABUSEIPDB],
        )

        with (
            patch(
                "src.agents.ioc_extractor._fetch_otx", new=AsyncMock(return_value=[duplicate_ioc])
            ),
            patch(
                "src.agents.ioc_extractor._fetch_abuseipdb",
                new=AsyncMock(return_value=[same_from_abuse]),
            ),
        ):
            result_dict = await ioc_extractor_agent(base_state, base_config)

        agent_result = result_dict["agent_results"][0]
        assert agent_result.items_fetched == 1

    @pytest.mark.asyncio
    async def test_partial_failure_still_returns_success(
        self, base_state: SwarmState, base_config: dict, sample_iocs: list[IOCRecord]
    ) -> None:
        with (
            patch("src.agents.ioc_extractor._fetch_otx", new=AsyncMock(return_value=sample_iocs)),
            patch(
                "src.agents.ioc_extractor._fetch_abuseipdb",
                new=AsyncMock(side_effect=Exception("timeout")),
            ),
        ):
            result_dict = await ioc_extractor_agent(base_state, base_config)

        agent_result = result_dict["agent_results"][0]
        assert agent_result.success is True
        assert agent_result.items_fetched == len(sample_iocs)
