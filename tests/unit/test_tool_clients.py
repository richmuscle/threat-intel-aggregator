"""Unit tests — API tool clients with mocked HTTP responses."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models import Severity, ThreatSource
from src.tools.ioc_clients import AbuseIPDBClient, OTXClient
from src.tools.nvd_client import NVDClient

# ── NVD Client tests ──────────────────────────────────────────────────────────

NVD_SAMPLE_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-12345",
                "published": "2024-01-15T10:00:00.000",
                "lastModified": "2024-01-20T12:00:00.000",
                "descriptions": [
                    {"lang": "en", "value": "Critical RCE in ExampleLib."},
                    {"lang": "es", "value": "Vulnerabilidad crítica."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        }
                    ]
                },
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
                "references": [{"url": "https://example.com/advisory"}],
                "configurations": [],
            }
        }
    ]
}


class TestNVDClient:
    @pytest.mark.asyncio
    async def test_parse_cve_from_response(self) -> None:
        client = NVDClient()
        with patch.object(client, "get", new=AsyncMock(return_value=NVD_SAMPLE_RESPONSE)):
            client._session = MagicMock()
            cves = await client.fetch_recent_cves(days_back=7, max_results=10)

        assert len(cves) == 1
        cve = cves[0]
        assert cve.cve_id == "CVE-2024-12345"
        assert cve.cvss_v3_score == 9.8
        assert cve.severity == Severity.CRITICAL
        assert "CWE-78" in cve.cwe_ids
        assert cve.source == ThreatSource.NVD

    @pytest.mark.asyncio
    async def test_english_description_selected(self) -> None:
        client = NVDClient()
        with patch.object(client, "get", new=AsyncMock(return_value=NVD_SAMPLE_RESPONSE)):
            client._session = MagicMock()
            cves = await client.fetch_recent_cves()

        assert "Critical RCE" in cves[0].description

    @pytest.mark.asyncio
    async def test_empty_response_returns_empty_list(self) -> None:
        client = NVDClient()
        with patch.object(client, "get", new=AsyncMock(return_value={"vulnerabilities": []})):
            client._session = MagicMock()
            cves = await client.fetch_recent_cves()

        assert cves == []

    @pytest.mark.asyncio
    async def test_missing_cvss_yields_unknown_severity(self) -> None:
        response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-99999",
                        "published": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-01-01T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "No CVSS."}],
                        "metrics": {},
                        "weaknesses": [],
                        "references": [],
                        "configurations": [],
                    }
                }
            ]
        }
        client = NVDClient()
        with patch.object(client, "get", new=AsyncMock(return_value=response)):
            client._session = MagicMock()
            cves = await client.fetch_recent_cves()

        assert cves[0].severity == Severity.UNKNOWN
        assert cves[0].cvss_v3_score is None


# ── AbuseIPDB Client tests ─────────────────────────────────────────────────────

ABUSEIPDB_RESPONSE = {
    "data": {
        "ipAddress": "1.2.3.4",
        "abuseConfidenceScore": 95,
        "countryCode": "RU",
        "isp": "Example ISP",
        "lastReportedAt": "2024-01-20T10:00:00+00:00",
    }
}


class TestAbuseIPDBClient:
    @pytest.mark.asyncio
    async def test_parse_high_confidence_ip(self) -> None:
        client = AbuseIPDBClient(api_key="test-key")
        with patch.object(client, "get", new=AsyncMock(return_value=ABUSEIPDB_RESPONSE)):
            client._session = MagicMock()
            ioc = await client.check_ip("1.2.3.4")

        assert ioc is not None
        assert ioc.value == "1.2.3.4"
        assert ioc.abuse_score == 95
        assert ioc.malicious is True
        assert ioc.country == "RU"
        assert ioc.confidence == pytest.approx(0.95)
        assert ThreatSource.ABUSEIPDB in ioc.sources

    @pytest.mark.asyncio
    async def test_zero_score_returns_none(self) -> None:
        response = {"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 0}}
        client = AbuseIPDBClient(api_key="test-key")
        with patch.object(client, "get", new=AsyncMock(return_value=response)):
            client._session = MagicMock()
            result = await client.check_ip("8.8.8.8")

        assert result is None


# ── OTX Client tests ──────────────────────────────────────────────────────────

OTX_RESPONSE = {
    "results": [
        {
            "id": "pulse-001",
            "tags": ["ransomware", "c2"],
            "pulse_source_score": 0.9,
            "pulse_count": 42,
            "indicators": [
                {
                    "type": "IPv4",
                    "indicator": "10.0.0.1",
                    "created": "2024-01-15T10:00:00Z",
                },
                {
                    "type": "domain",
                    "indicator": "malicious.example.com",
                    "created": "2024-01-15T10:00:00Z",
                },
                {
                    "type": "UnknownType",  # should be skipped
                    "indicator": "garbage",
                    "created": "2024-01-15T10:00:00Z",
                },
            ],
        }
    ]
}


class TestOTXClient:
    @pytest.mark.asyncio
    async def test_parses_valid_indicators(self) -> None:
        client = OTXClient(api_key="test-key")
        with patch.object(client, "get", new=AsyncMock(return_value=OTX_RESPONSE)):
            client._session = MagicMock()
            iocs = await client.fetch_recent_pulses()

        assert len(iocs) == 2
        values = {i.value for i in iocs}
        assert "10.0.0.1" in values
        assert "malicious.example.com" in values

    @pytest.mark.asyncio
    async def test_unknown_type_skipped(self) -> None:
        client = OTXClient(api_key="test-key")
        with patch.object(client, "get", new=AsyncMock(return_value=OTX_RESPONSE)):
            client._session = MagicMock()
            iocs = await client.fetch_recent_pulses()

        types = {i.ioc_type for i in iocs}
        assert "unknowntype" not in types

    @pytest.mark.asyncio
    async def test_tags_propagated(self) -> None:
        client = OTXClient(api_key="test-key")
        with patch.object(client, "get", new=AsyncMock(return_value=OTX_RESPONSE)):
            client._session = MagicMock()
            iocs = await client.fetch_recent_pulses()

        assert "ransomware" in iocs[0].tags
