"""
IOC clients — AlienVault OTX and AbuseIPDB.
Both run concurrently via asyncio.gather inside the IOC extractor agent.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog

from src.models import IOCRecord, ThreatSource
from src.tools.base_client import BaseAPIClient, is_valid_ip

logger = structlog.get_logger(__name__)


class OTXClient(BaseAPIClient):
    base_url = "https://otx.alienvault.com"
    calls_per_second = 3.0

    def _build_headers(self) -> dict[str, str]:
        headers = super()._build_headers()
        if self._api_key:
            headers["X-OTX-API-KEY"] = self._api_key
        return headers

    async def fetch_recent_pulses(self, days_back: int = 7, limit: int = 50) -> list[IOCRecord]:
        params = {"limit": limit, "modified_since": f"{days_back}d"}
        data = await self.get("/api/v1/pulses/subscribed", params=params)
        records: list[IOCRecord] = []
        for pulse in data.get("results", []):
            for indicator in pulse.get("indicators", []):
                rec = self._parse_indicator(indicator, pulse)
                if rec:
                    records.append(rec)
        return records

    async def fetch_iocs_for_cve(self, cve_id: str) -> list[IOCRecord]:
        data = await self.get("/api/v1/pulses/search", params={"q": cve_id, "limit": 20})
        records: list[IOCRecord] = []
        for pulse in data.get("results", []):
            for indicator in pulse.get("indicators", []):
                rec = self._parse_indicator(indicator, pulse)
                if rec:
                    records.append(rec)
        return records

    @staticmethod
    def _parse_indicator(indicator: dict[str, Any], pulse: dict[str, Any]) -> IOCRecord | None:
        type_map = {
            "IPv4": "ipv4",
            "IPv6": "ipv6",
            "domain": "domain",
            "hostname": "domain",
            "MD5": "md5",
            "SHA1": "sha1",
            "SHA256": "sha256",
            "URL": "url",
            "email": "email",
        }
        ioc_type = type_map.get(indicator.get("type", ""))
        if not ioc_type:
            return None

        created = indicator.get("created")
        return IOCRecord(
            ioc_type=ioc_type,
            value=indicator.get("indicator", ""),
            confidence=min(pulse.get("pulse_source_score", 0.5), 1.0),
            malicious=True,
            tags=pulse.get("tags", [])[:5],
            pulse_count=pulse.get("pulse_count", 0),
            first_seen=datetime.fromisoformat(created.replace("Z", "+00:00")) if created else None,
            sources=[ThreatSource.OTX],
        )


class AbuseIPDBClient(BaseAPIClient):
    base_url = "https://api.abuseipdb.com"
    calls_per_second = 1.0

    def _build_headers(self) -> dict[str, str]:
        headers = super()._build_headers()
        if self._api_key:
            headers["Key"] = self._api_key
        return headers

    async def check_ip(self, ip: str, max_age_days: int = 90) -> IOCRecord | None:
        # Defense-in-depth: `ip` here is a query param (not a URL path
        # component), so path traversal isn't a concern — but a malformed
        # value shouldn't reach AbuseIPDB regardless. `is_valid_ip` rejects
        # anything that isn't a canonical IPv4/IPv6.
        if not is_valid_ip(ip):
            logger.warning("abuseipdb_invalid_ip_rejected", ip=ip[:64])
            return None
        data = await self.get(
            "/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": False},
        )
        result = data.get("data", {})
        abuse_score = result.get("abuseConfidenceScore", 0)
        if abuse_score == 0:
            return None

        return IOCRecord(
            ioc_type="ipv4",
            value=ip,
            confidence=abuse_score / 100,
            malicious=abuse_score > 50,
            country=result.get("countryCode"),
            asn=str(result.get("isp", "")),
            abuse_score=abuse_score,
            last_seen=result.get("lastReportedAt"),
            sources=[ThreatSource.ABUSEIPDB],
        )

    async def fetch_blocklist(
        self, confidence_minimum: int = 90, limit: int = 100
    ) -> list[IOCRecord]:
        data = await self.get(
            "/api/v2/blacklist",
            params={"confidenceMinimum": confidence_minimum, "limit": limit},
        )
        records = []
        for entry in data.get("data", []):
            score = entry.get("abuseConfidenceScore", 0)
            records.append(
                IOCRecord(
                    ioc_type="ipv4",
                    value=entry.get("ipAddress", ""),
                    confidence=score / 100,
                    malicious=True,
                    country=entry.get("countryCode"),
                    abuse_score=score,
                    sources=[ThreatSource.ABUSEIPDB],
                )
            )
        return records
