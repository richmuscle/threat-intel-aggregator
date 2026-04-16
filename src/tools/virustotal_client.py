"""
VirusTotal v3 API client — IOC enrichment.
Free tier: 4 req/min, 500 lookups/day.
Enriches IPs, domains, hashes with malware families and detection ratios.
"""
from __future__ import annotations

from datetime import datetime, timezone

import structlog

from src.models.threat import VTReport
from src.tools.base_client import (
    BaseAPIClient,
    is_valid_domain,
    is_valid_hash,
    is_valid_ip,
)

logger = structlog.get_logger(__name__)


class VirusTotalClient(BaseAPIClient):
    base_url = "https://www.virustotal.com"
    calls_per_second = 0.06  # 4 req/min free tier — conservative

    def _build_headers(self) -> dict[str, str]:
        headers = super()._build_headers()
        if self._api_key:
            headers["x-apikey"] = self._api_key
        return headers

    async def enrich_ip(self, ip: str) -> VTReport | None:
        """Enrich an IP address with VT analysis data.

        `ip` is validated before URL construction — without this guard a
        malformed value would compose a crafted path against
        `www.virustotal.com`.
        """
        if not self._api_key:
            return None
        if not is_valid_ip(ip):
            logger.warning("vt_invalid_ip_rejected", ip=ip[:64])
            return None
        try:
            data = await self.get(f"/api/v3/ip_addresses/{ip}")
            return self._parse_report(ip, "ipv4", data)
        except Exception as exc:
            logger.debug("vt_ip_failed", ip=ip, error=str(exc))
            return None

    async def enrich_domain(self, domain: str) -> VTReport | None:
        """Enrich a domain with VT analysis data.

        Domain input is regex-validated against RFC-1035 label rules before
        URL construction. IP addresses are rejected (they belong on the IP
        endpoint).
        """
        if not self._api_key:
            return None
        if not is_valid_domain(domain):
            logger.warning("vt_invalid_domain_rejected", domain=domain[:64])
            return None
        try:
            data = await self.get(f"/api/v3/domains/{domain}")
            return self._parse_report(domain, "domain", data)
        except Exception as exc:
            logger.debug("vt_domain_failed", domain=domain, error=str(exc))
            return None

    async def enrich_hash(self, file_hash: str) -> VTReport | None:
        """Enrich a file hash (MD5/SHA1/SHA256) with VT analysis data.

        Hash is regex-validated to the canonical hex length (32 / 40 / 64)
        before URL construction.
        """
        if not self._api_key:
            return None
        if not is_valid_hash(file_hash, kind="any"):
            logger.warning("vt_invalid_hash_rejected", hash=file_hash[:80])
            return None
        try:
            data = await self.get(f"/api/v3/files/{file_hash}")
            return self._parse_report(file_hash, "hash", data)
        except Exception as exc:
            logger.debug("vt_hash_failed", hash=file_hash, error=str(exc))
            return None

    async def enrich_batch(
        self,
        iocs: list[tuple[str, str]],  # (value, type) pairs
        max_lookups: int = 50,
    ) -> dict[str, VTReport]:
        """
        Enrich a batch of IOCs. Respects free tier daily limit.
        Prioritises IPs and hashes over domains.
        """
        if not self._api_key:
            return {}

        results: dict[str, VTReport] = {}
        count = 0

        # Priority order: hash > ip > domain
        sorted_iocs = sorted(
            iocs[:max_lookups],
            key=lambda x: {"sha256": 0, "md5": 1, "sha1": 2, "ipv4": 3, "ipv6": 4, "domain": 5}.get(x[1], 9),
        )

        for value, ioc_type in sorted_iocs:
            if count >= max_lookups:
                break
            report = None
            if ioc_type in ("ipv4", "ipv6"):
                report = await self.enrich_ip(value)
            elif ioc_type == "domain":
                report = await self.enrich_domain(value)
            elif ioc_type in ("sha256", "md5", "sha1"):
                report = await self.enrich_hash(value)

            if report:
                results[value] = report
            count += 1

        logger.info("vt_batch_complete", enriched=len(results), attempted=count)
        return results

    @staticmethod
    def _parse_report(value: str, ioc_type: str, data: dict) -> VTReport:
        attrs = data.get("data", {}).get("attributes", {})

        last_analysis = attrs.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        total = sum(last_analysis.values()) if last_analysis else 0

        # Extract malware family names from popular AV verdicts
        results = attrs.get("last_analysis_results", {})
        families: set[str] = set()
        for engine_result in results.values():
            category = engine_result.get("category", "")
            result_name = engine_result.get("result") or ""
            if category == "malicious" and result_name:
                # Normalise: take first meaningful token
                clean = result_name.split("/")[-1].split(".")[-1].lower()
                if len(clean) > 3:
                    families.add(clean)

        tags = attrs.get("tags", [])
        last_date_ts = attrs.get("last_analysis_date")
        last_date = (
            datetime.fromtimestamp(last_date_ts, tz=timezone.utc)
            if last_date_ts
            else None
        )

        return VTReport(
            ioc_value=value,
            ioc_type=ioc_type,
            malicious_count=malicious,
            total_engines=total,
            malware_families=list(families)[:10],
            tags=tags[:10],
            last_analysis_date=last_date,
        )
