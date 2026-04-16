"""
Shodan client — internet exposure intelligence.
Free tier: 1 credit/day, 100 results/query (enough for spot-checking critical IPs).
Membership $49/mo: unlimited queries, full banner data, SSL certs, open ports.
"""

from __future__ import annotations

from typing import Any, cast

import structlog

from src.tools.base_client import BaseAPIClient, is_valid_ip

logger = structlog.get_logger(__name__)


class ShodanClient(BaseAPIClient):
    base_url = "https://api.shodan.io"
    calls_per_second = 1.0

    async def lookup_ip(self, ip: str) -> dict[str, Any] | None:
        """
        Full host lookup — open ports, banners, CVEs on running services.
        Costs 1 query credit on free tier.

        `ip` is validated as a canonical IPv4/IPv6 before URL construction —
        a malformed value (e.g. from a compromised feed) would otherwise let
        a crafted path like `../admin` reach `api.shodan.io`.
        """
        if not self._api_key:
            return None
        if not is_valid_ip(ip):
            logger.warning("shodan_invalid_ip_rejected", ip=ip[:64])
            return None
        try:
            data = await self.get(f"/shodan/host/{ip}", params={"key": self._api_key})
            return cast("dict[str, Any]", data)
        except Exception as exc:
            logger.debug("shodan_host_failed", ip=ip, error=str(exc))
            return None

    async def search(self, query: str, limit: int = 100) -> list[dict[str, Any]]:
        """
        SHODAN query — find exposed services matching a query.
        Examples: 'ransomware port:3389', 'product:OpenSSH vuln:CVE-2024-12345'
        """
        if not self._api_key:
            return []
        try:
            data = await self.get(
                "/shodan/host/search",
                params={
                    "key": self._api_key,
                    "query": query,
                    "limit": min(limit, 100),
                },
            )
            return cast("list[dict[str, Any]]", data.get("matches", []))
        except Exception as exc:
            logger.error("shodan_search_failed", query=query, error=str(exc))
            return []

    async def enrich_critical_ips(
        self,
        ips: list[str],
        max_lookups: int = 5,  # conservative on free tier
    ) -> dict[str, dict[str, Any]]:
        """
        Enrich a list of IPs with Shodan host data.
        Caps at max_lookups to preserve free tier credits.
        Prioritise first N — caller should pass highest-severity IPs first.
        """
        results: dict[str, dict[str, Any]] = {}
        for ip in ips[:max_lookups]:
            host_data = await self.lookup_ip(ip)
            if host_data:
                results[ip] = self._summarise_host(host_data)
                logger.info(
                    "shodan_host_enriched",
                    ip=ip,
                    ports=results[ip].get("open_ports", []),
                    vulns=len(results[ip].get("cves", [])),
                )
        return results

    @staticmethod
    def _summarise_host(data: dict[str, Any]) -> dict[str, Any]:
        """Extract actionable fields from raw Shodan host response."""
        ports = data.get("ports", [])
        vulns = list((data.get("vulns") or {}).keys())
        hostnames = data.get("hostnames", [])
        org = data.get("org", "")
        country = data.get("country_name", "")
        isp = data.get("isp", "")

        # Extract service banners
        banners: list[str] = []
        for service in data.get("data", []):
            product = service.get("product", "")
            version = service.get("version", "")
            port = service.get("port", "")
            if product:
                banners.append(f"{product} {version} (:{port})".strip())

        return {
            "open_ports": ports[:20],
            "cves": vulns[:10],
            "hostnames": hostnames[:5],
            "org": org,
            "country": country,
            "isp": isp,
            "banners": banners[:10],
            "last_update": data.get("last_update", ""),
        }

    async def get_api_info(self) -> dict[str, Any]:
        """Check API plan info and remaining scan credits."""
        if not self._api_key:
            return {}
        try:
            data = await self.get("/api-info", params={"key": self._api_key})
            return cast("dict[str, Any]", data)
        except Exception as exc:
            logger.warning("shodan_api_info_failed", error=str(exc))
            return {}
