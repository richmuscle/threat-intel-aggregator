"""CISA Known Exploited Vulnerabilities + GreyNoise feed clients."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from src.models import Severity, ThreatFeedItem, ThreatSource
from src.tools.base_client import BaseAPIClient, is_valid_ip

logger = structlog.get_logger(__name__)


class CISAKEVClient(BaseAPIClient):
    """CISA Known Exploited Vulnerabilities catalog — no API key required."""
    base_url = "https://www.cisa.gov"
    calls_per_second = 2.0

    async def fetch_kev_catalog(self) -> list[ThreatFeedItem]:
        """
        Parse the full KEV JSON feed.

        The KEV schema exposes a `knownRansomwareCampaignUse` flag
        (`Known` / `Unknown`) and structured vendor/product fields. We
        surface those into `tags` so downstream keyword filters can match
        on e.g. `"ransomware"`, `"microsoft"`, or a CWE id — previously the
        filter only saw `vulnerabilityName`, which almost never contains
        the user's query terms verbatim, and KEV records were being
        dropped for every run with `--keywords`.
        """
        data = await self.get(
            "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        )
        items: list[ThreatFeedItem] = []
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            vendor = vuln.get("vendorProject", "")
            product = vuln.get("product", "")
            vuln_name = vuln.get("vulnerabilityName", "")
            short_desc = vuln.get("shortDescription", "")
            required_action = vuln.get("requiredAction", "")
            ransomware_use = vuln.get("knownRansomwareCampaignUse", "Unknown")
            cwes = vuln.get("cwes", []) or []

            tags = ["kev", "actively-exploited"]
            if vendor:
                tags.append(vendor.lower())
            if product:
                tags.append(product.lower())
            if ransomware_use == "Known":
                tags.append("ransomware")
            tags.extend(cwe.lower() for cwe in cwes)

            # Ransomware-tied KEVs are the highest-priority class of entry —
            # bump their severity so downstream prioritisation reflects that.
            severity = Severity.CRITICAL if ransomware_use == "Known" else Severity.HIGH

            description = short_desc
            if required_action:
                description = f"{short_desc}  Required action: {required_action}"

            items.append(
                ThreatFeedItem(
                    title=f"{cve_id}: {vendor} {product} — {vuln_name}".strip(),
                    description=description,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    published=_parse_kev_date(vuln.get("dateAdded")),
                    severity=severity,
                    cve_refs=[cve_id] if cve_id else [],
                    tags=tags,
                    source=ThreatSource.CISA_KEV,
                )
            )
        return items

    async def fetch_recent_kev(self, limit: int = 20) -> list[ThreatFeedItem]:
        all_items = await self.fetch_kev_catalog()
        sorted_items = sorted(all_items, key=lambda x: x.published, reverse=True)
        return sorted_items[:limit]


def _parse_kev_date(raw: str | None) -> datetime:
    """Parse KEV `dateAdded` as a timezone-aware UTC datetime.

    KEV emits dates as `YYYY-MM-DD` with no timezone. `fromisoformat` would
    return a naive datetime, which compares unpredictably with UTC-aware
    values elsewhere in the pipeline (e.g. `SwarmState.triggered_at`).
    """
    if not raw:
        return datetime(2000, 1, 1, tzinfo=timezone.utc)
    return datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)


class GreyNoiseClient(BaseAPIClient):
    """GreyNoise community API — internet scanner / noise data."""
    base_url = "https://api.greynoise.io"
    calls_per_second = 1.0

    def _build_headers(self) -> dict[str, str]:
        headers = super()._build_headers()
        if self._api_key:
            headers["key"] = self._api_key
        return headers

    async def fetch_riot_data(self, ip: str) -> dict[str, Any]:
        """Check if IP is known benign internet infrastructure (RIOT).

        `ip` is URL-path interpolated — validate before request to prevent
        path traversal against `api.greynoise.io`.
        """
        if not is_valid_ip(ip):
            logger.warning("greynoise_invalid_ip_rejected", endpoint="riot", ip=ip[:64])
            return {}
        return await self.get(f"/v3/riot/{ip}")

    async def fetch_noise_status(self, ip: str) -> dict[str, Any]:
        """Check if IP is known internet scanner.

        `ip` is URL-path interpolated — validated same as RIOT above.
        """
        if not is_valid_ip(ip):
            logger.warning("greynoise_invalid_ip_rejected", endpoint="noise", ip=ip[:64])
            return {}
        return await self.get(f"/v3/noise/quick/{ip}")

    async def fetch_gnql_stats(self, query: str = "tags:malware") -> list[ThreatFeedItem]:
        """Query GreyNoise GNQL for threat stats (requires paid key)."""
        data = await self.get(
            "/v2/experimental/gnql/stats",
            params={"query": query, "count": 50},
        )
        items: list[ThreatFeedItem] = []
        for bucket in data.get("ip_count_by_tag", []):
            tag = bucket.get("value", "unknown")
            count = bucket.get("count", 0)
            items.append(
                ThreatFeedItem(
                    title=f"GreyNoise: {count} IPs tagged '{tag}'",
                    description=f"GreyNoise reports {count} IPs with tag '{tag}' in the last 24h.",
                    url=f"https://viz.greynoise.io/query/?gnql=tags:{tag}",
                    published=datetime.now(timezone.utc),
                    severity=Severity.MEDIUM if count > 100 else Severity.LOW,
                    tags=[tag, "greynoise", "scanner"],
                    source=ThreatSource.GREYNOISE,
                )
            )
        return items
