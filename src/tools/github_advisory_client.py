"""
GitHub Advisory Database client — free REST API, no key required.
Pulls supply-chain CVE context: affected packages, patched versions, GHSA IDs.
Pairs with NVD agent to give developer-level actionability to every CVE.
"""
from __future__ import annotations

from datetime import datetime, timezone

import structlog

from src.models.threat import GHAdvisory, Severity, ThreatSource
from src.tools.base_client import BaseAPIClient

logger = structlog.get_logger(__name__)

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class GitHubAdvisoryClient(BaseAPIClient):
    base_url = "https://api.github.com"
    calls_per_second = 3.0

    def _build_headers(self) -> dict[str, str]:
        headers = super()._build_headers()
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        # Optional: add GitHub token for higher rate limits
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def fetch_advisory_for_cve(self, cve_id: str) -> GHAdvisory | None:
        """Fetch GitHub advisory for a specific CVE ID."""
        try:
            data = await self.get(
                "/advisories",
                params={"cve_id": cve_id, "per_page": 1},
            )
            if not data:
                return None
            advisories = data if isinstance(data, list) else data.get("items", [])
            if not advisories:
                return None
            first = advisories[0]
            if not isinstance(first, dict):
                return None
            return self._parse_advisory(first)
        except Exception as exc:
            logger.debug("gh_advisory_cve_failed", cve_id=cve_id, error=str(exc))
            return None

    async def fetch_recent_advisories(
        self,
        severity: str = "high",
        ecosystem: str | None = None,
        limit: int = 50,
    ) -> list[GHAdvisory]:
        """Fetch recent high/critical GitHub advisories."""
        params: dict = {
            "severity": severity,
            "per_page": min(limit, 100),
            "sort": "published",
            "direction": "desc",
        }
        if ecosystem:
            params["ecosystem"] = ecosystem

        try:
            data = await self.get("/advisories", params=params)
            advisories = data if isinstance(data, list) else []
            return [self._parse_advisory(a) for a in advisories if isinstance(a, dict) and a.get("ghsa_id")]
        except Exception as exc:
            logger.error("gh_advisories_failed", error=str(exc))
            return []

    async def fetch_advisories_for_cves(self, cve_ids: list[str]) -> dict[str, GHAdvisory]:
        """Batch fetch advisories for multiple CVE IDs. Returns dict keyed by CVE ID."""
        results: dict[str, GHAdvisory] = {}
        for cve_id in cve_ids[:30]:  # cap to avoid rate limiting
            advisory = await self.fetch_advisory_for_cve(cve_id)
            if advisory and advisory.cve_id:
                results[advisory.cve_id] = advisory
        return results

    @staticmethod
    def _parse_advisory(data: dict) -> GHAdvisory:
        ghsa_id = data.get("ghsa_id", "")
        cve_id = data.get("cve_id")
        summary = data.get("summary", "")[:500]
        severity_str = (data.get("severity") or "").upper()
        severity = SEVERITY_MAP.get(severity_str, Severity.UNKNOWN)

        # Extract affected packages and patched versions
        affected_packages: list[str] = []
        patched_versions: list[str] = []
        for vuln in data.get("vulnerabilities", []):
            if not isinstance(vuln, dict): continue
            pkg = vuln.get("package", {})
            ecosystem = pkg.get("ecosystem", "")
            name = pkg.get("name", "")
            if name:
                affected_packages.append(f"{ecosystem}/{name}" if ecosystem else name)
            patched = vuln.get("patched_versions", "")
            if patched:
                patched_versions.append(patched)

        refs = [r.get("url", "") for r in data.get("references", []) if isinstance(r, dict) and r.get("url")]

        published_str = data.get("published_at")
        published = None
        if published_str:
            try:
                published = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        return GHAdvisory(
            ghsa_id=ghsa_id,
            cve_id=cve_id,
            summary=summary,
            severity=severity,
            affected_packages=affected_packages[:10],
            patched_versions=patched_versions[:5],
            published_at=published,
            references=refs[:5],
            source=ThreatSource.VENDOR_ADVISORY,
        )
