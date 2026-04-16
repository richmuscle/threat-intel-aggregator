"""
EPSS (Exploit Prediction Scoring System) client — FIRST.org free API.
No API key required. Returns exploit probability (0-1) per CVE.
EPSS >= 0.5 = actively exploited in the wild with high probability.
"""

from __future__ import annotations

import structlog

from src.models.threat import EPSSScore
from src.tools.base_client import BaseAPIClient

logger = structlog.get_logger(__name__)


class EPSSClient(BaseAPIClient):
    base_url = "https://api.first.org"
    calls_per_second = 5.0

    async def fetch_scores(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        """
        Batch fetch EPSS scores for a list of CVE IDs.
        Returns dict keyed by CVE ID for O(1) lookup during enrichment.
        """
        if not cve_ids:
            return {}

        # EPSS API accepts comma-separated CVE IDs, max 100 per request
        results: dict[str, EPSSScore] = {}
        batch_size = 100

        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i : i + batch_size]
            params = {"cve": ",".join(batch), "scope": "public"}

            try:
                data = await self.get("/data/v1/epss", params=params)
                for entry in data.get("data", []):
                    cve_id = entry.get("cve", "")
                    if cve_id:
                        results[cve_id] = EPSSScore(
                            cve_id=cve_id,
                            epss=float(entry.get("epss", 0.0)),
                            percentile=float(entry.get("percentile", 0.0)),
                            date=entry.get("date", ""),
                        )
                logger.debug(
                    "epss_batch_fetched",
                    batch_size=len(batch),
                    scored=len(results),
                )
            except Exception as exc:
                logger.warning("epss_batch_failed", error=str(exc), batch=batch[:3])

        return results

    async def fetch_score(self, cve_id: str) -> EPSSScore | None:
        """Fetch EPSS score for a single CVE."""
        scores = await self.fetch_scores([cve_id])
        return scores.get(cve_id)

    async def fetch_top_exploited(
        self, limit: int = 100, threshold: float = 0.5
    ) -> list[EPSSScore]:
        """Fetch CVEs with EPSS score above threshold — actively exploited."""
        params = {
            "scope": "public",
            "epss-gt": str(threshold),
            "order": "!epss",
            "limit": min(limit, 100),
        }
        try:
            data = await self.get("/data/v1/epss", params=params)
            return [
                EPSSScore(
                    cve_id=e.get("cve", ""),
                    epss=float(e.get("epss", 0.0)),
                    percentile=float(e.get("percentile", 0.0)),
                    date=e.get("date", ""),
                )
                for e in data.get("data", [])
                if e.get("cve")
            ]
        except Exception as exc:
            logger.error("epss_top_failed", error=str(exc))
            return []
