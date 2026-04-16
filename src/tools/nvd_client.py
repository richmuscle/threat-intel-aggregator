"""NVD 2.0 API client — fetches recent CVEs with CVSS v3 scoring."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

import aiohttp
import structlog

from src.models import CVERecord, ThreatSource
from src.tools.base_client import BaseAPIClient

logger = structlog.get_logger(__name__)


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


class NVDClient(BaseAPIClient):
    """
    NVD 2.0 REST client.

    Rate limits (NVD v2 public API):
      * Without API key: 5 req / 30s
      * With API key:   50 req / 30s

    `calls_per_second` is tuned to those published limits (5.0 / 50.0) so
    the token-bucket in `BaseAPIClient` tracks the correct order of magnitude.
    The API key falls back to `$NVD_API_KEY` when not passed in explicitly —
    LangGraph config always flows through the constructor, but test harnesses
    and ad-hoc scripts instantiating the client directly get the env value.
    """

    base_url = "https://services.nvd.nist.gov"
    calls_per_second = 5.0

    def __init__(self, api_key: str | None = None) -> None:
        super().__init__(api_key=api_key or os.environ.get("NVD_API_KEY"))
        if self._api_key:
            self.calls_per_second = 50.0

    def _build_headers(self) -> dict[str, str]:
        headers = super()._build_headers()
        if self._api_key:
            headers["apiKey"] = self._api_key
        return headers

    async def fetch_recent_cves(
        self,
        days_back: int = 7,
        max_results: int = 50,
        keywords: list[str] | None = None,
    ) -> list[CVERecord]:
        """
        Fetch CVEs published in the last `days_back` days.

        NVD v2 requires a *bounded* date window — omitting `pubStartDate` /
        `pubEndDate` returns a 404 (the endpoint exists but refuses the
        unbounded query). The values must match its exact format:
        `YYYY-MM-DDTHH:MM:SSZ` (no fractional seconds, no +00:00 suffix).

        `keywordExactMatch` is intentionally omitted; without it NVD does
        a broad substring match, which is what we want. Passing the string
        `"false"` is rejected with a 404 (bool-as-string is not accepted).

        A 404 response is treated as "empty window" — NVD periodically
        returns 404 for narrow ranges with no published CVEs, and that
        should not fail a swarm run. All other HTTP errors propagate so
        the agent wrapper can flag them as failures.
        """
        now = datetime.now(UTC)
        start = now - timedelta(days=days_back)

        params: dict[str, Any] = {
            "resultsPerPage": min(max_results, 2000),
            "startIndex": 0,
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if keywords:
            params["keywordSearch"] = " ".join(keywords)

        try:
            data = await self.get("/rest/json/cves/2.0", params=params)
        except aiohttp.ClientResponseError as exc:
            # NVD returns 403 to unauthenticated clients that exceed 5 req/30s.
            # It also returns 403 with a message like "Request forbidden by
            # administrative rules" for blocked user-agents. Either way, empty
            # results with 403 are a rate-limit symptom and must be surfaced.
            if exc.status == 403:
                logger.warning(
                    "nvd_rate_limited",
                    has_api_key=bool(self._api_key),
                    days_back=days_back,
                    keywords=keywords,
                    message=(
                        "NVD returned 403 — likely rate-limited. "
                        "Set NVD_API_KEY to raise the limit 10x."
                    ),
                )
                return []
            if exc.status == 404:
                # Distinguish empty window from rate-limit by log-level + field:
                # this path is a genuine "no CVEs in the requested window."
                logger.info(
                    "nvd_empty_window",
                    days_back=days_back,
                    keywords=keywords,
                    message="NVD returned 404 — no CVEs published in window",
                )
                return []
            raise

        vulns = data.get("vulnerabilities", [])
        # Some NVD responses are 200-OK but empty. Without an API key this
        # correlates strongly with silent rate-limiting against unauthenticated
        # callers; surface it so the swarm summary can warn the operator.
        if not vulns and not self._api_key:
            logger.warning(
                "nvd_empty_response_unauthenticated",
                days_back=days_back,
                keywords=keywords,
                message=(
                    "NVD returned 0 vulnerabilities without an API key. "
                    "This may be the unauthenticated rate limit (5 req/30s). "
                    "Get a free key at https://nvd.nist.gov/developers/request-an-api-key"
                ),
            )
        return [self._parse_cve(item) for item in vulns]

    async def fetch_cve_by_id(self, cve_id: str) -> CVERecord | None:
        try:
            data = await self.get("/rest/json/cves/2.0", params={"cveId": cve_id})
        except aiohttp.ClientResponseError as exc:
            if exc.status == 404:
                return None
            raise
        vulns = data.get("vulnerabilities", [])
        return self._parse_cve(vulns[0]) if vulns else None

    @staticmethod
    def _parse_cve(item: dict[str, Any]) -> CVERecord:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "CVE-0000-0000")
        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        cvss_score: float | None = None
        cvss_vector: str | None = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                break

        weaknesses = cve.get("weaknesses", [])
        cwe_ids = [
            desc["value"]
            for w in weaknesses
            for desc in w.get("description", [])
            if desc.get("lang") == "en" and desc["value"].startswith("CWE-")
        ]

        configs = cve.get("configurations", [])
        affected: list[str] = []
        for config in configs:
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    if cpe.get("vulnerable"):
                        affected.append(cpe.get("criteria", ""))

        refs = [r.get("url", "") for r in cve.get("references", [])]

        return CVERecord(
            cve_id=cve_id,
            description=description,
            published=cve.get("published", _utcnow_iso()),
            last_modified=cve.get("lastModified", _utcnow_iso()),
            cvss_v3_score=cvss_score,
            cvss_v3_vector=cvss_vector,
            cwe_ids=cwe_ids,
            affected_products=affected[:20],
            references=refs[:10],
            source=ThreatSource.NVD,
            raw=item,
        )
