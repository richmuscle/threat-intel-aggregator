"""CVE Scraper Agent — parallel node in the LangGraph swarm."""
from __future__ import annotations

import time

import structlog

from src.models import AgentResult, CVERecord, SwarmState
from src.pipeline.normalizer import normalize_cve
from src.tools import NVDClient

logger = structlog.get_logger(__name__)


async def cve_scraper_agent(state: SwarmState, config: dict) -> dict:
    """
    LangGraph node: fetches CVEs from NVD, returns AgentResult.
    Runs in parallel with ATT&CK mapper, IOC extractor, feed aggregator.
    """
    t0 = time.monotonic()
    agent_name = "cve_scraper"
    settings = config.get("configurable", {})
    api_key = settings.get("nvd_api_key")
    days_back = settings.get("cve_days_back", 7)
    max_cves = state.max_cves

    logger.info("agent_start", agent=agent_name, max_cves=max_cves, days_back=days_back)

    try:
        async with NVDClient(api_key=api_key) as client:
            cves: list[CVERecord] = await client.fetch_recent_cves(
                days_back=days_back,
                max_results=max_cves,
                keywords=state.query_keywords or None,
            )

        normalized = [normalize_cve(c) for c in cves]
        duration_ms = (time.monotonic() - t0) * 1000

        logger.info(
            "agent_complete",
            agent=agent_name,
            records=len(cves),
            duration_ms=round(duration_ms, 1),
        )

        result = AgentResult(
            agent_name=agent_name,
            success=True,
            records=normalized,
            items_fetched=len(cves),
            duration_ms=duration_ms,
        )

    except Exception as exc:
        duration_ms = (time.monotonic() - t0) * 1000
        logger.error("agent_failed", agent=agent_name, error=str(exc))
        result = AgentResult(
            agent_name=agent_name,
            success=False,
            error=str(exc),
            duration_ms=duration_ms,
        )

    return {"agent_results": state.agent_results + [result]}
