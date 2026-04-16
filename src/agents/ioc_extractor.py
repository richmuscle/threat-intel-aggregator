"""IOC Extractor Agent — runs OTX + AbuseIPDB concurrently via asyncio.gather."""
from __future__ import annotations

import asyncio
import time

import structlog

from src.models import AgentResult, IOCRecord, SwarmState
from src.pipeline.normalizer import normalize_ioc
from src.tools import AbuseIPDBClient, OTXClient

logger = structlog.get_logger(__name__)


async def ioc_extractor_agent(state: SwarmState, config: dict) -> dict:
    """
    LangGraph node: fires OTX and AbuseIPDB in true parallel via asyncio.gather.
    Merges, deduplicates by value, returns normalized IOC records.
    """
    t0 = time.monotonic()
    agent_name = "ioc_extractor"
    settings = config.get("configurable", {})
    otx_key = settings.get("otx_api_key")
    abuseipdb_key = settings.get("abuseipdb_api_key")
    max_iocs = state.max_iocs

    logger.info("agent_start", agent=agent_name, max_iocs=max_iocs)

    try:
        # True parallel: both APIs fire at the same time
        otx_iocs, abuse_iocs = await asyncio.gather(
            _fetch_otx(otx_key, max_iocs // 2),
            _fetch_abuseipdb(abuseipdb_key, max_iocs // 2),
            return_exceptions=True,
        )

        all_iocs: list[IOCRecord] = []

        if isinstance(otx_iocs, Exception):
            logger.warning("otx_failed", error=str(otx_iocs))
        else:
            all_iocs.extend(otx_iocs)

        if isinstance(abuse_iocs, Exception):
            logger.warning("abuseipdb_failed", error=str(abuse_iocs))
        else:
            all_iocs.extend(abuse_iocs)

        # Dedup by IOC value within this agent
        seen: dict[str, IOCRecord] = {}
        for ioc in all_iocs:
            if ioc.value not in seen:
                seen[ioc.value] = ioc
            else:
                # Merge sources
                seen[ioc.value].sources = list(
                    set(seen[ioc.value].sources + ioc.sources)
                )

        deduped = list(seen.values())
        normalized = [normalize_ioc(i) for i in deduped]
        duration_ms = (time.monotonic() - t0) * 1000

        logger.info(
            "agent_complete",
            agent=agent_name,
            raw_iocs=len(all_iocs),
            deduped=len(deduped),
            duration_ms=round(duration_ms, 1),
        )

        result = AgentResult(
            agent_name=agent_name,
            success=True,
            records=normalized,
            items_fetched=len(deduped),
            duration_ms=duration_ms,
        )
        # Return both the envelope (agent_results) *and* the raw IOCRecord
        # list so the downstream sidecar can emit real provider-confidence
        # values instead of synthesising them from NormalizedThreat severity.
        # `_parallel_ingest_node` pulls `raw_iocs` into SwarmState.
        return {
            "agent_results": state.agent_results + [result],
            "raw_iocs": deduped,
        }

    except Exception as exc:
        duration_ms = (time.monotonic() - t0) * 1000
        logger.error("agent_failed", agent=agent_name, error=str(exc))
        result = AgentResult(
            agent_name=agent_name,
            success=False,
            error=str(exc),
            duration_ms=duration_ms,
        )
        return {"agent_results": state.agent_results + [result], "raw_iocs": []}


async def _fetch_otx(api_key: str | None, limit: int) -> list[IOCRecord]:
    async with OTXClient(api_key=api_key) as client:
        return await client.fetch_recent_pulses(days_back=7, limit=limit)


async def _fetch_abuseipdb(api_key: str | None, limit: int) -> list[IOCRecord]:
    async with AbuseIPDBClient(api_key=api_key) as client:
        return await client.fetch_blocklist(confidence_minimum=85, limit=limit)
