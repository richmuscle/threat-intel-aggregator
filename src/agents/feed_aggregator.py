"""Feed Aggregator Agent — CISA KEV + GreyNoise, runs both concurrently."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog

from src.models import AgentResult, SwarmState, ThreatFeedItem
from src.pipeline.normalizer import normalize_feed_item
from src.tools import CISAKEVClient, GreyNoiseClient

logger = structlog.get_logger(__name__)


async def feed_aggregator_agent(state: SwarmState, config: dict[str, Any]) -> dict[str, Any]:
    """
    LangGraph node: CISA KEV and GreyNoise in parallel via asyncio.gather.
    CISA KEV needs no API key — always fires. GreyNoise degrades gracefully.
    """
    t0 = time.monotonic()
    agent_name = "feed_aggregator"
    settings = config.get("configurable", {})
    greynoise_key = settings.get("greynoise_api_key")

    logger.info("agent_start", agent=agent_name)

    # When a keyword filter is active, pull a wider KEV window so keyword
    # matches aren't starved by the default last-30 cutoff — there are 313
    # ransomware-tagged KEVs total but only ~1 in any given 30-item window.
    kev_limit = 300 if state.query_keywords else 30

    # `return_exceptions=True` widens each result to `T | BaseException`;
    # annotations help mypy narrow on the isinstance checks below.
    try:
        kev_items: list[ThreatFeedItem] | BaseException
        gn_items: list[ThreatFeedItem] | BaseException
        kev_items, gn_items = await asyncio.gather(
            _fetch_cisa_kev(limit=kev_limit),
            _fetch_greynoise(greynoise_key),
            return_exceptions=True,
        )

        all_items: list[ThreatFeedItem] = []

        if isinstance(kev_items, BaseException):
            logger.warning("cisa_kev_failed", error=str(kev_items))
        else:
            # Keyword filter now matches on tags as well as title/description.
            # KEV entries rarely contain user query terms verbatim in their
            # `vulnerabilityName`; richer metadata (vendor, product, CWE ids,
            # `ransomware` flag) is exposed as tags by `CISAKEVClient`, so
            # `--keywords ransomware` correctly surfaces KEVs flagged with
            # `knownRansomwareCampaignUse == "Known"`.
            if state.query_keywords:
                keywords_lower = [k.lower() for k in state.query_keywords]
                kev_items = [
                    item
                    for item in kev_items
                    if any(
                        kw in item.title.lower()
                        or kw in item.description.lower()
                        or any(kw in tag for tag in item.tags)
                        for kw in keywords_lower
                    )
                ]
            all_items.extend(kev_items[:30])

        if isinstance(gn_items, BaseException):
            logger.warning("greynoise_failed", error=str(gn_items))
        else:
            all_items.extend(gn_items[:20])

        normalized = [normalize_feed_item(f) for f in all_items]
        duration_ms = (time.monotonic() - t0) * 1000

        logger.info(
            "agent_complete",
            agent=agent_name,
            records=len(all_items),
            duration_ms=round(duration_ms, 1),
        )

        result = AgentResult(
            agent_name=agent_name,
            success=True,
            records=normalized,
            items_fetched=len(all_items),
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

    return {"agent_results": [*state.agent_results, result]}


async def _fetch_cisa_kev(limit: int = 30) -> list[ThreatFeedItem]:
    async with CISAKEVClient() as client:
        return await client.fetch_recent_kev(limit=limit)


async def _fetch_greynoise(api_key: str | None) -> list[ThreatFeedItem]:
    if not api_key:
        return []
    async with GreyNoiseClient(api_key=api_key) as client:
        return await client.fetch_gnql_stats(query="tags:malware")
