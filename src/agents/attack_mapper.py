"""ATT&CK Mapper Agent — maps techniques relevant to current threat landscape."""

from __future__ import annotations

import time
from typing import Any

import structlog

from src.models import AgentResult, SwarmState
from src.pipeline.normalizer import normalize_technique
from src.tools import MITREATTACKClient

logger = structlog.get_logger(__name__)

# High-value tactics to always pull
DEFAULT_TACTICS = [
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "lateral-movement",
    "exfiltration",
    "impact",
]


async def attack_mapper_agent(state: SwarmState, config: dict[str, Any]) -> dict[str, Any]:
    """
    LangGraph node: fetches relevant ATT&CK techniques.
    Prioritizes techniques matching query keywords or recent CVE products.
    """
    t0 = time.monotonic()
    agent_name = "attack_mapper"
    settings = config.get("configurable", {})
    platform = settings.get("attack_platform", "Windows")

    logger.info("agent_start", agent=agent_name, platform=platform)

    try:
        async with MITREATTACKClient() as client:
            techniques = await client.fetch_techniques(platform_filter=platform)

        # If keywords provided, filter to relevant techniques
        if state.query_keywords:
            keywords_lower = [k.lower() for k in state.query_keywords]
            techniques = [
                t
                for t in techniques
                if any(kw in t.name.lower() or kw in t.description.lower() for kw in keywords_lower)
            ]

        # Cap at reasonable limit for correlation
        techniques = techniques[:100]
        normalized = [normalize_technique(t) for t in techniques]
        duration_ms = (time.monotonic() - t0) * 1000

        logger.info(
            "agent_complete",
            agent=agent_name,
            records=len(techniques),
            duration_ms=round(duration_ms, 1),
        )

        result = AgentResult(
            agent_name=agent_name,
            success=True,
            records=normalized,
            items_fetched=len(techniques),
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
