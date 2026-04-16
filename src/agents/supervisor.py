"""
Supervisor Agent — dynamic swarm routing.
Analyzes keywords and decides which agents to activate and with what parameters.
Runs BEFORE the parallel ingest fan-out.
Example: "LockBit" → activate ransomware IOC mode, increase KEV limit, focus ATT&CK on impact tactics.
"""

from __future__ import annotations

import time
from typing import Any

import anthropic
import structlog

from src.models import SwarmState
from src.tools.base_client import unwrap_secret

logger = structlog.get_logger(__name__)

SUPERVISOR_TOOL = {
    "name": "configure_swarm",
    "description": "Configure which agents to activate and their parameters based on threat keywords.",
    "input_schema": {
        "type": "object",
        "properties": {
            "threat_category": {
                "type": "string",
                "enum": [
                    "ransomware",
                    "apt",
                    "phishing",
                    "supply_chain",
                    "infrastructure",
                    "generic",
                ],
                "description": "Primary threat category inferred from keywords.",
            },
            "activate_agents": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of agents to activate: cve_scraper, attack_mapper, ioc_extractor, feed_aggregator, epss, virustotal, github_advisory, shodan",
            },
            "cve_days_back": {
                "type": "integer",
                "description": "How many days back to fetch CVEs. Increase for broad searches.",
            },
            "attack_tactics": {
                "type": "array",
                "items": {"type": "string"},
                "description": "MITRE ATT&CK tactics to focus on.",
            },
            "ioc_limit": {
                "type": "integer",
                "description": "Max IOCs to fetch.",
            },
            "kev_limit": {
                "type": "integer",
                "description": "Max KEV entries to fetch.",
            },
            "reasoning": {
                "type": "string",
                "description": "Brief explanation of routing decisions.",
            },
        },
        "required": ["threat_category", "activate_agents", "reasoning"],
    },
}


async def supervisor_agent(state: SwarmState, config: dict[str, Any]) -> dict[str, Any]:
    """
    Pre-ingest supervisor — configures swarm routing based on query analysis.
    Falls back to default full-swarm config if LLM call fails.
    """
    t0 = time.monotonic()
    settings = config.get("configurable", {})
    api_key = unwrap_secret(settings.get("anthropic_api_key"))

    if not state.query_keywords or not api_key:
        # No keywords or no key — run full swarm with defaults
        return {"swarm_config": _default_config()}

    keywords = ", ".join(state.query_keywords)
    logger.info("supervisor_start", keywords=keywords)

    try:
        client = anthropic.AsyncAnthropic(api_key=api_key)
        model = settings.get("llm_model", "claude-opus-4-20250514")
        # See correlation_agent for the SDK-TypedDict overload suppression rationale.
        response = await client.messages.create(  # type: ignore[call-overload]
            model=model,
            max_tokens=512,
            tools=[SUPERVISOR_TOOL],
            tool_choice={"type": "tool", "name": "configure_swarm"},
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"Configure a threat intelligence swarm for these keywords: {keywords}\n\n"
                        "Available agents: cve_scraper (NVD CVEs), attack_mapper (MITRE ATT&CK), "
                        "ioc_extractor (OTX+AbuseIPDB), feed_aggregator (CISA KEV), "
                        "epss (exploit probability), virustotal (malware families), "
                        "github_advisory (supply chain), shodan (exposed services)\n\n"
                        "Configure parameters to maximise signal for these specific keywords. "
                        "For ransomware: activate all agents, focus on impact/exfiltration tactics. "
                        "For APT: increase CVE lookback, focus on persistence/lateral-movement. "
                        "For supply chain: prioritise github_advisory and CVE scraper."
                    ),
                }
            ],
        )

        tool_block = next((b for b in response.content if b.type == "tool_use"), None)
        if tool_block:
            cfg = tool_block.input
            logger.info(
                "supervisor_complete",
                category=cfg.get("threat_category"),
                agents=cfg.get("activate_agents"),
                reasoning=cfg.get("reasoning", "")[:100],
                duration_ms=round((time.monotonic() - t0) * 1000, 1),
            )
            return {"swarm_config": cfg}

    except Exception as exc:
        logger.warning("supervisor_failed_using_defaults", error=str(exc))

    return {"swarm_config": _default_config()}


def _default_config() -> dict[str, Any]:
    return {
        "threat_category": "generic",
        "activate_agents": [
            "cve_scraper",
            "attack_mapper",
            "ioc_extractor",
            "feed_aggregator",
            "epss",
            "github_advisory",
        ],
        "cve_days_back": 7,
        "ioc_limit": 100,
        "kev_limit": 50,
        "attack_tactics": [],
        "reasoning": "Default full-swarm configuration.",
    }
