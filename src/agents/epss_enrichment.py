"""
EPSS Enrichment Agent — enriches CVEs with exploit probability scores.
Runs in parallel with other ingestion agents.
EPSS >= 0.5 = high probability of active exploitation in the wild.
"""
from __future__ import annotations

import structlog

from src.agents._enrichment_base import EnrichmentResult, enrichment_agent
from src.models import SwarmState
from src.models.threat import EPSSScore, NormalizedThreat, Severity
from src.tools.epss_client import EPSSClient

logger = structlog.get_logger(__name__)


@enrichment_agent("epss_enrichment")
async def epss_enrichment_agent(state: SwarmState, config: dict) -> EnrichmentResult:
    """
    Fetches EPSS scores for all CVEs in current state.
    Upgrades severity of high-EPSS CVEs to CRITICAL via the `enriched_severity`
    overlay. Also pulls the top-exploited list as additional threat records.
    """
    cve_ids = list({cve_id for t in state.normalized_threats for cve_id in t.cve_ids})
    if not cve_ids:
        return None  # no-op: nothing to enrich

    logger.info("agent_start", agent="epss_enrichment", cve_count=len(cve_ids))

    async with EPSSClient() as client:
        scores: dict[str, EPSSScore] = await client.fetch_scores(cve_ids)

    async with EPSSClient() as client:
        top_exploited = await client.fetch_top_exploited(limit=20, threshold=0.7)

    enriched_count = 0
    upgraded_count = 0
    for threat in state.normalized_threats:
        for cve_id in threat.cve_ids:
            score = scores.get(cve_id)
            if not score:
                continue
            enriched_count += 1
            epss_tag = f"epss:{score.epss:.3f}"
            if epss_tag not in threat.enriched_tags:
                threat.enriched_tags.append(epss_tag)
            if score.is_actively_exploited and threat.effective_severity != Severity.CRITICAL:
                threat.enriched_severity = Severity.CRITICAL
                threat.enriched_tags.append("epss-actively-exploited")
                upgraded_count += 1

    new_threats: list[NormalizedThreat] = []
    for score in top_exploited:
        if score.cve_id in cve_ids:
            continue
        new_threats.append(NormalizedThreat(
            threat_type="cve",
            title=f"{score.cve_id} (EPSS: {score.epss:.1%})",
            description=(
                f"Actively exploited CVE with EPSS score {score.epss:.3f} "
                f"(top {(1 - score.percentile) * 100:.0f}% of all CVEs by exploit probability)."
            ),
            severity=Severity.CRITICAL,
            cve_ids=[score.cve_id],
            tags=[
                "epss-actively-exploited",
                f"epss:{score.epss:.3f}",
                f"epss-percentile:{score.percentile:.2f}",
            ],
        ))

    return (
        new_threats,
        enriched_count + len(new_threats),
        {
            "enriched": enriched_count,
            "severity_upgrades": upgraded_count,
            "new_exploited": len(new_threats),
        },
    )
