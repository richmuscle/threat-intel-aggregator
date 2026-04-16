"""
GitHub Advisory Agent — supply chain CVE context.
No API key required (token raises rate limits). Pairs with NVD CVEs to add
package-level actionability via the `enriched_*` overlay pattern.
"""

from __future__ import annotations

from typing import Any

import structlog

from src.agents._enrichment_base import EnrichmentResult, enrichment_agent
from src.models import SwarmState
from src.models.threat import NormalizedThreat
from src.tools.base_client import unwrap_secret
from src.tools.github_advisory_client import GitHubAdvisoryClient

logger = structlog.get_logger(__name__)


@enrichment_agent("github_advisory")
async def github_advisory_agent(state: SwarmState, config: dict[str, Any]) -> EnrichmentResult:
    gh_token = unwrap_secret(config.get("configurable", {}).get("github_token"))  # optional

    cve_ids = list({cve_id for threat in state.normalized_threats for cve_id in threat.cve_ids})
    if not cve_ids:
        return None

    logger.info("agent_start", agent="github_advisory", cve_count=len(cve_ids))

    async with GitHubAdvisoryClient(api_key=gh_token) as client:
        advisory_map = await client.fetch_advisories_for_cves(cve_ids[:20])
        recent = await client.fetch_recent_advisories(severity="critical", limit=20)

    # Enrich existing threats via overlays. Never mutates `affected_products`
    # directly — those become `pkg:`/`patched:`/`ghsa:` entries in
    # `enriched_tags`, preserving content_hash determinism.
    enriched = 0
    for threat in state.normalized_threats:
        for cve_id in threat.cve_ids:
            advisory = advisory_map.get(cve_id)
            if not advisory:
                continue
            enriched += 1
            for pkg in advisory.affected_packages[:3]:
                threat.enriched_tags.append(f"pkg:{pkg}")
            if advisory.patched_versions:
                threat.enriched_tags.append(f"patched:{advisory.patched_versions[0]}")
            if advisory.ghsa_id:
                threat.enriched_tags.append(f"ghsa:{advisory.ghsa_id}")

    # Recent critical advisories become new threat records — dedup against
    # existing CVEs runs in the post-enrichment pass inside `_enrichment_node`.
    known_cves = {cve_id for threat in state.normalized_threats for cve_id in threat.cve_ids}
    new_threats: list[NormalizedThreat] = [
        NormalizedThreat(
            threat_type="cve",
            title=f"{adv.cve_id or adv.ghsa_id}: {adv.summary[:80]}",
            description=adv.summary,
            severity=adv.severity,
            cve_ids=[adv.cve_id] if adv.cve_id else [],
            affected_products=adv.affected_packages[:5],
            tags=[f"ghsa:{adv.ghsa_id}"] + [f"pkg:{p}" for p in adv.affected_packages[:3]],
            references=adv.references[:3],
        )
        for adv in recent
        if adv.cve_id and adv.cve_id not in known_cves
    ]

    return (
        new_threats,
        enriched + len(new_threats),
        {"enriched": enriched, "new_advisories": len(new_threats)},
    )
