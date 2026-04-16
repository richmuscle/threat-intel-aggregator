"""
VirusTotal Enrichment Agent — enriches IOCs with malware family data.
Free tier: 500 lookups/day, 4 req/min.
Writes to `enriched_*` overlays so the provider-original severity/tags stay
intact and `content_hash` remains valid.
"""
from __future__ import annotations

import structlog

from src.agents._enrichment_base import EnrichmentResult, enrichment_agent
from src.models import SwarmState
from src.models.threat import Severity
from src.tools.base_client import unwrap_secret
from src.tools.virustotal_client import VirusTotalClient

logger = structlog.get_logger(__name__)


@enrichment_agent("virustotal_enrichment")
async def virustotal_enrichment_agent(state: SwarmState, config: dict) -> EnrichmentResult:
    vt_key = unwrap_secret(config.get("configurable", {}).get("virustotal_api_key"))
    if not vt_key:
        return None  # no-op: key not configured

    # `threat.ioc_type` is now a typed Literal (populated by `normalize_ioc`),
    # so downstream consumers no longer fish the type out of `tags`.
    ioc_pairs: list[tuple[str, str]] = []
    for threat in state.normalized_threats:
        if threat.ioc_type is None:
            continue
        for ioc_val in threat.ioc_values:
            ioc_pairs.append((ioc_val, threat.ioc_type))
    if not ioc_pairs:
        return None  # no-op: no IOCs to enrich

    # Free tier: 4 req/min caps real throughput. Skip domains (slower) and
    # sha1 (rarely actionable), cap at 10 lookups per run.
    ioc_pairs = [(v, t) for v, t in ioc_pairs if t in ("ipv4", "sha256", "md5")]

    logger.info("agent_start", agent="virustotal_enrichment", ioc_count=len(ioc_pairs))

    async with VirusTotalClient(api_key=vt_key) as client:
        vt_results = await client.enrich_batch(ioc_pairs, max_lookups=10)

    enriched_count = 0
    for threat in state.normalized_threats:
        for ioc_val in threat.ioc_values:
            report = vt_results.get(ioc_val)
            if not report:
                continue
            enriched_count += 1

            ratio_pct = int(report.detection_ratio * 100)
            threat.enriched_tags.append(f"vt-detection:{ratio_pct}%")
            for family in report.malware_families[:3]:
                threat.enriched_tags.append(f"malware:{family}")

            # Severity overlay — reads `effective_severity` so a prior EPSS
            # upgrade isn't overridden when VT confirms at a lower ratio.
            if report.detection_ratio >= 0.8:
                threat.enriched_severity = Severity.CRITICAL
            elif report.detection_ratio >= 0.5 and threat.effective_severity == Severity.UNKNOWN:
                threat.enriched_severity = Severity.HIGH

    return [], enriched_count, {"enriched": enriched_count}
