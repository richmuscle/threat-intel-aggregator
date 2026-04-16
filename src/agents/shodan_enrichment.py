"""
Shodan Enrichment Agent — internet exposure intelligence.
Runs POST-normalization to enrich critical IPs with port/service/CVE data.
Free tier: conservative 5 lookups max. Paid: increase max_lookups.
"""

from __future__ import annotations

from typing import Any

import structlog

from src.agents._enrichment_base import EnrichmentResult, enrichment_agent
from src.models import SwarmState
from src.models.threat import Severity
from src.tools.base_client import is_valid_ip, unwrap_secret
from src.tools.shodan_client import ShodanClient

logger = structlog.get_logger(__name__)

# Exposed services we flag as CRITICAL when Shodan confirms they're open.
_DANGEROUS_PORTS = {3389, 445, 135, 22, 23, 5900}


@enrichment_agent("shodan_enrichment")
async def shodan_enrichment_agent(state: SwarmState, config: dict[str, Any]) -> EnrichmentResult:
    """
    Enriches the top CRITICAL IPs with Shodan host data.
    Adds open ports, running services, and CVEs on exposed services as
    overlay tags — never mutates `severity`/`tags`/`cve_ids` directly.
    """
    shodan_key = unwrap_secret(config.get("configurable", {}).get("shodan_api_key"))
    if not shodan_key:
        return None  # no-op: key not configured

    # Prioritise by `effective_severity` so EPSS/VT-upgraded IPs are also
    # covered. `is_valid_ip` guards against malformed values before they
    # reach the Shodan URL path.
    critical_ips = [
        ioc
        for threat in state.normalized_threats
        if threat.effective_severity == Severity.CRITICAL
        for ioc in threat.ioc_values
        if is_valid_ip(ioc)
    ][:10]
    if not critical_ips:
        return None

    logger.info("agent_start", agent="shodan_enrichment", ip_count=len(critical_ips))

    async with ShodanClient(api_key=shodan_key) as client:
        api_info = await client.get_api_info()
        scan_credits = api_info.get("scan_credits", 0)
        query_credits = api_info.get("query_credits", 0)
        logger.info("shodan_credits", scan=scan_credits, query=query_credits)

        max_lookups = min(5, query_credits) if query_credits < 10 else 10
        enriched = await client.enrich_critical_ips(critical_ips, max_lookups=max_lookups)

    enriched_count = 0
    for threat in state.normalized_threats:
        # Idempotency guard (P1-B): skip threats we've already overlayed.
        if "shodan" in threat.enrichments_applied:
            continue
        touched = False
        for ioc_val in threat.ioc_values:
            host_data = enriched.get(ioc_val)
            if not host_data:
                continue
            enriched_count += 1
            touched = True
            for port in host_data.get("open_ports", [])[:5]:
                threat.enriched_tags.append(f"port:{port}")
            # Shodan-discovered CVEs live as overlay tags rather than being
            # appended to `cve_ids` — mutating `cve_ids` post-hash would
            # invalidate the content hash and break dedup convergence.
            for cve in host_data.get("cves", [])[:3]:
                threat.enriched_tags.append(f"shodan-cve:{cve}")

            if set(host_data.get("open_ports", [])) & _DANGEROUS_PORTS:
                threat.enriched_severity = Severity.CRITICAL
                threat.enriched_tags.append("shodan-exposed-dangerous-port")
        if touched:
            threat.enrichments_applied.append("shodan")

    return [], enriched_count, {"ips_enriched": enriched_count}
