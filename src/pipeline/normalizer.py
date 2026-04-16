"""
Normalization + dedup pipeline.
Collapses all raw agent records into NormalizedThreat with hash-based dedup.
"""

from __future__ import annotations

from typing import cast

import structlog

from src.models import (
    ATTACKTechnique,
    CVERecord,
    IOCRecord,
    NormalizedThreat,
    Severity,
    ThreatFeedItem,
)
from src.models.threat import IOCType

logger = structlog.get_logger(__name__)


def normalize_cve(cve: CVERecord) -> NormalizedThreat:
    return NormalizedThreat(
        threat_type="cve",
        title=cve.cve_id,
        description=cve.description[:800],
        severity=cve.severity,
        cvss_score=cve.cvss_v3_score,
        sources=[cve.source],
        cve_ids=[cve.cve_id],
        technique_ids=[],
        ioc_values=[],
        affected_products=cve.affected_products[:10],
        tags=cve.cwe_ids[:5],
        references=cve.references[:5],
        first_seen=cve.published,
        last_seen=cve.last_modified,
    )


def normalize_technique(technique: ATTACKTechnique) -> NormalizedThreat:
    return NormalizedThreat(
        threat_type="technique",
        title=f"{technique.technique_id}: {technique.name}",
        description=technique.description[:800],
        severity=Severity.MEDIUM,
        sources=[technique.source],
        cve_ids=[],
        technique_ids=[technique.technique_id],
        ioc_values=[],
        affected_products=technique.platforms[:5],
        tags=[technique.tactic, *technique.data_sources[:3]],
        references=[technique.url] if technique.url else [],
    )


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.UNKNOWN: 0,
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


def ioc_severity(ioc: IOCRecord) -> Severity:
    """Derive severity for an IOC using abuse_score, confidence, and the
    `malicious` flag. Mapping:

      abuse_score >= 90  → CRITICAL
      abuse_score >= 70  → HIGH
      abuse_score >= 40  → MEDIUM
      abuse_score  < 40  → LOW

    Otherwise by confidence:
      confidence >= 0.9  → CRITICAL
      confidence >= 0.7  → HIGH
      confidence >= 0.5  → MEDIUM
      confidence  < 0.5  → LOW

    `malicious=True` floors the result at HIGH so a confirmed-bad indicator
    never lands in LOW/UNKNOWN buckets, even when the provider didn't supply
    an abuse_score and confidence defaulted to 0.5.
    """
    if ioc.abuse_score is not None:
        if ioc.abuse_score >= 90:
            severity = Severity.CRITICAL
        elif ioc.abuse_score >= 70:
            severity = Severity.HIGH
        elif ioc.abuse_score >= 40:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
    else:
        c = ioc.confidence
        if c >= 0.9:
            severity = Severity.CRITICAL
        elif c >= 0.7:
            severity = Severity.HIGH
        elif c >= 0.5:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

    if ioc.malicious and _SEVERITY_RANK[severity] < _SEVERITY_RANK[Severity.HIGH]:
        severity = Severity.HIGH
    return severity


def normalize_ioc(ioc: IOCRecord) -> NormalizedThreat:
    # `ioc_type` is populated explicitly so downstream consumers (VT enrichment,
    # sidecar, breakdown) don't have to fish it out of `tags` anymore. The tag
    # copy is kept for report rendering where plain strings are easier to
    # surface — losing it would churn the markdown output without benefit.
    return NormalizedThreat(
        threat_type="ioc",
        title=f"IOC [{ioc.ioc_type.upper()}]: {ioc.value}",
        description=f"Malicious {ioc.ioc_type} indicator. Tags: {', '.join(ioc.tags)}",
        severity=ioc_severity(ioc),
        sources=list(ioc.sources),
        cve_ids=[],
        technique_ids=[],
        ioc_values=[ioc.value],
        # IOCRecord.ioc_type is a regex-validated `str` that matches the
        # `IOCType` literal values exactly; cast makes the assignment typed.
        ioc_type=cast("IOCType", ioc.ioc_type),
        # Snapshot the provider-original confidence BEFORE enrichment can
        # mutate severity/tags. Lets the IOC sidecar's firewall gate in
        # `scripts/extract_iocs.py` consume raw provider confidence instead
        # of deriving a synthetic value from (possibly enrichment-bumped)
        # severity.
        original_confidence=ioc.confidence,
        affected_products=[],
        tags=list(dict.fromkeys([*ioc.tags, ioc.ioc_type])),
        first_seen=ioc.first_seen,
        last_seen=ioc.last_seen,
    )


def normalize_feed_item(item: ThreatFeedItem) -> NormalizedThreat:
    return NormalizedThreat(
        threat_type="feed_item",
        title=item.title[:200],
        description=item.description[:800],
        severity=item.severity,
        sources=[item.source],
        cve_ids=item.cve_refs,
        technique_ids=[],
        ioc_values=[],
        tags=item.tags,
        references=[item.url],
        first_seen=item.published,
    )


class NormalizationPipeline:
    """
    Normalization + content-hash deduplication.

    Two entry points:

    * `run(...)` — takes raw agent records of every type, normalizes each,
      then dedups. Used by unit tests that exercise the full path in isolation.
    * `dedup(...)` — takes records that are already `NormalizedThreat`
      (as produced by the four ingestion agents) and only dedups. Used by
      the swarm's `normalize` node, which receives pre-normalized records
      inside `AgentResult.records`.
    """

    def run(
        self,
        cves: list[CVERecord],
        techniques: list[ATTACKTechnique],
        iocs: list[IOCRecord],
        feed_items: list[ThreatFeedItem],
    ) -> tuple[list[NormalizedThreat], int]:
        raw: list[NormalizedThreat] = []
        raw.extend(normalize_cve(c) for c in cves)
        raw.extend(normalize_technique(t) for t in techniques)
        raw.extend(normalize_ioc(i) for i in iocs)
        raw.extend(normalize_feed_item(f) for f in feed_items)
        return self.dedup(raw)

    def dedup(
        self,
        normalized_input: list[NormalizedThreat],
    ) -> tuple[list[NormalizedThreat], int]:
        """Deduplicate a list of already-normalized threats by `content_hash`."""
        seen: dict[str, NormalizedThreat] = {}
        dedup_count = 0

        for threat in normalized_input:
            h = threat.content_hash
            existing = seen.get(h)
            if existing is None:
                seen[h] = threat
            else:
                existing.sources = list({*existing.sources, *threat.sources})
                dedup_count += 1

        output = list(seen.values())
        logger.info(
            "normalization_complete",
            raw=len(normalized_input),
            deduplicated=dedup_count,
            output=len(output),
        )
        return output, dedup_count
