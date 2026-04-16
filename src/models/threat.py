"""
Core threat intelligence data models.
All inter-agent data passes through these schemas — no loose dicts anywhere.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field, model_validator

# ── Discriminated-union labels ────────────────────────────────────────────────
#
# `ThreatType` is the four-value domain of `NormalizedThreat.threat_type`.
# Defined as a `Literal` (not an `Enum`) so branching code like
# `if t.threat_type == "ioc"` narrows statically under mypy — no `.value`
# call sites to churn.
#
# `IOCType` is the eight-value domain of IOC type strings that already regex-
# match in `IOCRecord.ioc_type`. Promoting the string literal to a declared
# `Literal` lets consumers read it as a typed field instead of fishing it
# out of `tags` with a set-membership check.

ThreatType = Literal["cve", "technique", "ioc", "feed_item"]
IOCType = Literal["ipv4", "ipv6", "domain", "md5", "sha1", "sha256", "url", "email"]


# `StrEnum` (Python 3.11+) replaces the older `class X(str, Enum)` mixin:
# `str(Severity.CRITICAL)` now returns `"CRITICAL"` instead of the
# `"Severity.CRITICAL"` name-qualified form. `.value` access and equality
# against raw strings stay unchanged, which is the whole migration API-
# compatibility story. See `pyproject.toml` — UP042 is now satisfied.
class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class ThreatSource(StrEnum):
    NVD = "NVD"
    MITRE_CVE = "MITRE_CVE"
    MITRE_ATTACK = "MITRE_ATTACK"
    OTX = "OTX"
    ABUSEIPDB = "ABUSEIPDB"
    CISA_KEV = "CISA_KEV"
    GREYNOISE = "GREYNOISE"
    RSS_FEED = "RSS_FEED"
    VENDOR_ADVISORY = "VENDOR_ADVISORY"


# ─── Agent-specific raw models ────────────────────────────────────────────────


class CVERecord(BaseModel):
    """Raw CVE data from NVD / MITRE CVE feeds."""

    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")
    description: str
    published: datetime
    last_modified: datetime
    cvss_v3_score: float | None = Field(None, ge=0.0, le=10.0)
    cvss_v3_vector: str | None = None
    severity: Severity = Severity.UNKNOWN
    cwe_ids: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    source: ThreatSource = ThreatSource.NVD
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    @model_validator(mode="after")
    def derive_severity_from_score(self) -> CVERecord:
        if self.severity != Severity.UNKNOWN:
            return self
        score = self.cvss_v3_score
        if score is None:
            return self
        if score >= 9.0:
            self.severity = Severity.CRITICAL
        elif score >= 7.0:
            self.severity = Severity.HIGH
        elif score >= 4.0:
            self.severity = Severity.MEDIUM
        else:
            self.severity = Severity.LOW
        return self


class ATTACKTechnique(BaseModel):
    """MITRE ATT&CK technique / sub-technique."""

    technique_id: str = Field(..., pattern=r"^T\d{4}(\.\d{3})?$")
    name: str
    tactic: str
    description: str
    platforms: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    detection_hints: list[str] = Field(default_factory=list)
    url: str = ""
    source: ThreatSource = ThreatSource.MITRE_ATTACK


class IOCRecord(BaseModel):
    """Indicator of Compromise — IP, domain, file hash, URL."""

    ioc_type: str = Field(..., pattern=r"^(ipv4|ipv6|domain|md5|sha1|sha256|url|email)$")
    value: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    malicious: bool = False
    tags: list[str] = Field(default_factory=list)
    country: str | None = None
    asn: str | None = None
    abuse_score: int | None = Field(None, ge=0, le=100)
    pulse_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sources: list[ThreatSource] = Field(default_factory=list)


class ThreatFeedItem(BaseModel):
    """Generic threat feed item from CISA KEV, GreyNoise, or RSS."""

    title: str
    description: str
    url: str
    published: datetime
    severity: Severity = Severity.UNKNOWN
    cve_refs: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    source: ThreatSource = ThreatSource.RSS_FEED


# ─── Normalized cross-source model ────────────────────────────────────────────


class NormalizedThreat(BaseModel):
    """
    Canonical representation after normalization.
    All raw records collapse into this schema before correlation.
    """

    content_hash: str = ""  # populated by pipeline
    threat_type: ThreatType
    title: str
    description: str
    severity: Severity
    cvss_score: float | None = None
    sources: list[ThreatSource] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    ioc_values: list[str] = Field(default_factory=list)
    # Set by `normalize_ioc` for `threat_type == "ioc"` records. Remains
    # `None` for CVE / technique / feed_item rows. Consumers that previously
    # fished the type out of `tags` (VT enrichment, sidecar, report break-
    # downs) now read it directly — no substring-matching hack.
    ioc_type: IOCType | None = None
    # Provider-original IOC confidence (`IOCRecord.confidence`, 0.0-1.0)
    # snapshot at normalization time. Populated only for `threat_type == "ioc"`.
    # Downstream consumers that need the *raw* confidence — e.g. the IOC
    # sidecar's firewall/DNS-block gate in `scripts/extract_iocs.py` — read
    # this instead of deriving from `effective_severity`, which would reflect
    # post-enrichment severity bumps (EPSS/VT/Shodan) rather than the original
    # provider signal.
    original_confidence: float | None = None
    affected_products: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    raw_ids: list[str] = Field(default_factory=list)
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # ── Enrichment overlay (immutable-enrichment pattern) ──────────────────
    # Enrichment agents (EPSS, VirusTotal, Shodan, GitHub Advisory) never
    # mutate `severity` or `tags` directly. They write overlays here so the
    # original provider-sourced values stay intact and the `content_hash`
    # below remains valid. Consumers that want the post-enrichment view read
    # `effective_severity` / `effective_tags`; consumers that want the raw
    # provider view (e.g. the IOC sidecar's "original confidence" gate) can
    # still read `severity` / `tags`.
    enriched_severity: Severity | None = None
    enriched_tags: list[str] = Field(default_factory=list)
    # Per-agent idempotency marker — agents that have already applied their
    # overlay to this threat add their name here and skip on re-entry. The
    # graph runs enrichment once today (the DAG has no loop back into
    # `enrich`), but the flag makes a future remediation loop safe:
    # double-bumps from a second EPSS pass would otherwise be non-obvious.
    # Names are stable strings matching the `@enrichment_agent(name=...)`
    # decorator argument.
    enrichments_applied: list[str] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def effective_severity(self) -> Severity:
        """Return the enrichment-adjusted severity if set, else the original."""
        return self.enriched_severity or self.severity

    @computed_field  # type: ignore[prop-decorator]
    @property
    def effective_tags(self) -> list[str]:
        """Return `tags + enriched_tags` with duplicates dropped, order preserved."""
        return list(dict.fromkeys([*self.tags, *self.enriched_tags]))

    def compute_hash(self) -> str:
        """Deterministic content hash for deduplication.

        Intentionally excludes `severity`, `tags`, `enriched_*` — the hash is
        a record-identity fingerprint (what is this threat?), not a state
        fingerprint (what do we know about it right now?). Enrichment
        mutations must not shift the hash or dedup would stop converging.
        """
        key = json.dumps(
            {
                "title": self.title.lower().strip(),
                "cve_ids": sorted(self.cve_ids),
                "technique_ids": sorted(self.technique_ids),
                "ioc_values": sorted(self.ioc_values),
            },
            sort_keys=True,
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def model_post_init(self, __context: Any) -> None:
        if not self.content_hash:
            self.content_hash = self.compute_hash()


# ─── LLM correlation output ───────────────────────────────────────────────────


class CorrelatedIntelReport(BaseModel):
    """Structured output from the LLM correlation agent."""

    report_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    executive_summary: str
    critical_findings: list[str] = Field(default_factory=list)
    threat_clusters: list[dict[str, Any]] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    siem_alerts: list[dict[str, Any]] = Field(default_factory=list)
    total_threats_processed: int = 0
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    sources_queried: list[str] = Field(default_factory=list)
    markdown_report: str = ""


# ─── Swarm state (LangGraph StateGraph node) ─────────────────────────────────


class AgentResult(BaseModel):
    """Result envelope for each parallel agent."""

    agent_name: str
    success: bool
    records: list[NormalizedThreat] = Field(default_factory=list)
    error: str | None = None
    duration_ms: float = 0.0
    items_fetched: int = 0


class SwarmState(BaseModel):
    """
    LangGraph state — flows through every node in the DAG.
    Immutable fields set at init; mutable fields accumulated by agents.
    """

    run_id: str
    triggered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # set by orchestrator
    query_keywords: list[str] = Field(default_factory=list)
    max_cves: int = 50
    max_iocs: int = 100

    # accumulated by parallel agents
    agent_results: list[AgentResult] = Field(default_factory=list)

    # set by normalization pipeline
    normalized_threats: list[NormalizedThreat] = Field(default_factory=list)
    raw_iocs: list[IOCRecord] = Field(default_factory=list)
    dedup_removed: int = 0

    # set by correlation agent
    report: CorrelatedIntelReport | None = None

    # supervisor routing config (set by supervisor agent)
    swarm_config: dict[str, Any] = Field(default_factory=dict)

    # run metadata
    errors: list[str] = Field(default_factory=list)
    completed: bool = False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_raw_records(self) -> int:
        return sum(r.items_fetched for r in self.agent_results)


# ─── V2 enrichment models ─────────────────────────────────────────────────────


class EPSSScore(BaseModel):
    """FIRST.org Exploit Prediction Scoring System score for a CVE."""

    cve_id: str
    epss: float = Field(ge=0.0, le=1.0)
    percentile: float = Field(ge=0.0, le=1.0)
    date: str = ""

    @property
    def is_actively_exploited(self) -> bool:
        return self.epss >= 0.5


class VTReport(BaseModel):
    """VirusTotal enrichment for an IOC."""

    ioc_value: str
    ioc_type: str
    malicious_count: int = 0
    total_engines: int = 0
    malware_families: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    last_analysis_date: datetime | None = None

    @property
    def detection_ratio(self) -> float:
        if self.total_engines == 0:
            return 0.0
        return self.malicious_count / self.total_engines


class GHAdvisory(BaseModel):
    """GitHub Advisory Database entry."""

    ghsa_id: str
    cve_id: str | None = None
    summary: str
    severity: Severity = Severity.UNKNOWN
    affected_packages: list[str] = Field(default_factory=list)
    patched_versions: list[str] = Field(default_factory=list)
    published_at: datetime | None = None
    references: list[str] = Field(default_factory=list)
    source: ThreatSource = ThreatSource.VENDOR_ADVISORY
