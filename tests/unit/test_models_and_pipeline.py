"""Unit tests — models and normalization pipeline."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.models import (
    CVERecord,
    ATTACKTechnique,
    IOCRecord,
    NormalizedThreat,
    Severity,
    ThreatFeedItem,
    ThreatSource,
    SwarmState,
    AgentResult,
)
from src.pipeline.normalizer import (
    NormalizationPipeline,
    normalize_cve,
    normalize_ioc,
    normalize_technique,
    normalize_feed_item,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_cve() -> CVERecord:
    return CVERecord(
        cve_id="CVE-2024-12345",
        description="A critical remote code execution vulnerability in ExampleLib.",
        published=datetime(2024, 1, 15, tzinfo=timezone.utc),
        last_modified=datetime(2024, 1, 20, tzinfo=timezone.utc),
        cvss_v3_score=9.8,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_ids=["CWE-78"],
        affected_products=["example:lib:1.0", "example:lib:1.1"],
        references=["https://example.com/advisory"],
        source=ThreatSource.NVD,
    )


@pytest.fixture
def sample_technique() -> ATTACKTechnique:
    return ATTACKTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic="execution",
        description="Adversaries may abuse command interpreters to execute commands.",
        platforms=["Windows", "Linux", "macOS"],
        data_sources=["Process: Process Creation"],
        source=ThreatSource.MITRE_ATTACK,
    )


@pytest.fixture
def sample_ioc() -> IOCRecord:
    return IOCRecord(
        ioc_type="ipv4",
        value="192.168.1.100",
        confidence=0.95,
        malicious=True,
        abuse_score=92,
        tags=["ransomware", "c2"],
        sources=[ThreatSource.ABUSEIPDB],
    )


@pytest.fixture
def sample_feed_item() -> ThreatFeedItem:
    return ThreatFeedItem(
        title="CVE-2024-12345: ExampleLib RCE Actively Exploited",
        description="CISA reports active exploitation of CVE-2024-12345.",
        url="https://www.cisa.gov/kev/CVE-2024-12345",
        published=datetime(2024, 1, 22, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        cve_refs=["CVE-2024-12345"],
        tags=["kev", "actively-exploited"],
        source=ThreatSource.CISA_KEV,
    )


# ── Model tests ───────────────────────────────────────────────────────────────

class TestCVERecord:
    def test_severity_derived_from_score(self, sample_cve: CVERecord) -> None:
        assert sample_cve.severity == Severity.CRITICAL

    def test_severity_high_range(self) -> None:
        cve = CVERecord(
            cve_id="CVE-2024-99999",
            description="High severity.",
            published=datetime.utcnow(),
            last_modified=datetime.utcnow(),
            cvss_v3_score=7.5,
        )
        assert cve.severity == Severity.HIGH

    def test_severity_medium_range(self) -> None:
        cve = CVERecord(
            cve_id="CVE-2024-88888",
            description="Medium severity.",
            published=datetime.utcnow(),
            last_modified=datetime.utcnow(),
            cvss_v3_score=5.0,
        )
        assert cve.severity == Severity.MEDIUM

    def test_severity_unknown_when_no_score(self) -> None:
        cve = CVERecord(
            cve_id="CVE-2024-77777",
            description="No score.",
            published=datetime.utcnow(),
            last_modified=datetime.utcnow(),
        )
        assert cve.severity == Severity.UNKNOWN

    def test_invalid_cve_id_rejected(self) -> None:
        with pytest.raises(ValueError):
            CVERecord(
                cve_id="NOT-A-CVE",
                description="bad",
                published=datetime.utcnow(),
                last_modified=datetime.utcnow(),
            )

    def test_raw_field_excluded_from_serialization(self, sample_cve: CVERecord) -> None:
        data = sample_cve.model_dump()
        assert "raw" not in data


class TestIOCRecord:
    def test_valid_ioc_types(self) -> None:
        for ioc_type in ("ipv4", "ipv6", "domain", "md5", "sha256", "url"):
            ioc = IOCRecord(ioc_type=ioc_type, value="test", sources=[ThreatSource.OTX])
            assert ioc.ioc_type == ioc_type

    def test_invalid_ioc_type_rejected(self) -> None:
        with pytest.raises(ValueError):
            IOCRecord(ioc_type="hostname", value="test")

    def test_confidence_clamped(self) -> None:
        with pytest.raises(ValueError):
            IOCRecord(ioc_type="ipv4", value="1.2.3.4", confidence=1.5)


class TestNormalizedThreat:
    def test_content_hash_is_deterministic(self, sample_cve: CVERecord) -> None:
        n1 = normalize_cve(sample_cve)
        n2 = normalize_cve(sample_cve)
        assert n1.content_hash == n2.content_hash

    def test_same_content_different_source_produces_same_hash(self) -> None:
        cve1 = CVERecord(
            cve_id="CVE-2024-11111",
            description="Test.",
            published=datetime.utcnow(),
            last_modified=datetime.utcnow(),
            source=ThreatSource.NVD,
        )
        cve2 = CVERecord(
            cve_id="CVE-2024-11111",
            description="Test.",
            published=datetime.utcnow(),
            last_modified=datetime.utcnow(),
            source=ThreatSource.MITRE_CVE,
        )
        n1 = normalize_cve(cve1)
        n2 = normalize_cve(cve2)
        assert n1.content_hash == n2.content_hash


# ── Normalization tests ───────────────────────────────────────────────────────

class TestNormalizeCVE:
    def test_maps_cve_id_correctly(self, sample_cve: CVERecord) -> None:
        n = normalize_cve(sample_cve)
        assert "CVE-2024-12345" in n.cve_ids
        assert n.threat_type == "cve"

    def test_severity_preserved(self, sample_cve: CVERecord) -> None:
        n = normalize_cve(sample_cve)
        assert n.severity == Severity.CRITICAL

    def test_cvss_score_preserved(self, sample_cve: CVERecord) -> None:
        n = normalize_cve(sample_cve)
        assert n.cvss_score == 9.8


class TestNormalizeTechnique:
    def test_maps_technique_id(self, sample_technique: ATTACKTechnique) -> None:
        n = normalize_technique(sample_technique)
        assert "T1059" in n.technique_ids
        assert n.threat_type == "technique"

    def test_tactic_in_tags(self, sample_technique: ATTACKTechnique) -> None:
        n = normalize_technique(sample_technique)
        assert "execution" in n.tags


class TestNormalizeIOC:
    def test_critical_from_high_abuse_score(self, sample_ioc: IOCRecord) -> None:
        n = normalize_ioc(sample_ioc)
        assert n.severity == Severity.CRITICAL

    def test_ioc_value_in_record(self, sample_ioc: IOCRecord) -> None:
        n = normalize_ioc(sample_ioc)
        assert "192.168.1.100" in n.ioc_values

    def test_high_severity_from_confidence_0_7(self) -> None:
        ioc = IOCRecord(
            ioc_type="domain",
            value="malicious.example.com",
            confidence=0.7,
            malicious=True,
            sources=[ThreatSource.OTX],
        )
        n = normalize_ioc(ioc)
        # New mapping: confidence >= 0.7 → HIGH; malicious=True floors at HIGH.
        assert n.severity == Severity.HIGH


class TestNormalizationPipeline:
    def test_dedup_identical_cves(self, sample_cve: CVERecord) -> None:
        pipeline = NormalizationPipeline()
        normalized, dedup_count = pipeline.run(
            cves=[sample_cve, sample_cve],
            techniques=[],
            iocs=[],
            feed_items=[],
        )
        assert dedup_count == 1
        assert len(normalized) == 1

    def test_sources_merged_on_dedup(self, sample_cve: CVERecord) -> None:
        cve_nvd = sample_cve.model_copy(update={"source": ThreatSource.NVD})
        cve_mitre = sample_cve.model_copy(update={"source": ThreatSource.MITRE_CVE})
        pipeline = NormalizationPipeline()
        normalized, _ = pipeline.run(
            cves=[cve_nvd, cve_mitre],
            techniques=[],
            iocs=[],
            feed_items=[],
        )
        assert len(normalized) == 1
        assert ThreatSource.NVD in normalized[0].sources
        assert ThreatSource.MITRE_CVE in normalized[0].sources

    def test_different_threats_not_deduped(
        self,
        sample_cve: CVERecord,
        sample_technique: ATTACKTechnique,
        sample_ioc: IOCRecord,
        sample_feed_item: ThreatFeedItem,
    ) -> None:
        pipeline = NormalizationPipeline()
        normalized, dedup_count = pipeline.run(
            cves=[sample_cve],
            techniques=[sample_technique],
            iocs=[sample_ioc],
            feed_items=[sample_feed_item],
        )
        assert dedup_count == 0
        assert len(normalized) == 4

    def test_empty_inputs_return_empty(self) -> None:
        pipeline = NormalizationPipeline()
        normalized, dedup_count = pipeline.run([], [], [], [])
        assert normalized == []
        assert dedup_count == 0


# ── SwarmState tests ──────────────────────────────────────────────────────────

class TestSwarmState:
    def test_total_raw_records_computed(self) -> None:
        state = SwarmState(
            run_id="test-run",
            agent_results=[
                AgentResult(agent_name="a", success=True, items_fetched=10),
                AgentResult(agent_name="b", success=True, items_fetched=25),
            ],
        )
        assert state.total_raw_records == 35

    def test_errors_list_is_mutable(self) -> None:
        state = SwarmState(run_id="test-run")
        updated = state.model_copy(update={"errors": ["something failed"]})
        assert len(updated.errors) == 1
        assert len(state.errors) == 0  # original unchanged
