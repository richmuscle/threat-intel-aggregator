"""Severity mapping rules in src.pipeline.normalizer.ioc_severity.

These tests lock in the contract documented in the docstring:
    abuse_score >= 90 → CRITICAL
    abuse_score >= 70 → HIGH
    abuse_score >= 40 → MEDIUM
    abuse_score  < 40 → LOW
    (no abuse_score) confidence >= 0.9 → CRITICAL
                     confidence >= 0.7 → HIGH
                     confidence >= 0.5 → MEDIUM
                     confidence  < 0.5 → LOW
    malicious=True floors result at HIGH regardless of the above.
"""

from __future__ import annotations

import pytest

from src.models import IOCRecord, Severity, ThreatSource
from src.pipeline.normalizer import ioc_severity, normalize_ioc


def _ioc(**kwargs) -> IOCRecord:
    defaults = {"ioc_type": "ipv4", "value": "1.2.3.4", "sources": [ThreatSource.OTX]}
    defaults.update(kwargs)
    return IOCRecord(**defaults)


class TestAbuseScoreMapping:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (100, Severity.CRITICAL),
            (90, Severity.CRITICAL),
            (89, Severity.HIGH),
            (70, Severity.HIGH),
            (69, Severity.MEDIUM),
            (40, Severity.MEDIUM),
            (39, Severity.LOW),
            (0, Severity.LOW),
        ],
    )
    def test_abuse_score_thresholds(self, score: int, expected: Severity) -> None:
        assert ioc_severity(_ioc(abuse_score=score)) == expected


class TestConfidenceMapping:
    @pytest.mark.parametrize(
        "conf,expected",
        [
            (1.0, Severity.CRITICAL),
            (0.9, Severity.CRITICAL),
            (0.89, Severity.HIGH),
            (0.7, Severity.HIGH),
            (0.69, Severity.MEDIUM),
            (0.5, Severity.MEDIUM),
            (0.49, Severity.LOW),
            (0.0, Severity.LOW),
        ],
    )
    def test_confidence_thresholds(self, conf: float, expected: Severity) -> None:
        assert ioc_severity(_ioc(confidence=conf)) == expected


class TestMaliciousFloor:
    def test_malicious_low_confidence_floors_at_high(self) -> None:
        # confidence 0.3 would map to LOW, but malicious=True floors at HIGH.
        assert ioc_severity(_ioc(confidence=0.3, malicious=True)) == Severity.HIGH

    def test_malicious_does_not_downgrade_critical(self) -> None:
        # confidence 0.95 → CRITICAL; malicious=True must not pull it down.
        assert ioc_severity(_ioc(confidence=0.95, malicious=True)) == Severity.CRITICAL

    def test_malicious_with_abuse_score_medium_floors_high(self) -> None:
        # abuse_score 50 → MEDIUM, malicious floors at HIGH.
        assert ioc_severity(_ioc(abuse_score=50, malicious=True)) == Severity.HIGH


class TestNormalizeIOCEnrichment:
    def test_ioc_type_added_to_tags(self) -> None:
        ioc = _ioc(ioc_type="domain", value="bad.example", tags=["phishing"])
        n = normalize_ioc(ioc)
        assert "domain" in n.tags
        assert "phishing" in n.tags

    def test_ioc_type_tag_not_duplicated(self) -> None:
        # If tags already contains the ioc_type, don't add it twice.
        ioc = _ioc(ioc_type="ipv4", tags=["ipv4", "c2"])
        n = normalize_ioc(ioc)
        assert n.tags.count("ipv4") == 1

    def test_sources_preserved(self) -> None:
        ioc = _ioc(sources=[ThreatSource.OTX, ThreatSource.ABUSEIPDB])
        n = normalize_ioc(ioc)
        assert ThreatSource.OTX in n.sources
        assert ThreatSource.ABUSEIPDB in n.sources

    def test_unknown_severity_no_longer_default(self) -> None:
        # Regression: the old normalizer left many IOCs at UNKNOWN when
        # abuse_score was absent and confidence was mid-range. The new mapping
        # must always produce a non-UNKNOWN severity.
        ioc = _ioc(confidence=0.5)
        assert normalize_ioc(ioc).severity != Severity.UNKNOWN
