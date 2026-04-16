"""
Unit tests for `_stratified_sample` — the pure function inside
`correlation_agent` that picks which threats reach the LLM prompt.

Post-H3 the sampler uses `effective_severity` (enrichment-informed view),
applies per-tier quotas with leftover rollover, and round-robins across
`threat_type` inside each tier so no single ingestion source crowds out
the others. This file locks that behaviour against regression.
"""
from __future__ import annotations

import pytest

from src.agents.correlation_agent import MAX_PROMPT_THREATS, _stratified_sample
from src.models import NormalizedThreat, Severity


def _threat(tt: str, sev: Severity, label: str = "") -> NormalizedThreat:
    """Compact constructor for typed threat fixtures."""
    return NormalizedThreat(
        threat_type=tt,  # type: ignore[arg-type]
        title=label or f"{tt}-{sev.value}",
        description="-",
        severity=sev,
    )


class TestStratifiedSample:

    def test_empty_input_returns_empty(self) -> None:
        assert _stratified_sample([], limit=10) == []

    def test_small_input_returns_all_items(self) -> None:
        """When input is smaller than the limit, everything comes through."""
        threats = [_threat("cve", Severity.HIGH) for _ in range(5)]
        result = _stratified_sample(threats, limit=10)
        assert len(result) == 5

    def test_small_input_round_robins_across_types(self) -> None:
        """Under the limit the sampler still distributes across threat_type.

        This is the post-H3 fix — before, a CVE-heavy input under the limit
        came out severity-sorted verbatim and IOCs/techniques got starved.
        """
        # 12 threats, all HIGH: 6 cves, 3 iocs, 2 techniques, 1 feed_item.
        threats = (
            [_threat("cve",       Severity.HIGH) for _ in range(6)]
            + [_threat("ioc",       Severity.HIGH) for _ in range(3)]
            + [_threat("technique", Severity.HIGH) for _ in range(2)]
            + [_threat("feed_item", Severity.HIGH) for _ in range(1)]
        )
        result = _stratified_sample(threats, limit=12)
        assert len(result) == 12
        # At least one of every type present in the input should appear in the
        # first 4 picks — the round-robin guarantees representativeness.
        first_four_types = {t.threat_type for t in result[:4]}
        assert first_four_types == {"cve", "ioc", "technique", "feed_item"}

    def test_respects_severity_priority(self) -> None:
        """CRITICAL items dominate the sample over HIGH/MEDIUM when forced."""
        threats = (
            [_threat("cve", Severity.CRITICAL) for _ in range(10)]
            + [_threat("cve", Severity.HIGH)   for _ in range(50)]
            + [_threat("cve", Severity.MEDIUM) for _ in range(40)]
        )
        result = _stratified_sample(threats, limit=20)
        # With the CRITICAL quota of 50% × 20 = 10 slots, all 10 CRITICAL
        # items should make it in, plus some HIGH/MEDIUM filling remainder.
        critical_count = sum(1 for t in result if t.severity == Severity.CRITICAL)
        assert critical_count == 10

    def test_quota_rollover_when_critical_sparse(self) -> None:
        """Unused CRITICAL slots roll forward to HIGH — never waste budget."""
        # 1 CRITICAL (well below the 50% quota), 50 HIGH available.
        threats = (
            [_threat("cve", Severity.CRITICAL)]
            + [_threat("cve", Severity.HIGH) for _ in range(50)]
        )
        result = _stratified_sample(threats, limit=10)
        assert len(result) == 10
        # All 10 slots filled, not just 1 CRITICAL + 3 HIGH from raw quota.
        sev_counts = {t.severity: 0 for t in result}
        for t in result:
            sev_counts[t.severity] = sev_counts.get(t.severity, 0) + 1
        assert sev_counts.get(Severity.HIGH, 0) >= 9

    def test_uses_effective_severity_not_raw(self) -> None:
        """EPSS-enriched threat should participate at its upgraded tier."""
        raw_medium = _threat("cve", Severity.MEDIUM)
        raw_medium.enriched_severity = Severity.CRITICAL
        other_criticals = [_threat("cve", Severity.CRITICAL) for _ in range(3)]
        other_lows      = [_threat("cve", Severity.LOW)      for _ in range(20)]
        result = _stratified_sample([raw_medium, *other_criticals, *other_lows], limit=5)
        # The enriched record must appear in the sample — its effective
        # severity puts it in the CRITICAL tier regardless of raw severity.
        assert raw_medium in result

    def test_caps_at_limit(self) -> None:
        """Sample size is never larger than `limit`."""
        threats = [_threat("cve", Severity.HIGH) for _ in range(200)]
        result = _stratified_sample(threats, limit=MAX_PROMPT_THREATS)
        assert len(result) == MAX_PROMPT_THREATS

    def test_respects_custom_limit(self) -> None:
        threats = [_threat("cve", Severity.HIGH) for _ in range(100)]
        assert len(_stratified_sample(threats, limit=25)) == 25
        assert len(_stratified_sample(threats, limit=5))  == 5
