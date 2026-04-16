"""
Unit tests for the P1-A / P1-B enrichment contracts:

* `original_confidence` is snapshotted at normalization time (P1-A) so the
  IOC sidecar's firewall gate can see the raw provider value even after
  enrichment has bumped severity.
* `enrichments_applied` acts as a per-agent idempotency marker (P1-B) so a
  second enrichment pass (e.g. a future remediation loop) doesn't double-
  bump severity or duplicate overlay tags.

These are defensive tests — the current graph runs enrichment exactly once
per swarm run. The contracts exist to make that invariant load-bearing
rather than incidental.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.agents.epss_enrichment import epss_enrichment_agent
from src.models import IOCRecord, NormalizedThreat, Severity, SwarmState, ThreatSource
from src.models.threat import EPSSScore
from src.pipeline.normalizer import normalize_ioc

# ── P1-A: original_confidence snapshot ────────────────────────────────────────


class TestOriginalConfidenceSnapshot:
    """`normalize_ioc` must persist the provider-original confidence so the
    sidecar's firewall gate can consume it unchanged after enrichment."""

    def test_high_provider_confidence_snapshotted(self) -> None:
        ioc = IOCRecord(
            ioc_type="ipv4",
            value="1.2.3.4",
            confidence=0.92,
            malicious=True,
            sources=[ThreatSource.OTX],
        )
        n = normalize_ioc(ioc)
        assert n.original_confidence == 0.92

    def test_low_provider_confidence_snapshotted(self) -> None:
        """Even low-confidence IOCs carry their raw value forward."""
        ioc = IOCRecord(
            ioc_type="domain",
            value="noisy.example.com",
            confidence=0.2,
            malicious=False,
            sources=[ThreatSource.OTX],
        )
        n = normalize_ioc(ioc)
        assert n.original_confidence == 0.2

    def test_non_ioc_threats_have_none(self) -> None:
        """CVE/technique/feed_item records don't carry a provider confidence —
        the field stays None for them. The sidecar only ever walks `ioc`-typed
        threats, so this is just a typing-cleanliness check."""
        cve_threat = NormalizedThreat(
            threat_type="cve",
            title="CVE-2024-0001",
            description="-",
            severity=Severity.HIGH,
        )
        assert cve_threat.original_confidence is None


# ── P1-B: enrichments_applied idempotency ─────────────────────────────────────


def _cve_threat(title: str = "CVE-2024-0001") -> NormalizedThreat:
    return NormalizedThreat(
        threat_type="cve",
        title=title,
        description="rce",
        severity=Severity.MEDIUM,
        cve_ids=[title],
    )


class TestEnrichmentsAppliedMarker:
    """`enrichments_applied` is the per-agent idempotency marker."""

    def test_defaults_to_empty_list(self) -> None:
        t = _cve_threat()
        assert t.enrichments_applied == []

    def test_list_is_independent_per_instance(self) -> None:
        """Pydantic `default_factory=list` avoids the mutable-default trap — each
        threat gets its own list, not a shared one."""
        a = _cve_threat("CVE-2024-0001")
        b = _cve_threat("CVE-2024-0002")
        a.enrichments_applied.append("epss")
        assert b.enrichments_applied == []


# ── P1-B end-to-end via epss_enrichment_agent ─────────────────────────────────


class TestEPSSEnrichmentIdempotency:
    """A second EPSS pass on the same SwarmState must not double-bump severity
    or duplicate the `epss-actively-exploited` tag."""

    @pytest.mark.asyncio
    async def test_second_pass_is_noop(self) -> None:
        threat = _cve_threat("CVE-2024-12345")
        state = SwarmState(run_id="test", normalized_threats=[threat])

        # Mock the EPSS client — any CVE in state maps to an actively-exploited
        # score. The second call returns the same data, to isolate the guard.
        score = EPSSScore(
            cve_id="CVE-2024-12345",
            epss=0.95,
            percentile=0.99,
            date="2026-04-16",
        )
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.fetch_scores = AsyncMock(return_value={"CVE-2024-12345": score})
        mock_client.fetch_top_exploited = AsyncMock(return_value=[])

        with patch("src.agents.epss_enrichment.EPSSClient", return_value=mock_client):
            # First pass: applies the overlay.
            await epss_enrichment_agent(state, {"configurable": {}})

        assert threat.enriched_severity == Severity.CRITICAL
        assert "epss-actively-exploited" in threat.enriched_tags
        assert "epss" in threat.enrichments_applied
        tag_count_after_first = threat.enriched_tags.count("epss-actively-exploited")

        with patch("src.agents.epss_enrichment.EPSSClient", return_value=mock_client):
            # Second pass: should no-op because "epss" is in `enrichments_applied`.
            await epss_enrichment_agent(state, {"configurable": {}})

        # Tag wasn't re-appended; severity stayed CRITICAL (no double-bump).
        assert threat.enriched_tags.count("epss-actively-exploited") == tag_count_after_first
        assert threat.enrichments_applied.count("epss") == 1
