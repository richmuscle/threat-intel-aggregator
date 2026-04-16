"""
Unit tests for the reflection agent.

Reflection is deliberately **passive** (see module docstring): it scores
confidence and appends analyst notes, but never triggers re-enrichment or
mutates state outside the report field. These tests lock both halves of
that contract — the annotation behaviour on success, and the no-op safety
on every failure mode (no report / no key / LLM error / missing tool
block).

All network is mocked — no real Anthropic calls.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from src.agents.reflection import reflection_agent
from src.models import CorrelatedIntelReport, SwarmState


def _report(markdown: str = "# existing\n") -> CorrelatedIntelReport:
    return CorrelatedIntelReport(
        report_id="TIA-REFLTEST",
        executive_summary="initial summary",
        critical_findings=["finding-a"],
        threat_clusters=[{"cluster_name": "c1", "severity": "HIGH", "narrative": "n"}],
        severity_breakdown={"HIGH": 1},
        sources_queried=["cve_scraper"],
        markdown_report=markdown,
    )


def _state_with_report(markdown: str = "# existing\n") -> SwarmState:
    return SwarmState(run_id="test-run", report=_report(markdown))


def _cfg(key: str | SecretStr | None = "sk-fake") -> dict:
    return {"configurable": {"anthropic_api_key": key}}


def _mock_client(tool_input: dict | None) -> MagicMock:
    """Build an AsyncAnthropic mock that returns the given tool_input, or no tool_use."""
    if tool_input is None:
        # Response with a non-tool_use block — forces the missing-tool-block path.
        mock_block = MagicMock(type="text")
    else:
        mock_block = MagicMock(type="tool_use", input=tool_input)
    mock_response = MagicMock(content=[mock_block])
    mock_client = MagicMock()
    mock_client.messages.create = AsyncMock(return_value=mock_response)
    return mock_client


# ── Short-circuit paths ───────────────────────────────────────────────────────


class TestReflectionShortCircuits:
    @pytest.mark.asyncio
    async def test_no_report_returns_empty(self) -> None:
        """Without a correlation report, reflection has nothing to score."""
        state = SwarmState(run_id="test-run", report=None)
        result = await reflection_agent(state, _cfg())
        assert result == {}

    @pytest.mark.asyncio
    async def test_no_api_key_returns_empty(self) -> None:
        """Without an Anthropic key, the LLM call is skipped entirely."""
        result = await reflection_agent(_state_with_report(), _cfg(key=None))
        assert result == {}


# ── Happy path ────────────────────────────────────────────────────────────────


class TestReflectionHappyPath:
    @pytest.mark.asyncio
    async def test_appends_reflection_to_markdown(self) -> None:
        tool_payload = {
            "confidence_score": 0.82,
            "gaps_identified": ["missing EPSS data", "no ATT&CK coverage"],
            "analyst_notes": "Solid CVE coverage. IOC layer thin.",
            "low_confidence_clusters": ["c1"],
            "strengthened_findings": ["finding-a backed by 3 sources"],
        }
        with patch(
            "src.agents.reflection.anthropic.AsyncAnthropic",
            return_value=_mock_client(tool_payload),
        ):
            result = await reflection_agent(_state_with_report(), _cfg())

        assert "report" in result
        md = result["report"].markdown_report
        assert "# existing" in md  # original markdown preserved
        assert "## Analyst reflection" in md  # new section appended
        assert "82%" in md  # formatted confidence
        assert "Solid CVE coverage" in md  # analyst_notes rendered
        assert "missing EPSS data" in md  # gaps listed
        assert "finding-a backed by 3 sources" in md  # strengthened findings
        assert "c1" in md  # low-confidence clusters

    @pytest.mark.asyncio
    async def test_gaps_appended_to_executive_summary(self) -> None:
        """Reflection gaps surface on the JSON artifact's executive_summary too."""
        tool_payload = {
            "confidence_score": 0.5,
            "gaps_identified": ["no IOC data", "stale CVE window"],
            "analyst_notes": "Mediocre.",
        }
        with patch(
            "src.agents.reflection.anthropic.AsyncAnthropic",
            return_value=_mock_client(tool_payload),
        ):
            result = await reflection_agent(_state_with_report(), _cfg())

        summary = result["report"].executive_summary
        assert "initial summary" in summary  # original survived
        assert "[Gaps:" in summary  # tag present
        assert "no IOC data" in summary  # first gap inlined

    @pytest.mark.asyncio
    async def test_no_gaps_leaves_summary_unchanged(self) -> None:
        tool_payload = {
            "confidence_score": 0.95,
            "gaps_identified": [],
            "analyst_notes": "Excellent.",
        }
        with patch(
            "src.agents.reflection.anthropic.AsyncAnthropic",
            return_value=_mock_client(tool_payload),
        ):
            result = await reflection_agent(_state_with_report(), _cfg())
        assert result["report"].executive_summary == "initial summary"

    @pytest.mark.asyncio
    async def test_unwraps_secretstr_api_key(self) -> None:
        """Production passes `SecretStr`; reflection must unwrap at the SDK boundary."""
        tool_payload = {"confidence_score": 0.9, "gaps_identified": [], "analyst_notes": "ok"}
        mock_client = _mock_client(tool_payload)
        with patch(
            "src.agents.reflection.anthropic.AsyncAnthropic",
            return_value=mock_client,
        ) as ctor:
            await reflection_agent(_state_with_report(), _cfg(key=SecretStr("sk-real")))
        ctor.assert_called_once_with(api_key="sk-real")


# ── Failure modes (must never raise) ──────────────────────────────────────────


class TestReflectionFailureModes:
    @pytest.mark.asyncio
    async def test_llm_exception_returns_empty(self) -> None:
        """Any LLM error is swallowed — reflection is passive, never blocks the pipeline."""
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(side_effect=RuntimeError("429 Too Many Requests"))
        with patch("src.agents.reflection.anthropic.AsyncAnthropic", return_value=mock_client):
            result = await reflection_agent(_state_with_report(), _cfg())
        assert result == {}

    @pytest.mark.asyncio
    async def test_missing_tool_block_returns_empty(self) -> None:
        """If the LLM didn't emit a tool_use block, reflection leaves the report alone."""
        with patch(
            "src.agents.reflection.anthropic.AsyncAnthropic",
            return_value=_mock_client(None),
        ):
            result = await reflection_agent(_state_with_report(), _cfg())
        assert result == {}
