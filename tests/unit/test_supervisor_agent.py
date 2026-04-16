"""
Unit tests for the supervisor agent.

The supervisor's output (`swarm_config.activate_agents`) drives the
ingestion + enrichment fan-out in `swarm.py`. These tests cover the three
decision paths: normal LLM-driven routing, degraded fallback on LLM
failure, and the no-keywords / no-key short-circuit.

All network is mocked — no real Anthropic calls.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from src.agents.supervisor import _default_config, supervisor_agent
from src.models import SwarmState


def _state(keywords: list[str] | None = None) -> SwarmState:
    return SwarmState(run_id="test-run", query_keywords=keywords or [])


def _cfg(key: str | SecretStr | None = "sk-fake") -> dict:
    return {"configurable": {"anthropic_api_key": key}}


class TestSupervisorShortCircuit:
    """Paths that deliberately skip the LLM call."""

    @pytest.mark.asyncio
    async def test_no_keywords_returns_default_config(self) -> None:
        result = await supervisor_agent(_state(keywords=[]), _cfg())
        assert result["swarm_config"] == _default_config()

    @pytest.mark.asyncio
    async def test_no_api_key_returns_default_config(self) -> None:
        result = await supervisor_agent(_state(["ransomware"]), _cfg(key=None))
        assert result["swarm_config"] == _default_config()


class TestSupervisorLLMPath:
    """LLM-driven routing — Anthropic client mocked."""

    @pytest.mark.asyncio
    async def test_routes_based_on_keywords(self) -> None:
        """Supervisor's tool output becomes `swarm_config`."""
        tool_payload = {
            "threat_category": "ransomware",
            "activate_agents": ["cve_scraper", "feed_aggregator", "epss"],
            "cve_days_back": 14,
            "ioc_limit": 200,
            "kev_limit": 100,
            "attack_tactics": ["impact", "exfiltration"],
            "reasoning": "Ransomware run — prioritise KEV + EPSS.",
        }
        mock_block = MagicMock(type="tool_use", input=tool_payload)
        mock_response = MagicMock(content=[mock_block])
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)

        with patch("src.agents.supervisor.anthropic.AsyncAnthropic", return_value=mock_client):
            result = await supervisor_agent(_state(["ransomware"]), _cfg())

        assert result["swarm_config"] == tool_payload
        assert result["swarm_config"]["activate_agents"] == [
            "cve_scraper",
            "feed_aggregator",
            "epss",
        ]

    @pytest.mark.asyncio
    async def test_llm_failure_falls_back_to_default(self) -> None:
        """API error must not crash the swarm — default config is returned."""
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(side_effect=RuntimeError("boom"))
        with patch("src.agents.supervisor.anthropic.AsyncAnthropic", return_value=mock_client):
            result = await supervisor_agent(_state(["apt"]), _cfg())
        assert result["swarm_config"] == _default_config()

    @pytest.mark.asyncio
    async def test_unwraps_secretstr_api_key(self) -> None:
        """The `anthropic_api_key` arrives as `SecretStr` in production;
        the agent unwraps before passing to the Anthropic SDK."""
        tool_payload = {
            "threat_category": "apt",
            "activate_agents": ["cve_scraper"],
            "reasoning": "lean APT recon",
        }
        mock_block = MagicMock(type="tool_use", input=tool_payload)
        mock_response = MagicMock(content=[mock_block])
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)

        with patch(
            "src.agents.supervisor.anthropic.AsyncAnthropic",
            return_value=mock_client,
        ) as ctor:
            await supervisor_agent(_state(["apt"]), _cfg(key=SecretStr("sk-real-key")))

        # Anthropic client was instantiated with the raw string, not a SecretStr
        ctor.assert_called_once_with(api_key="sk-real-key")

    @pytest.mark.asyncio
    async def test_missing_tool_block_falls_back(self) -> None:
        """If the LLM didn't return a tool_use block, default config is used."""
        # Response with only a text block — no tool call.
        mock_text = MagicMock(type="text")
        mock_response = MagicMock(content=[mock_text])
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        with patch("src.agents.supervisor.anthropic.AsyncAnthropic", return_value=mock_client):
            result = await supervisor_agent(_state(["phishing"]), _cfg())
        assert result["swarm_config"] == _default_config()


class TestDefaultConfig:
    """The fallback should activate the core ingest agents + epss + gh_advisory."""

    def test_default_activates_core_agents(self) -> None:
        cfg = _default_config()
        activate = set(cfg["activate_agents"])
        for name in ("cve_scraper", "attack_mapper", "ioc_extractor", "feed_aggregator", "epss"):
            assert name in activate, f"default missing core agent: {name}"

    def test_default_has_reasoning(self) -> None:
        """Callers log the reasoning field — must not be empty."""
        assert _default_config()["reasoning"]
