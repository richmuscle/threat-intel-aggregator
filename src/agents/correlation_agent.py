"""
Correlation Agent — Claude-powered cross-source enrichment and clustering.
Uses structured tool calls, not free-text prompting.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

import anthropic
import structlog

from src.models import (
    CorrelatedIntelReport,
    NormalizedThreat,
    Severity,
    SwarmState,
)
from src.tools.base_client import unwrap_secret

# Keep enough room for Claude's response within the 200k-token window.
MAX_PROMPT_THREATS = 80

# Severity ordering for prioritisation — CRITICAL first, UNKNOWN last.
_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
)

# Quota per severity tier as a fraction of MAX_PROMPT_THREATS. CRITICAL and
# HIGH get the lion's share; lower tiers get a small sample so Claude still
# sees the long-tail shape without flooding the prompt.
_TIER_QUOTA: dict[Severity, float] = {
    Severity.CRITICAL: 0.50,
    Severity.HIGH: 0.30,
    Severity.MEDIUM: 0.12,
    Severity.LOW: 0.05,
    Severity.INFO: 0.02,
    Severity.UNKNOWN: 0.01,
}

logger = structlog.get_logger(__name__)

# Structured output tool definition — forces Claude to return typed JSON
CORRELATION_TOOL = {
    "name": "produce_intel_report",
    "description": "Produce a structured threat intelligence correlation report.",
    "input_schema": {
        "type": "object",
        "properties": {
            "executive_summary": {
                "type": "string",
                "description": "3-5 sentence executive summary of the current threat landscape.",
            },
            "critical_findings": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Top 5 critical findings requiring immediate attention.",
            },
            "threat_clusters": {
                "type": "array",
                "description": "Groups of related threats that share TTPs, CVEs, or IOCs.",
                "items": {
                    "type": "object",
                    "properties": {
                        "cluster_name": {"type": "string"},
                        "severity": {
                            "type": "string",
                            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        },
                        "threat_ids": {"type": "array", "items": {"type": "string"}},
                        "narrative": {"type": "string"},
                        "mitre_techniques": {"type": "array", "items": {"type": "string"}},
                        "cve_ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["cluster_name", "severity", "narrative"],
                },
            },
            "recommended_actions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Prioritized remediation and detection actions.",
            },
            "siem_alerts": {
                "type": "array",
                "description": "Structured alerts ready for SIEM ingestion (ECS-aligned).",
                "items": {
                    "type": "object",
                    "properties": {
                        "alert_id": {"type": "string"},
                        "rule_name": {"type": "string"},
                        "severity": {"type": "string"},
                        "description": {"type": "string"},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "mitre_technique": {"type": "string"},
                        "cve_ref": {"type": "string"},
                    },
                    "required": ["rule_name", "severity", "description"],
                },
            },
        },
        "required": [
            "executive_summary",
            "critical_findings",
            "threat_clusters",
            "recommended_actions",
            "siem_alerts",
        ],
    },
}


def _stratified_sample(
    threats: list[NormalizedThreat],
    limit: int = MAX_PROMPT_THREATS,
) -> list[NormalizedThreat]:
    """
    Pick up to `limit` threats for the LLM prompt using a two-stage strategy:

    1. Bucket every threat by severity tier (CRITICAL → UNKNOWN).
    2. Inside each tier, take threats in round-robin order across
       `threat_type` (cve / technique / ioc / feed_item) so no single
       ingestion source crowds out the others.

    Tier quotas (`_TIER_QUOTA`) set *targets*, not caps — when a tier has
    fewer items than its target, the leftover budget rolls into the next
    tier so we always fill up to `limit` when enough threats exist.

    The round-robin runs *regardless of input size* — a 50-threat run
    dominated by CVEs used to reach Claude as 45 CVEs + 5 IOCs because the
    old short-circuit returned the severity-sorted input verbatim. Now the
    same 50-threat run surfaces at least one of each threat_type present.
    """
    if not threats:
        return []

    # Effective cap: whichever is smaller — the prompt limit or the input size.
    effective_limit = min(limit, len(threats))

    by_tier: dict[Severity, list[NormalizedThreat]] = defaultdict(list)
    for t in threats:
        by_tier[t.effective_severity].append(t)

    picked: list[NormalizedThreat] = []
    leftover = 0
    for tier in _SEVERITY_ORDER:
        tier_threats = by_tier.get(tier, [])
        if not tier_threats:
            leftover += int(_TIER_QUOTA[tier] * effective_limit)
            continue

        target = int(_TIER_QUOTA[tier] * effective_limit) + leftover
        target = min(target, len(tier_threats))
        leftover = int(_TIER_QUOTA[tier] * effective_limit) - target + leftover
        if leftover < 0:
            leftover = 0

        # Round-robin across threat types to keep the sample representative.
        by_type: dict[str, list[NormalizedThreat]] = defaultdict(list)
        for t in tier_threats:
            by_type[t.threat_type].append(t)

        type_queues = list(by_type.values())
        selected: list[NormalizedThreat] = []
        while len(selected) < target and any(type_queues):
            for q in type_queues:
                if not q or len(selected) >= target:
                    continue
                selected.append(q.pop(0))
            type_queues = [q for q in type_queues if q]
        picked.extend(selected)

        if len(picked) >= effective_limit:
            break

    # Fill any leftover budget with remaining threats, preferring the highest
    # severity tier that still has capacity — protects against quota rounding
    # leaving CRITICAL/HIGH slots empty when lower tiers are sparse.
    if len(picked) < effective_limit:
        picked_ids = {id(t) for t in picked}
        remaining = [t for t in threats if id(t) not in picked_ids]
        remaining.sort(key=lambda t: _SEVERITY_ORDER.index(t.effective_severity))
        picked.extend(remaining[: effective_limit - len(picked)])

    return picked[:effective_limit]


def _build_prompt(threats: list[NormalizedThreat], run_id: str) -> str:
    # Use `effective_severity` so enrichment upgrades (EPSS flag, VT ratio,
    # Shodan dangerous-port exposure) shape the prompt — Claude should see
    # the enrichment-informed picture, not the raw provider-sourced one.
    severity_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    for t in threats:
        sev = t.effective_severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        type_counts[t.threat_type] = type_counts.get(t.threat_type, 0) + 1

    sampled = _stratified_sample(threats, limit=MAX_PROMPT_THREATS)

    threat_summaries = "\n".join(
        f"- [{t.threat_type.upper()}] {t.title} | {t.effective_severity.value} | "
        f"CVEs: {','.join(t.cve_ids[:3]) or 'none'} | "
        f"TTPs: {','.join(t.technique_ids[:3]) or 'none'} | "
        f"IOCs: {','.join(t.ioc_values[:2]) or 'none'}"
        for t in sampled
    )

    return (
        f"You are a senior threat intelligence analyst. Analyze the following normalized "
        f"threat intelligence data from run {run_id}.\n\n"
        f"SEVERITY BREAKDOWN: {json.dumps(severity_counts)}\n"
        f"THREAT TYPE BREAKDOWN: {json.dumps(type_counts)}\n"
        f"TOTAL THREATS: {len(threats)}  (sampled {len(sampled)} for this prompt)\n\n"
        f"THREAT DATA:\n{threat_summaries}\n\n"
        "Correlate these threats across sources. Identify clusters of related activity, "
        "critical vulnerabilities requiring urgent patching, and active IOCs.\n"
        "Produce SIEM-ready alerts aligned with Elastic Common Schema conventions.\n"
        "Focus on actionable intelligence — avoid generic advice.\n\n"
        "Patch priority: when recommending remediation, explicitly call out the highest-\n"
        "CVSS CVEs by ID ordered worst-first; downstream tooling will cross-reference\n"
        "those IDs against the NVD CVSS table for a sorted patch table. When an IOC\n"
        "has type domain or ipv4, include it verbatim in a relevant cluster's\n"
        "threat_ids so firewall/DNS blocking tooling picks it up."
    )


async def correlation_agent(state: SwarmState, config: dict[str, Any]) -> dict[str, Any]:
    """
    LangGraph node: LLM-powered correlation over all normalized threats.
    Uses Claude structured tool calls for typed output — no JSON parsing hacks.
    """
    t0 = time.monotonic()
    agent_name = "correlation_agent"
    settings = config.get("configurable", {})
    anthropic_api_key = unwrap_secret(settings.get("anthropic_api_key"))

    if not state.normalized_threats:
        logger.warning("no_threats_to_correlate", agent=agent_name)
        return {"errors": [*state.errors, "correlation_agent: no normalized threats"]}

    logger.info(
        "agent_start",
        agent=agent_name,
        threat_count=len(state.normalized_threats),
    )

    try:
        client = anthropic.AsyncAnthropic(api_key=anthropic_api_key)
        model = settings.get("llm_model", "claude-opus-4-20250514")

        # `tools` / `tool_choice` are TypedDict params in the Anthropic SDK;
        # our dict literals are structurally valid but don't satisfy the SDK's
        # overload resolver. Suppressing at the call — alternative is to
        # import `ToolParam` / `ToolChoiceToolParam` solely for annotation.
        response = await client.messages.create(  # type: ignore[call-overload]
            model=model,
            max_tokens=4096,
            tools=[CORRELATION_TOOL],
            tool_choice={"type": "tool", "name": "produce_intel_report"},
            messages=[
                {
                    "role": "user",
                    "content": _build_prompt(state.normalized_threats, state.run_id),
                }
            ],
        )

        # Extract structured tool call result
        tool_block = next(
            (b for b in response.content if b.type == "tool_use"),
            None,
        )
        if not tool_block:
            raise ValueError("LLM did not return tool_use block")

        payload: dict[str, Any] = tool_block.input
        severity_breakdown = {
            s.value: sum(1 for t in state.normalized_threats if t.effective_severity == s)
            for s in Severity
        }

        report = CorrelatedIntelReport(
            report_id=f"TIA-{state.run_id[:8].upper()}",
            generated_at=datetime.now(UTC),
            executive_summary=payload["executive_summary"],
            critical_findings=payload["critical_findings"],
            threat_clusters=payload["threat_clusters"],
            recommended_actions=payload["recommended_actions"],
            siem_alerts=payload["siem_alerts"],
            total_threats_processed=len(state.normalized_threats),
            severity_breakdown=severity_breakdown,
            sources_queried=[r.agent_name for r in state.agent_results if r.success],
        )

        duration_ms = (time.monotonic() - t0) * 1000
        logger.info(
            "agent_complete",
            agent=agent_name,
            clusters=len(report.threat_clusters),
            siem_alerts=len(report.siem_alerts),
            duration_ms=round(duration_ms, 1),
        )

        return {"report": report}

    except Exception as exc:
        duration_ms = (time.monotonic() - t0) * 1000
        logger.error("agent_failed", agent=agent_name, error=str(exc))
        return {"errors": [*state.errors, f"correlation_agent: {exc}"]}
