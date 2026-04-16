"""
Reflection Agent — **passive** post-correlation quality scorer.

Scores report confidence (0-1), identifies gaps, flags low-confidence
clusters, and appends analyst notes to the report's markdown + executive
summary. Explicitly does **not** trigger re-enrichment or re-ingestion when
confidence is low — this is diagnostic, not remedial.

Non-goal (deliberate): a conditional-edge loop back into `enrich` when
`confidence_score < 0.6`. Such a loop would make run cost non-deterministic
(one extra Opus call per re-enrichment pass, plus duplicated external API
spend) and complicate the dedup story — enrichment agents already mutate
`NormalizedThreat` overlays in place, so a second enrichment pass would see
already-enriched records and the idempotency of severity/tag overlays is
not currently guaranteed. If remediation-on-low-confidence is ever wanted,
model it as a separate driver (e.g. cron re-run with widened keywords),
not an in-graph loop.
"""

from __future__ import annotations

import time
from typing import Any

import anthropic
import structlog

from src.models import SwarmState
from src.tools.base_client import unwrap_secret

logger = structlog.get_logger(__name__)

REFLECTION_TOOL = {
    "name": "reflect_on_report",
    "description": "Evaluate a threat intelligence report for quality, gaps, and confidence.",
    "input_schema": {
        "type": "object",
        "properties": {
            "confidence_score": {
                "type": "number",
                "description": (
                    "Overall report confidence 0.0-1.0. Consider: source diversity, "
                    "threat count, cluster coherence."
                ),
            },
            "gaps_identified": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Intelligence gaps — missing data sources, low coverage areas, "
                    "unverified claims."
                ),
            },
            "low_confidence_clusters": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Cluster names with weak evidence that need caveating.",
            },
            "strengthened_findings": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Findings well-supported by multiple sources — high confidence.",
            },
            "analyst_notes": {
                "type": "string",
                "description": (
                    "2-3 sentence meta-assessment of the report quality and key caveats."
                ),
            },
        },
        "required": ["confidence_score", "gaps_identified", "analyst_notes"],
    },
}


async def reflection_agent(state: SwarmState, config: dict[str, Any]) -> dict[str, Any]:
    """
    Post-correlation reflection pass.
    Adds confidence score and analyst notes to the report.
    Does NOT re-run agents — only critiques and annotates.
    """
    t0 = time.monotonic()
    agent_name = "reflection"
    settings = config.get("configurable", {})
    api_key = unwrap_secret(settings.get("anthropic_api_key"))

    if not state.report or not api_key:
        return {}

    report = state.report
    logger.info(
        "agent_start",
        agent=agent_name,
        clusters=len(report.threat_clusters),
        threats=report.total_threats_processed,
    )

    try:
        client = anthropic.AsyncAnthropic(api_key=api_key)
        model = settings.get("llm_model", "claude-opus-4-20250514")

        # Summarise report for reflection prompt
        cluster_summary = "\n".join(
            f"- {c.get('cluster_name', '?')} [{c.get('severity', '?')}]: "
            f"{c.get('narrative', '')[:100]}"
            for c in report.threat_clusters
        )
        sources_str = ", ".join(report.sources_queried)
        severity_str = str(report.severity_breakdown)

        # See correlation_agent for the SDK-TypedDict overload suppression rationale.
        response = await client.messages.create(  # type: ignore[call-overload]
            model=model,
            max_tokens=1024,
            tools=[REFLECTION_TOOL],
            tool_choice={"type": "tool", "name": "reflect_on_report"},
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"Critically evaluate this threat intelligence report:\n\n"
                        f"Sources queried: {sources_str}\n"
                        f"Threats processed: {report.total_threats_processed}\n"
                        f"Severity breakdown: {severity_str}\n"
                        f"Clusters:\n{cluster_summary}\n\n"
                        f"Executive summary (first 300 chars): {report.executive_summary[:300]}\n\n"
                        "Be critical. Identify: missing sources, weak evidence, "
                        "over-confident claims, clusters that need more data, "
                        "and genuinely well-supported findings."
                    ),
                }
            ],
        )

        tool_block = next((b for b in response.content if b.type == "tool_use"), None)
        if not tool_block:
            return {}

        reflection = tool_block.input
        confidence = float(reflection.get("confidence_score", 0.5))
        gaps = reflection.get("gaps_identified", [])
        analyst_notes = reflection.get("analyst_notes", "")
        low_conf = reflection.get("low_confidence_clusters", [])
        strong = reflection.get("strengthened_findings", [])

        # Append reflection section to markdown report
        reflection_md = (
            f"\n\n---\n\n## Analyst reflection\n\n"
            f"**Confidence score:** {confidence:.0%}  \n"
            f"**Analyst notes:** {analyst_notes}\n\n"
        )
        if strong:
            reflection_md += (
                "**Well-supported findings:**\n" + "\n".join(f"- {s}" for s in strong) + "\n\n"
            )
        if gaps:
            reflection_md += "**Intelligence gaps:**\n" + "\n".join(f"- {g}" for g in gaps) + "\n\n"
        if low_conf:
            reflection_md += (
                "**Low-confidence clusters (treat with caution):**\n"
                + "\n".join(f"- {c}" for c in low_conf)
                + "\n"
            )

        updated_report = report.model_copy(
            update={
                "markdown_report": (report.markdown_report or "") + reflection_md,
            }
        )

        # Append reflection notes to executive summary for JSON artifact
        if gaps:
            gaps_note = f" [Gaps: {'; '.join(gaps[:2])}]"
            updated_report = updated_report.model_copy(
                update={
                    "executive_summary": updated_report.executive_summary + gaps_note,
                }
            )

        duration_ms = (time.monotonic() - t0) * 1000
        logger.info(
            "agent_complete",
            agent=agent_name,
            confidence=confidence,
            gaps=len(gaps),
            duration_ms=round(duration_ms, 1),
        )

        return {"report": updated_report}

    except Exception as exc:
        duration_ms = (time.monotonic() - t0) * 1000
        logger.warning("reflection_failed", error=str(exc), duration_ms=round(duration_ms, 1))
        return {}
