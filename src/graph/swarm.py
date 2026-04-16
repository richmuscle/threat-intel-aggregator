"""
LangGraph StateGraph — V2 enterprise swarm DAG.

Topology:
  supervisor → parallel_ingest (4 agents) → enrichment (3 agents parallel + shodan)
             → normalize → correlate → reflect → report → END

V2 additions:
  - Supervisor agent: dynamic routing before ingest
  - EPSS / VirusTotal / GitHub Advisory / Shodan enrichment agents
  - Reflection agent: post-correlation confidence scoring
  - Post-enrichment dedup pass to keep `normalized_threats` unique
  - `swarm_config.activate_agents` honored by `_parallel_ingest_node`
  - `raw_iocs` propagated from `ioc_extractor_agent` into SwarmState

State model
-----------
The graph is declared with `StateGraph(SwarmState)` — LangGraph owns the
Pydantic state natively, merges partial-dict node returns via `model_copy`,
and preserves nested typed fields (`AgentResult`, `NormalizedThreat`,
`IOCRecord`) across edges. No dict/Pydantic bridge to maintain.

`_hydrate()` exists only as a defensive coercion used by `run_swarm` in case
LangGraph hands back the final state as a dict (driver-version dependent).
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any

import structlog
from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, StateGraph

from src.agents.attack_mapper import attack_mapper_agent
from src.agents.correlation_agent import correlation_agent
from src.agents.cve_scraper import cve_scraper_agent
from src.agents.epss_enrichment import epss_enrichment_agent
from src.agents.feed_aggregator import feed_aggregator_agent
from src.agents.github_advisory import github_advisory_agent
from src.agents.ioc_extractor import ioc_extractor_agent
from src.agents.reflection import reflection_agent
from src.agents.report_coordinator import report_coordinator
from src.agents.shodan_enrichment import shodan_enrichment_agent
from src.agents.supervisor import supervisor_agent
from src.agents.virustotal_enrichment import virustotal_enrichment_agent
from src.models import AgentResult, IOCRecord, NormalizedThreat, SwarmState
from src.pipeline.normalizer import NormalizationPipeline

logger = structlog.get_logger(__name__)


# ── State coercion (defensive) ────────────────────────────────────────────────

def _hydrate(raw: Any) -> SwarmState:
    """Coerce `raw` to a typed `SwarmState`.

    With `StateGraph(SwarmState)`, nodes receive SwarmState instances and the
    graph returns a SwarmState. But LangGraph's checkpointer and some driver
    versions hand the final state back as a plain dict; this helper makes
    `run_swarm` version-resilient without scattering isinstance checks.
    """
    if isinstance(raw, SwarmState):
        return raw
    data = dict(raw)
    # Drop computed fields — `SwarmState` validation rejects unknown keys.
    for key in list(data.keys()):
        if key not in SwarmState.model_fields:
            data.pop(key, None)

    def _rehydrate_list(key: str, model: type) -> None:
        if data.get(key):
            data[key] = [model(**r) if isinstance(r, dict) else r for r in data[key]]

    _rehydrate_list("normalized_threats", NormalizedThreat)
    _rehydrate_list("raw_iocs",           IOCRecord)
    if data.get("agent_results"):
        rebuilt: list[AgentResult] = []
        for r in data["agent_results"]:
            if isinstance(r, AgentResult):
                rebuilt.append(r)
                continue
            rec_dicts = r.get("records") or []
            r = {**r, "records": [
                NormalizedThreat(**x) if isinstance(x, dict) else x for x in rec_dicts
            ]}
            rebuilt.append(AgentResult(**r))
        data["agent_results"] = rebuilt

    return SwarmState(**data)


def _cfg(config: RunnableConfig | None) -> dict:
    return {"configurable": dict((config or {}).get("configurable", {}))}


# ── Graph nodes ───────────────────────────────────────────────────────────────

async def _supervisor_node(state: SwarmState, config: RunnableConfig) -> dict:
    """Pre-ingest: dynamic swarm routing based on keyword analysis."""
    result = await supervisor_agent(state, _cfg(config))
    swarm_cfg = result.get("swarm_config", {})
    logger.info(
        "supervisor_routing",
        category=swarm_cfg.get("threat_category", "generic"),
        agents=swarm_cfg.get("activate_agents", []),
    )
    return {"swarm_config": swarm_cfg}


# Name → coroutine registry lets the supervisor toggle agents by name without
# the fan-out node encoding each agent's import. New ingest agents get added
# here in one line; `_parallel_ingest_node` never needs re-editing.
_INGEST_AGENTS: dict[str, Any] = {
    "cve_scraper":     cve_scraper_agent,
    "attack_mapper":   attack_mapper_agent,
    "ioc_extractor":   ioc_extractor_agent,
    "feed_aggregator": feed_aggregator_agent,
}


async def _parallel_ingest_node(state: SwarmState, config: RunnableConfig) -> dict:
    """Fan-out: fires the ingestion agents selected by `swarm_config.activate_agents`.

    Honors the supervisor's routing decision — if the supervisor chose only
    `cve_scraper` and `feed_aggregator` for a CVE-heavy query, the other two
    are skipped entirely, saving rate-limit budget and latency. When
    `activate_agents` is empty or unset (no keywords / supervisor skipped),
    the full set fires, matching v1 behaviour exactly.
    """
    cfg = _cfg(config)
    activate = set(state.swarm_config.get("activate_agents") or [])
    selected: dict[str, Any] = {
        name: fn for name, fn in _INGEST_AGENTS.items()
        if not activate or name in activate
    }
    logger.info("parallel_ingest_start", run_id=state.run_id, agents=list(selected))

    results = await asyncio.gather(
        *(fn(state, cfg) for fn in selected.values()),
        return_exceptions=False,
    )

    merged_results: list[AgentResult] = []
    raw_iocs: list[IOCRecord] = list(state.raw_iocs)
    for result_dict in results:
        merged_results.extend(result_dict.get("agent_results", []))
        # `ioc_extractor_agent` returns `raw_iocs` alongside agent_results —
        # collect them here so the sidecar has real `IOCRecord` objects to
        # emit rather than synthesising from `NormalizedThreat` later.
        raw_iocs.extend(result_dict.get("raw_iocs", []))

    logger.info(
        "parallel_ingest_complete",
        agents=len(merged_results),
        total_records=sum(r.items_fetched for r in merged_results),
        raw_iocs=len(raw_iocs),
    )
    return {"agent_results": merged_results, "raw_iocs": raw_iocs}


async def _normalization_node(state: SwarmState, config: RunnableConfig) -> dict:
    """Dedup agent records by content hash. Delegates to NormalizationPipeline."""
    all_records: list[NormalizedThreat] = []
    for result in state.agent_results:
        all_records.extend(result.records)

    normalized, dedup_removed = NormalizationPipeline().dedup(all_records)
    logger.info(
        "normalization_complete",
        total=len(all_records),
        deduped=dedup_removed,
        output=len(normalized),
    )
    return {"normalized_threats": normalized, "dedup_removed": dedup_removed}


# Enrichment agents follow the supervisor's activation list too — lets the
# operator disable e.g. EPSS when the CVE set is tiny to save API budget.
_ENRICHMENT_AGENTS_TIER1: dict[str, Any] = {
    "epss":            epss_enrichment_agent,
    "virustotal":      virustotal_enrichment_agent,
    "github_advisory": github_advisory_agent,
}


async def _enrichment_node(state: SwarmState, config: RunnableConfig) -> dict:
    """
    V2 enrichment. Tier 1 (EPSS / VT / GitHub Advisory) runs in parallel
    because their inputs are disjoint (EPSS reads CVEs, VT reads IOCs,
    GH Advisory reads CVE IDs). Shodan follows serially because it benefits
    from the post-tier-1 severity overlay when picking which IPs to enrich.

    Enrichment is **additive and immutable**: agents write to
    `NormalizedThreat.enriched_severity` / `enriched_tags` rather than
    mutating `severity` / `tags`, so the content hash stays valid. New
    records produced by EPSS's "top actively exploited" extras go through a
    second dedup pass against the existing `normalized_threats` set.
    """
    cfg = _cfg(config)
    activate = set(state.swarm_config.get("activate_agents") or [])
    selected_t1: dict[str, Any] = {
        name: fn for name, fn in _ENRICHMENT_AGENTS_TIER1.items()
        if not activate or name in activate
    }
    logger.info(
        "enrichment_start",
        threat_count=len(state.normalized_threats),
        tier1_agents=list(selected_t1),
    )

    tier1_results = await asyncio.gather(
        *(fn(state, cfg) for fn in selected_t1.values()),
        return_exceptions=False,
    )

    new_agent_results: list[AgentResult] = list(state.agent_results)
    added_records: list[NormalizedThreat] = []
    for result_dict in tier1_results:
        ar_list: list[AgentResult] = result_dict.get("agent_results", [])
        new_agent_results.extend(ar_list)
        for ar in ar_list:
            added_records.extend(ar.records)

    # Tier 2: Shodan (optional). Skipped when the supervisor disabled it.
    if not activate or "shodan" in activate:
        shodan_state = state.model_copy(update={
            "agent_results": new_agent_results,
            "normalized_threats": state.normalized_threats + added_records,
        })
        shodan_result = await shodan_enrichment_agent(shodan_state, cfg)
        new_agent_results.extend(shodan_result.get("agent_results", []))

    # Re-run dedup over the merged set so EPSS's "top actively exploited"
    # extras don't duplicate CVEs already in `normalized_threats`. Without
    # this, a report can double-count the same CVE with conflicting
    # severities coming from different agents.
    merged_normalized = state.normalized_threats + added_records
    final_normalized, post_dedup = NormalizationPipeline().dedup(merged_normalized)

    logger.info(
        "enrichment_complete",
        tier1_records=len(added_records),
        post_enrichment_dedup_removed=post_dedup,
        total_threats=len(final_normalized),
    )
    return {
        "agent_results":      new_agent_results,
        "normalized_threats": final_normalized,
        # `dedup_removed` accumulates — first pass in normalize + second here.
        "dedup_removed":      state.dedup_removed + post_dedup,
    }


async def _correlation_node(state: SwarmState, config: RunnableConfig) -> dict:
    # Agents already return pre-concatenated error lists (`state.errors + [new]`),
    # so the node passes them through as-is — LangGraph's merge semantics
    # replace the field wholesale.
    result = await correlation_agent(state, _cfg(config))
    update: dict[str, Any] = {}
    if result.get("report") is not None:
        update["report"] = result["report"]
    if result.get("errors"):
        update["errors"] = list(result["errors"])
    return update


async def _reflection_node(state: SwarmState, config: RunnableConfig) -> dict:
    """Post-correlation: confidence scoring and gap analysis. No state mutation."""
    result = await reflection_agent(state, _cfg(config))
    return {"report": result["report"]} if result.get("report") else {}


async def _report_node(state: SwarmState, config: RunnableConfig) -> dict:
    result = await report_coordinator(state, _cfg(config))
    update: dict[str, Any] = {"completed": True}
    if result.get("report"):
        update["report"] = result["report"]
    if result.get("errors"):
        update["errors"] = list(result["errors"])
    return update


# ── Graph construction ────────────────────────────────────────────────────────

def build_graph() -> Any:
    """Build and compile the V2 enterprise swarm StateGraph.

    Uses `SwarmState` as the Pydantic state schema so LangGraph merges node
    returns via `model_copy(update=...)` — no manual dict↔Pydantic bridge
    per hop, and nested typed fields (`AgentResult`, `NormalizedThreat`,
    `IOCRecord`) survive edge traversal.
    """
    graph: StateGraph = StateGraph(SwarmState)

    graph.add_node("supervisor",       _supervisor_node)
    graph.add_node("parallel_ingest",  _parallel_ingest_node)
    graph.add_node("normalize",        _normalization_node)
    graph.add_node("enrich",           _enrichment_node)
    graph.add_node("correlate",        _correlation_node)
    graph.add_node("reflect",          _reflection_node)
    graph.add_node("report",           _report_node)

    graph.set_entry_point("supervisor")
    graph.add_edge("supervisor",      "parallel_ingest")
    graph.add_edge("parallel_ingest", "normalize")
    graph.add_edge("normalize",       "enrich")
    graph.add_edge("enrich",          "correlate")
    graph.add_edge("correlate",       "reflect")
    graph.add_edge("reflect",         "report")
    graph.add_edge("report",          END)

    return graph.compile()


# ── Public entrypoint ─────────────────────────────────────────────────────────

async def run_swarm(
    query_keywords: list[str] | None = None,
    max_cves: int = 50,
    max_iocs: int = 100,
    config: dict | None = None,
) -> SwarmState:
    run_id = str(uuid.uuid4())
    structlog.contextvars.bind_contextvars(run_id=run_id)
    logger.info("swarm_start", run_id=run_id, keywords=query_keywords)

    initial = SwarmState(
        run_id=run_id,
        query_keywords=query_keywords or [],
        max_cves=max_cves,
        max_iocs=max_iocs,
    )

    graph = build_graph()
    cfg = config or {"configurable": {}}
    try:
        final = await graph.ainvoke(initial, cfg)
    finally:
        structlog.contextvars.unbind_contextvars("run_id")

    final_state = _hydrate(final)
    logger.info(
        "swarm_complete",
        run_id=run_id,
        completed=final_state.completed,
        threats=len(final_state.normalized_threats),
        errors=len(final_state.errors),
    )
    return final_state
