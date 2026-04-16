"""
Shared envelope for enrichment-style agents.

All four enrichment agents (EPSS / VirusTotal / GitHub Advisory / Shodan)
repeat the same outer shape: start a stopwatch, do the work, package a
success `AgentResult` on the happy path, package a failure `AgentResult` on
any exception, return `{"agent_results": [*state.agent_results, result]}`.
That's ~20 lines of boilerplate per agent, repeated four times.

`@enrichment_agent(name=…)` absorbs the envelope. The decorated body is the
*only* thing the agent author writes: pre-flight checks, the actual API
calls and state overlays. It returns either:

    (records, items_fetched, extra_log_fields)   # success
    None                                         # skipped (no-op, success=True, items_fetched=0)

…and the decorator takes care of timing, logging (`agent_complete` /
`agent_failed`), exception wrapping (packaged into `success=False`), and
the return-dict shape the graph expects.

This is *not* a LangGraph-node decorator — the enrichment agents run inside
`_enrichment_node`'s `asyncio.gather`, not as standalone graph nodes.
"""

from __future__ import annotations

import functools
import time
from collections.abc import Awaitable, Callable
from typing import Any, TypeAlias

import structlog

from src.models import AgentResult, NormalizedThreat, SwarmState

logger = structlog.get_logger(__name__)


# Body return shape. `None` means "skipped"; tuple means real work happened.
EnrichmentResult: TypeAlias = tuple[list[NormalizedThreat], int, dict[str, Any]] | None

# Body signature the decorator wraps.
EnrichmentBody: TypeAlias = Callable[[SwarmState, dict[str, Any]], Awaitable[EnrichmentResult]]


def enrichment_agent(
    name: str,
) -> Callable[[EnrichmentBody], Callable[[SwarmState, dict[str, Any]], Awaitable[dict[str, Any]]]]:
    """Wrap an enrichment-agent body in the standard LangGraph envelope.

    The body can `return None` to indicate a no-op (no key, no matching
    inputs) — the envelope emits `success=True, items_fetched=0` for that
    case so reflection/reports still see the agent ran. Any uncaught
    exception becomes `success=False, error=str(exc)` — siblings in the
    same `gather()` are unaffected.
    """

    def _decorator(
        body: EnrichmentBody,
    ) -> Callable[[SwarmState, dict[str, Any]], Awaitable[dict[str, Any]]]:
        @functools.wraps(body)
        async def _wrapped(state: SwarmState, config: dict[str, Any]) -> dict[str, Any]:
            t0 = time.monotonic()
            try:
                result = await body(state, config)
                if result is None:
                    records: list[NormalizedThreat] = []
                    items_fetched = 0
                    extras: dict[str, Any] = {}
                else:
                    records, items_fetched, extras = result
                duration_ms = (time.monotonic() - t0) * 1000
                logger.info(
                    "agent_complete",
                    agent=name,
                    items_fetched=items_fetched,
                    duration_ms=round(duration_ms, 1),
                    **extras,
                )
                ar = AgentResult(
                    agent_name=name,
                    success=True,
                    records=records,
                    items_fetched=items_fetched,
                    duration_ms=duration_ms,
                )
            except Exception as exc:
                duration_ms = (time.monotonic() - t0) * 1000
                logger.error("agent_failed", agent=name, error=str(exc))
                ar = AgentResult(
                    agent_name=name,
                    success=False,
                    error=str(exc),
                    duration_ms=duration_ms,
                )
            return {"agent_results": [*state.agent_results, ar]}

        return _wrapped

    return _decorator
