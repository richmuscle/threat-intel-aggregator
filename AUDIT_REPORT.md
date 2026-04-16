# Audit Report — Threat Intel Aggregator

**Generated:** 2026-04-16 (Opus 4.6, agentic /audit pipeline)
**Subagents:** audit-agent (Haiku, read-only), recon-agent (Haiku, recon), patch-agent (Sonnet, P0 fixes)
**Isolation:** in-place (repo is not a git worktree)

---

## Executive verdict

**Composite score: 6.8 / 10** — a high-ceiling swarm platform whose v1 core is well-engineered but whose v2 enrichment tier was grafted on without corresponding schema, state-bridge, and sidecar-ordering updates. The *architecture and CS primitives* (LangGraph DAG, content-hash dedup, typed contracts, token-bucket rate limiter, `retry_on_disconnect` decorator) are genuinely senior-level. The *risk* is the drift between the enrichment agents and the shared `SwarmState` — one of those drifts was already breaking the integration happy-path test at the start of this audit and was fixed in the patch phase.

| Lens | Score | Rationale |
|---|---:|---|
| Architecture | 6 / 10 | Clean v1 DAG; v2 enrichment layer bolted on without matching state-model updates (the `raw_iocs` field was produced by `ioc_extractor_agent` but never declared on `SwarmState`). |
| CS depth | 7 / 10 | Two-layer `asyncio.gather`, bounded `TCPConnector`, `MAX_RETRY_AFTER_SECONDS` cap, token-bucket rate limiter, content-hash dedup. One subtle bug: enrichment agents append to `normalized_threats` *after* dedup, bypassing the hash check. |
| Python / typing | 6 / 10 | Pydantic v2 contracts are strong, `model_validator(mode="after")` is correct, `_to_state()` bridge works — but many node signatures still return `dict` instead of a TypedDict envelope, and `threat_type` is a bare `str` rather than a `Literal`. |
| Security / domain | 5 / 10 | ECS-correct SIEM output, UTC-aware datetimes (after P0-2 fix), strict nftables IP regex. Gaps: API keys are read straight from env with no `SecretStr` wrapper, Shodan client passes the key as a query param instead of a header, sidecar IOC confidence is synthesised after enrichment has mutated severity. |
| Test discipline | 7 / 10 | 77 async-aware tests, clean unit/integration split, real LangGraph DAG exercised end-to-end with mocked APIs — but rate-limiter, retry decorator, and `_to_ecs()` have no direct unit coverage, and enrichment agents are under-tested. |

**Dominant strength:** the LangGraph ↔ Pydantic state bridge (`src/graph/swarm.py::_to_state()`) is the right abstraction — a single place that rehydrates `AgentResult`, `NormalizedThreat`, and now `IOCRecord`, dropping computed fields, surviving LangGraph's serialization. Without this the swarm would crumble.

**Root-cause gap:** **schema drift under scope creep.** The v2 enrichment tier (6 new agents + scripts/ automation + wazuh integration) shipped before its contracts were in the shared model. The `raw_iocs` test failure was not a one-off — it's the class of bug this codebase produces when agents are added without updating `SwarmState` + `_to_state()` + the dedup path in lockstep. Fix once by making the pattern explicit; otherwise every new enrichment agent risks repeating it.

---

## § Patch Log — P0 fixes applied this run

Patch-agent ran against the P0 backlog. Summary (full diffs in `PATCHES.md`):

| # | Status | File | Effect |
|---|---|---|---|
| **P0-1** | ✅ done | `src/models/threat.py`, `src/graph/swarm.py` | Added `raw_iocs: list[IOCRecord] = Field(default_factory=list)` on `SwarmState`. Extended `_to_state()` to rehydrate `raw_iocs` from dicts. Imports updated. Fixes contract drift; future `state.raw_iocs` reads no longer crash. |
| **P0-2** | ✅ done | `src/api/app.py:162` | `datetime.utcnow()` → `datetime.now(timezone.utc)`. Import updated to include `timezone`. |
| **P0-3** | ✅ done | `src/agents/virustotal_enrichment.py` | Real bug: `client.enrich_batch(...)` was dedented *outside* the `async with VirusTotalClient(...)` block, meaning every run with a valid VT key would call through a closed `aiohttp` session. Moved the call inside the context manager; the pre-call filtering (which needs no client) now sits outside. |
| **P0-4** | ⏭ skipped (audit was wrong) | `scripts/nftables_block.sh`, `scripts/auto_block.sh` | Re-read both scripts: `nftables_block.sh` already validates IPv4 with a regex at line 83 before calling `nft add element` (line 91), and all expansions are quoted. `auto_block.sh` delegates the file path to the validated script rather than invoking `nft` itself. No injection surface — no change needed. |

**Tests before:** 76 passed, 1 failed (`test_full_swarm_pipeline_happy_path` → `AttributeError: 'SwarmState' object has no attribute 'raw_iocs'`).
**Tests after:** **77 passed, 0 failed.**

---

## § Findings by lens

### 1. Architecture — 6/10

- **Strong:** clean four-layer DAG — `parallel_ingest` → `normalize` → `enrichment` → `correlate` → `report`. Each node signature is typed, and state merging is centralised through one bridge function. Two nested `asyncio.gather` calls (outer across agents, inner per-agent for paired APIs) give the right parallelism shape.
- **Weak:** the **enrichment-layer architecture is half-finished.** Six enrichment agents (`epss`, `virustotal`, `shodan`, `github_advisory`, `reflection`, `supervisor`) each return records that get appended to `state.normalized_threats` in `_enrichment_node` (`src/graph/swarm.py:176`), but the second pass bypasses `NormalizationPipeline.dedup()`. If two enrichment agents both generate records for the same CVE, duplicates persist into the report. Either the enrichment layer must mutate in place (no new records), or a post-enrichment dedup pass is required. **Tracked as P1-C below.**
- **Weak:** `ioc_extractor_agent` returns `{"raw_iocs": [...]}` alongside its `agent_results`, but until this run `SwarmState` had no `raw_iocs` field — LangGraph was silently dropping the key and `report_coordinator._sidecar_from_state` fell back to reconstructing synthetic `IOCRecord` shapes from `NormalizedThreat`. Patch-agent fixed the schema; the sidecar fallback should now be revisited so it prefers real `raw_iocs` when present.

### 2. CS depth — 7/10

- **Token-bucket rate limiter** in `src/tools/base_client.py::RateLimiter` is correctly implemented with an `asyncio.Lock` and monotonic-clock elapsed refill — no over-refill bug, no clock-skew bug.
- **Backoff strategy** has two layers: HTTP-retry (`get()` inner loop) handles 429/5xx; `retry_on_disconnect` decorator handles `ServerDisconnectedError` before any response. Both cap out at bounded sleeps via `MAX_RETRY_AFTER_SECONDS` (60s) — essential defence against AbuseIPDB's ~18-hour `Retry-After` responses.
- **Content-hash dedup** in `NormalizedThreat.compute_hash()` (SHA-256 over lowercase title + sorted CVE/TTP/IOC IDs, truncated to 16 chars) is deterministic and source-agnostic — exactly the right primitive.
- **Concurrency gap:** enrichment agents can run in sequence inside `_enrichment_node` rather than parallel — worth checking whether the current v2 code `asyncio.gather`s them or sequentially awaits each (this auditor did not exhaustively trace that node). **Tracked as P1-D.**

### 3. Python / typing — 6/10

- `model_validator(mode="after")` on `CVERecord` correctly derives severity from CVSS (the `mode="before"` bug from the v1 phase is fully resolved — when a field uses its default value, `before` validators are skipped; `after` runs unconditionally).
- `_to_state()` handles the LangGraph dict-vs-Pydantic impedance mismatch with a handful of explicit branches. With `raw_iocs` added, this pattern scales for one more type but will not scale to N more — each new field requires another isinstance branch. **Tracked as P1-A (generalise `_to_state()`).**
- **Opportunity:** `threat_type` on `NormalizedThreat` is a `str` with four expected values. A `Literal["cve", "technique", "ioc", "feed_item"]` (or `ThreatType` enum) would give mypy real narrowing in `report_coordinator._sidecar_from_state` and similar. **Tracked as P2.**
- Node return types are `dict` (so e.g. `{"agent_results": [...]}`). A `TypedDict` per node return would let the type checker catch missing keys. **Tracked as P2.**

### 4. Security / domain — 5/10

- **ECS alert shape is correct** — `_to_ecs()` maps severity to the 1–100 integer Elastic expects and lands fields under `event.*`, `threat.technique.id`, `vulnerability.id`, `rule.*`. Filebeat/Wazuh/Splunk snippets in the README are credible.
- **Secret handling is thin.** API keys are read by `os.getenv` with no redacting wrapper. A stray `logger.info("config_loaded", config=config)` anywhere in the chain would dump every key. Recommend wrapping env reads in `pydantic.SecretStr` or a small `Secret` class whose `__repr__` / `__str__` returns `"***"`. **Tracked as P1-B.**
- **Shodan client** (flagged by audit-agent, not verified exhaustively by this synthesis) passes the API key as a query parameter — which lands it in HTTP access logs and any intermediate proxy. Header auth is supported; switch to it. **Tracked as P2.**
- **Sidecar ordering.** `report_coordinator._sidecar_from_state` runs *after* the enrichment layer has mutated `severity` and `tags` in place. `scripts/extract_iocs.py` then gates on `malicious or confidence >= 0.7`. Enrichment-driven severity bumps can silently flip that gate's decisions. Fix options: (a) snapshot `original_confidence` on `NormalizedThreat`, or (b) emit the sidecar from `raw_iocs` before enrichment touches anything. **Tracked as P1-E.**
- **nftables / auto_block** — P0-4 concern was not real; both scripts use `set -euo pipefail`, validate IPv4 with a regex before invoking `nft`, and quote expansions.

### 5. Test discipline — 7/10

- 77 tests (counted from pytest output), clean unit/integration split. Integration test exercises the full `run_swarm()` with mocked external APIs — exactly the right size of test for the DAG.
- Async fixtures use `pytest-asyncio`'s `asyncio_mode = "auto"` — no per-test decorators.
- **Gaps:**
  - `RateLimiter` token-bucket behaviour under concurrent `acquire()` is untested.
  - `retry_on_disconnect` decorator has no unit coverage (would need an `aiohttp.ServerDisconnectedError` mock).
  - `_to_ecs()` output shape is not asserted against the ECS schema.
  - Enrichment agents' error-path behaviour is largely untested.

---

## § Adversarial critiques and neutralising moves

From audit-agent, distilled:

1. **Critique:** *Stratified sampling in `correlation_agent` only helps when the threat list already exceeds the 80-item cap; for CVE-heavy runs under 80 items, `_build_prompt` still ships whatever shape the input has.*
   **Neutralising move:** keep the current quota-based sampler, and add a *minimum-floor per tier* so CRITICAL always gets at least 20 slots when available, regardless of input size.

2. **Critique:** *The reflection agent identifies gaps (e.g. "no EPSS data") but has no conditional edge back to enrichment — it's diagnostic only.*
   **Neutralising move:** either wire a LangGraph conditional edge on `reflection.confidence_score < 0.6 → enrichment`, or explicitly document reflection as a passive scorer. (P2.)

3. **Critique:** *Every node signature returns `dict`, so callers must know internal key names. The typing story breaks down at the LangGraph boundary.*
   **Neutralising move:** define per-node `TypedDict` envelopes (e.g. `IngestionResult = TypedDict("IngestionResult", {"agent_results": list[AgentResult], "raw_iocs": list[IOCRecord]})`) and annotate node returns with them. Cost is low, and static checkers will catch further drift.

4. **Critique:** *Shodan client embeds the key in the URL path query — a credential-in-URL OWASP anti-pattern.*
   **Neutralising move:** override `_build_headers()` to add `Authorization: Bearer <key>` and strip the `key` query param.

---

## § Prioritised backlog (post-patch)

### P1 — this week

- **P1-A: Generalise `_to_state()`.** The current per-type isinstance branches won't scale. Introduce a small registry mapping model names to their Pydantic classes, or use `SwarmState.model_validate(data)` with a pre-pass that walks `model_fields` and coerces nested dicts. Ref: `src/graph/swarm.py:45-86`.
- **P1-B: SecretStr wrapper for API keys.** Wrap every `os.getenv("*_API_KEY")` read in a type whose `__repr__` returns `"***"`. Audit every `logger.*` call-site in the correlation and report nodes for accidental config logging. Ref: `src/api/app.py:108-115`, `main.py::_build_config`.
- **P1-C: Post-enrichment dedup.** Run `NormalizationPipeline.dedup()` a second time after `_enrichment_node` returns, or change enrichment agents to mutate `NormalizedThreat` in place rather than appending new records. Ref: `src/graph/swarm.py:165-190`.
- **P1-D: Parallelise enrichment.** Confirm `_enrichment_node` uses `asyncio.gather` across the six enrichment agents; if it awaits them in sequence, the latency budget gets blown when two agents are slow. Ref: `src/graph/swarm.py::_enrichment_node`.
- **P1-E: IOC sidecar freezing.** Emit `output/*_iocs.json` from `raw_iocs` (now typed and reachable) *before* enrichment mutations, or record `original_confidence` on `NormalizedThreat` so the downstream `extract_iocs.py` gate is enrichment-stable. Ref: `src/agents/report_coordinator.py:~80-89`.
- **P1-F: Supervisor model choice.** `src/agents/supervisor.py` hard-codes `claude-opus-4-…`. Accept the model from config; default to Sonnet to keep cost predictable.
- **P1-G: Rate-limiter + retry unit coverage.** Add `tests/unit/test_base_client_retry.py` covering `RateLimiter.acquire()` under concurrent callers and `retry_on_disconnect` across a mocked `ServerDisconnectedError`. Ref: `src/tools/base_client.py:29-57, 138-200`.
- **P1-H: Dependency upper bounds.** All deps are pinned with `>=X` floors only. Add conservative upper bounds (`anthropic>=0.40,<2`, `langgraph>=0.2,<1`, `pydantic>=2.7,<3`). Ref: `pyproject.toml`.

### P2 — this month

- **P2-A:** Typed node-return envelopes (`TypedDict`) in place of bare `dict`.
- **P2-B:** `threat_type` as `Literal[...]` or `ThreatType` enum.
- **P2-C:** Shodan `Authorization` header migration.
- **P2-D:** ECS schema compliance assertion in `_to_ecs()` tests (a small JSON-schema validator is enough).
- **P2-E:** SSRF/path-injection regex validation on user-provided IPs/domains that reach client URL paths (Shodan `host/{ip}`, VirusTotal `files/{hash}`).
- **P2-F:** `aiosqlite.connect(DB_PATH, isolation_level=None)` + `PRAGMA journal_mode=WAL` on API startup so concurrent background runs don't trip `SQLITE_BUSY`.
- **P2-G:** Reflection-driven re-enrichment loop via LangGraph conditional edge (or explicit docs marking reflection as passive).
- **P2-H:** Consolidate enrichment-agent boilerplate (no-key-skip, empty-input-skip, AgentResult wrapping) into a small decorator.

---

## § Appendix A — Dependency inventory (from recon)

| Package | Pin | Risk | Note |
|---|---|---|---|
| anthropic | `>=0.40.0` | medium | SDK evolves rapidly; add upper bound |
| langgraph | `>=0.2.0` | medium | Core orchestration; minor upgrades can break state semantics |
| langchain-core | `>=0.3.0` | medium | Coupled to langgraph |
| pydantic | `>=2.7.0` | low | v2 stable; v3 (~2026) likely to need validator updates |
| aiohttp | `>=3.9.0` | low | Well-maintained; stable async semantics |
| fastapi | `>=0.115.0` | low | Modern FastAPI, no breaking changes in 0.115.x |
| python-dotenv | `>=1.0.0` | low | Stable, minimal API surface |

All deps are floors-only. **Action:** add conservative upper bounds (P1-H).

---

## § Appendix B — Environment variable inventory (from recon)

| Variable | Read at | Required? |
|---|---|---|
| `NVD_API_KEY` | `src/tools/nvd_client.py:40`, `src/api/app.py:110` | no (raises NVD rate limit 10×) |
| `OTX_API_KEY` | `src/api/app.py:111` | no |
| `ABUSEIPDB_API_KEY` | `src/api/app.py:112` | no |
| `GREYNOISE_API_KEY` | `src/api/app.py:113` | no |
| `ANTHROPIC_API_KEY` | `src/api/app.py:114` | **yes** (correlation agent) |

No `SecretStr` wrapper anywhere. See P1-B.

---

## § Appendix C — File size distribution (from recon, top 15)

| Path | LOC |
|---|---:|
| `src/agents/report_coordinator.py` | 394 |
| `src/agents/correlation_agent.py` | 287 |
| `src/graph/swarm.py` | 284 |
| `src/models/threat.py` | 263 |
| `src/api/app.py` | 263 |
| `src/pipeline/normalizer.py` | 198 |
| `src/tools/nvd_client.py` | 193 |
| `src/tools/base_client.py` | 187 |
| `src/agents/reflection.py` | 155 |
| `src/tools/virustotal_client.py` | 136 |
| `src/tools/feed_clients.py` | 135 |
| `src/tools/github_advisory_client.py` | 132 |
| `src/agents/supervisor.py` | 131 |
| `src/tools/ioc_clients.py` | 130 |
| `src/agents/attack_mapper.py` | 84 |

**Observation:** `report_coordinator.py` is the largest module at ~400 LOC and the P1 candidates around it (sidecar ordering, ECS tests) suggest it's ready for a small split — render-markdown, sidecar-emit, and ECS-emit are three concerns that could each live in their own sub-module. Not urgent, but queue it.

---

## § Appendix D — Agent meta-findings

Orchestrator observed two agent failures worth naming:

1. **Recon-agent false negative on contract drift.** The recon-agent's `contract_drift` array returned `[]` even though `state.raw_iocs` is referenced in `src/agents/report_coordinator.py:83, 259-260` and produced by `src/agents/ioc_extractor.py:99` but was not declared on `SwarmState` (verified by the orchestrator via `SwarmState.model_fields`). The failing integration test was the ground truth the recon check should have caught. Lesson: **contract-drift checks must cross-reference field *writes* (return dicts), not only field *reads*.**

2. **Audit-agent framed the right symptom but not the sharpest P0.** The audit mentioned "V2 enrichment tier added 6 parallel agents without corresponding updates to SwarmState" but did not explicitly name `raw_iocs` as the failing-test cause. The orchestrator promoted it to the head of the patch queue based on direct test output. Lesson: **always couple the audit to the live test status; do not trust the audit's P0 ordering when a test is already failing.**

---

## § How to verify

```bash
# Test suite
pytest tests/ -q
# → 77 passed

# SwarmState schema now includes raw_iocs
python -c "from src.models import SwarmState; assert 'raw_iocs' in SwarmState.model_fields"

# No naïve utcnow remains in src/
grep -rn "datetime.utcnow" src/ && echo BAD || echo OK

# Dry-run still exits 0
python main.py --dry-run
```

---

*End of report. Full per-fix diffs in `PATCHES.md`.*
