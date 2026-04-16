# Threat Intel Aggregator

A production-grade **AI agent swarm** that pulls from six threat-intelligence sources in parallel, normalizes them through strict Pydantic contracts, and correlates the result with Claude using a structured tool call — producing a markdown report, a typed JSON artifact, and an ECS-aligned SIEM alert stream in a single run.

The interesting parts are the **orchestration and contracts**, not the API scraping. Four ingestion agents run inside a LangGraph `StateGraph` DAG and fan out concurrently via `asyncio.gather`. Every boundary — agent → pipeline → LLM → report — is a Pydantic v2 model. The Claude correlation agent uses `tool_choice` forcing, so the DAG never parses free-text JSON.

---

## Swarm architecture

```
                            ┌─────────────────┐
                            │   run_swarm()   │   uuid + config
                            └────────┬────────┘
                                     │
                       ┌─────────────▼─────────────┐
                       │  LangGraph StateGraph     │
                       │  state = SwarmState       │   Pydantic BaseModel
                       └─────────────┬─────────────┘
                                     │
                      ┌──────────────┴──────────────┐
                      │      parallel_ingest        │     asyncio.gather
                      │                             │
        ┌─────────────┼─────────────┬───────────────┼──────────────┐
        │             │             │               │              │
        ▼             ▼             ▼               ▼              │
  ┌──────────┐  ┌──────────┐  ┌───────────────┐  ┌──────────────┐  │
  │   CVE    │  │  ATT&CK  │  │  IOC          │  │  Feed        │  │
  │ scraper  │  │  mapper  │  │  extractor    │  │  aggregator  │  │
  │  (NVD)   │  │ (MITRE)  │  │ (OTX+Abuse)*  │  │ (KEV+GN)*    │  │
  └─────┬────┘  └─────┬────┘  └───────┬───────┘  └──────┬───────┘  │
        │             │               │                 │          │
        └────────┬────┴──────┬────────┴────────┬────────┘          │
                 │           │                 │                    │
              AgentResult  AgentResult      AgentResult (* = inner
                 │           │                 │         asyncio.gather)
                 └───────────┴──────┬──────────┘
                                    ▼
                       ┌─────────────────────────────┐
                       │       normalize node        │   content-hash dedup
                       │  NormalizationPipeline      │   source-set merge
                       └─────────────┬───────────────┘
                                     ▼
                       ┌─────────────────────────────┐
                       │     correlate node          │   Claude Sonnet
                       │  tool_choice=produce_report │   structured output
                       └─────────────┬───────────────┘
                                     ▼
                       ┌─────────────────────────────┐
                       │       report node           │
                       │   ├─ Markdown (.md)         │
                       │   ├─ Full JSON (.json)      │
                       │   └─ ECS alerts (.ndjson)   │
                       └─────────────────────────────┘
```

Six external APIs, four agents, one DAG, one correlated report per run.

---

## Quickstart

```bash
# 1. Install
pip install -e ".[dev]"

# 2. Configure
cp .env.example .env                       # then set ANTHROPIC_API_KEY

# 3. Validate
python main.py --dry-run

# 4. Run
python main.py --keywords ransomware log4j --max-cves 50

# 5. Inspect
ls -la output/                             # .md + .json + .ndjson
```

Your first run against CISA KEV alone (no API keys at all) will still produce a correlated report — every downstream agent degrades gracefully when its key is missing.

### Repository layout

```
.
├── main.py                     # CLI entrypoint
├── src/
│   ├── agents/                 # 4 ingestion agents + correlation + report coordinator
│   ├── graph/                  # LangGraph StateGraph wiring
│   ├── integrations/           # wazuh_client.py (UDP syslog forwarder)
│   ├── models/                 # Pydantic v2 contracts (IOCRecord, NormalizedThreat, …)
│   ├── pipeline/               # normalizer + dedup
│   └── tools/                  # per-source async HTTP clients
├── scripts/                    # operational automation (nftables, DNS, Wazuh, cron)
│   ├── auto_block.sh           # orchestrator: extract → nft → DNS → Wazuh
│   ├── extract_iocs.py         # IOC extraction with _iocs.json sidecar support
│   ├── nftables_block.sh       # idempotent firewall set loader
│   ├── dns_block.sh            # /etc/hosts sinkhole
│   ├── verify_blocks.sh        # post-block verification
│   ├── install_cron.sh         # 6-hour schedule
│   └── cleanup_output.sh       # rotate old reports (dry-run by default)
├── output/                     # generated — reports, blocklists, sidecars (gitignored)
├── logs/                       # generated — cron logs (gitignored)
└── tests/                      # unit + integration, 43+ async-aware
```

---

## Architecture deep-dive

### Why LangGraph, not bare `asyncio`

The swarm is a DAG, not a pipeline. LangGraph gives us:

* **State as a Pydantic model** — `SwarmState` is the graph's state schema, so every node signature documents exactly what it reads and writes. No implicit globals; no "where did this key come from?"
* **Checkpointable execution** — every node's partial return is merged into state. The `parallel_ingest` node returning `{"agent_results": […]}` is visible to downstream nodes without manual plumbing.
* **Declarative fan-in** — the graph's edges tell you `parallel_ingest → normalize → correlate → report`. That control flow is data, not nested `await` blocks.

The LangGraph ↔ Pydantic bridge is load-bearing: LangGraph serialises state between nodes, which strips nested Pydantic type information. `src/graph/swarm.py::_to_state()` is the single place that re-hydrates nested `AgentResult` and `NormalizedThreat` objects (including the `content_hash` computed field) on every node entry.

### Why `asyncio.gather`, not a queue

All six external APIs are I/O-bound. Running them sequentially would take ~6× longer; running them in threads would cost context switches for nothing. `asyncio.gather` is the idiomatic primitive:

* `parallel_ingest_node` fires all four ingestion agents simultaneously.
* `ioc_extractor_agent` and `feed_aggregator_agent` each do a **second** `asyncio.gather` internally — OTX + AbuseIPDB in one, CISA KEV + GreyNoise in the other. Two layers of parallelism, bounded by a single `aiohttp` connection pool.
* `return_exceptions=True` inside the inner gathers isolates partial failures — if OTX times out, AbuseIPDB still returns cleanly.

The outer gather uses `return_exceptions=False` because each *agent* already catches and packages exceptions into an `AgentResult(success=False, error=…)`. Failures never propagate up and kill the DAG.

### Why Pydantic v2 contracts at every boundary

Every inter-module handoff is a typed model (`src/models/threat.py`):

* **`CVERecord`, `ATTACKTechnique`, `IOCRecord`, `ThreatFeedItem`** — raw per-source records, each with field-level validation (e.g. `cve_id` regex, `confidence ∈ [0, 1]`, `ioc_type ∈ {ipv4, ipv6, domain, md5, sha1, sha256, url, email}`).
* **`NormalizedThreat`** — the canonical cross-source shape; every agent produces `list[NormalizedThreat]` so the correlation layer never sees raw. Includes a deterministic `content_hash` (SHA-256 over normalized title + CVE/TTP/IOC IDs, truncated to 16 chars) for cross-source deduplication — the same CVE pulled from both NVD and MITRE CVE hashes to the same value, and the dedup step merges their `sources` lists.
* **`CorrelatedIntelReport`** — the Claude output schema, validated on construction. The Anthropic tool call (`CORRELATION_TOOL` in `correlation_agent.py`) mirrors this schema exactly.
* **`SwarmState`** — the graph state, including a `total_raw_records` computed field for observability.

`CVERecord` uses `model_validator(mode="after")` to derive `severity` from `cvss_v3_score` after all fields are set. This is deliberate: `field_validator(mode="before")` is skipped when a field falls back to its default value, which previously hid a severity-derivation bug. The fix is documented inline at `src/models/threat.py::_derive_severity_from_score`.

### Why structured `tool_choice` for Claude

The correlation agent doesn't ask Claude for JSON. It defines `CORRELATION_TOOL` — a tool whose `input_schema` is the exact shape of `CorrelatedIntelReport` — and sets `tool_choice={"type": "tool", "name": "produce_intel_report"}`. Claude is forced to emit a `tool_use` block whose `input` is pre-validated against that schema before we ever see it.

Upside:

* No `json.loads` of model output. No regex for triple-backticks. No retry loop on malformed JSON.
* The schema lives in Python next to the Pydantic model — the prompt engineering surface is `input_schema` plus a terse instruction, nothing more.
* Prompts stay small: `_build_prompt()` does a **two-stage stratified sample** of the threat list — it buckets by severity tier first (CRITICAL/HIGH dominate), then round-robins across `threat_type` inside each tier so CVEs don't crowd out IOCs or techniques when the run is CVE-heavy.

---

## API keys

| Variable | Role | Status | Source |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | Drives the correlation agent | **Required** | console.anthropic.com |
| `NVD_API_KEY` | Raises NVD rate limit 5× (25 req/30s) | Recommended | nvd.nist.gov/developers/request-an-api-key |
| `OTX_API_KEY` | AlienVault OTX pulse feeds | Recommended | otx.alienvault.com (free) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB malicious-IP blocklist | Recommended | abuseipdb.com/api (free tier OK) |
| `GREYNOISE_API_KEY` | GreyNoise GNQL scanner data | Optional | greynoise.io (paid tier for GNQL) |
| *(none)* | CISA KEV catalogue | Always on | cisa.gov/known-exploited-vulnerabilities |

Missing keys surface as warnings during `--dry-run`; the corresponding agent still runs but returns an empty list.

Tuning vars: `CVE_DAYS_BACK` (lookback window, default 7), `ATTACK_PLATFORM` (MITRE filter, default `Windows`), `LOG_FORMAT=json` for SIEM-friendly stdout.

---

## CLI

```bash
python main.py                              # all recent threats, all sources
python main.py --keywords ransomware log4j  # keyword filter across agents
python main.py --max-cves 100 --max-iocs 200
python main.py --dry-run                    # validate config, no API calls
python main.py --serve                      # FastAPI dashboard on :8000
```

| Flag | Type | Default | Effect |
|---|---|---|---|
| `--keywords / -k` | `list[str]` | `[]` | Filter CVE + ATT&CK + KEV by case-insensitive substring match in title/description |
| `--max-cves` | `int` | `50` | Caps NVD fetch; also used as top-N filter after CVSS sort |
| `--max-iocs` | `int` | `100` | Split evenly between OTX and AbuseIPDB |
| `--dry-run` | flag | off | Prints config warnings and exits 0 without any HTTP traffic |
| `--serve` | flag | off | Launches `uvicorn src.api.app:app` on `$API_HOST:$API_PORT` |

---

## Output

Every run writes three artifacts to `output/` under a shared `TIA-<RUN_ID>_<UTC_TIMESTAMP>` prefix:

### 1. Markdown report (`.md`)

Human-readable brief — executive summary, severity histogram with unicode bar chart, ranked critical findings, threat clusters (CVE + TTP cross-references), recommended actions, SIEM alert table, and a run-metadata footer that captures per-agent duration and success/failure. This is the artifact you paste into a Slack channel or a ticket.

### 2. Full JSON (`.json`)

`CorrelatedIntelReport.model_dump(mode="json")` — the whole structured record including every cluster, finding, and alert. Consume this from a downstream pipeline or reingest into Python via `CorrelatedIntelReport.model_validate(...)`.

### 3. ECS-aligned SIEM alerts (`.ndjson`)

Newline-delimited JSON, one event per line, each mapped to **Elastic Common Schema**:

```json
{
  "@timestamp": "2026-04-15T21:04:12.553Z",
  "event":  { "kind": "alert", "category": ["threat"], "type": ["indicator"],
              "severity": 99, "dataset": "threat_intel.aggregator" },
  "rule":   { "name": "Critical CVE Detection",
              "description": "CVE-2024-00001 exploitation attempt detected" },
  "threat": { "technique": { "id": "T1059" } },
  "vulnerability": { "id": "CVE-2024-00001" },
  "tags":   ["ransomware", "rce", "threat-intel-aggregator"],
  "labels": { "report_id": "TIA-A1B2C3D4" }
}
```

The ECS severity field is the 1–100 integer Elastic expects (`CRITICAL=99`, `HIGH=73`, `MEDIUM=47`, `LOW=21`, `INFO=1`), not a string.

---

## Wiring the NDJSON into a SIEM

### Elastic / Kibana

```yaml
# filebeat.yml
filebeat.inputs:
  - type: filestream
    id: threat-intel-aggregator
    paths:
      - /path/to/threat-intel-aggregator/output/*_siem_alerts.ndjson
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true

output.elasticsearch:
  hosts: ["https://es.internal:9200"]
  index: "threat-intel-%{+yyyy.MM.dd}"
```

Because the payload is already ECS-shaped, nothing needs an ingest pipeline — `@timestamp`, `event.*`, `threat.*`, `vulnerability.*`, `rule.*` all land in the canonical fields. Build a Kibana dashboard on `event.severity` and `threat.technique.id`.

### Wazuh

```xml
<localfile>
  <log_format>json</log_format>
  <location>/path/to/threat-intel-aggregator/output/*_siem_alerts.ndjson</location>
</localfile>
```

Wazuh auto-parses the JSON keys into fields; write decoders/rules against `data.rule.name` and `data.vulnerability.id`.

### Splunk

`sourcetype=_json` plus a props/transforms stanza that maps `@timestamp → _time`.

---

## Extending: adding a new parallel agent

The contract is small. To add, say, a Shodan scanner:

1. **Client** — `src/tools/shodan_client.py`, subclass `BaseAPIClient`. Set `base_url`, override `_build_headers()`, expose an async method that returns `list[IOCRecord]` or a new raw model.
2. **Raw model** — if the new source produces a shape that doesn't fit `IOCRecord`/`CVERecord`/etc., add a new Pydantic model to `src/models/threat.py`.
3. **Normalizer** — add `normalize_shodan(...)` to `src/pipeline/normalizer.py` producing a `NormalizedThreat`. The `content_hash` will compose automatically from the fields you populate.
4. **Agent** — `src/agents/shodan_scanner.py` with signature `async def shodan_scanner_agent(state: SwarmState, config: dict) -> dict`. Wrap the fetch in `try/except`, time it with `time.monotonic()`, return `{"agent_results": state.agent_results + [AgentResult(...)]}`.
5. **Wire it in** — `src/graph/swarm.py::parallel_ingest_node`: add one more coroutine to the `asyncio.gather(...)` call. That's the only DAG edit. The normalization/correlation/report nodes adapt automatically because they consume `NormalizedThreat`, not source-specific shapes.
6. **Test** — `tests/unit/test_tool_clients.py` for HTTP parsing (use `aioresponses` or `unittest.mock.AsyncMock` on `BaseAPIClient.get`), and an entry in `tests/integration/test_swarm_pipeline.py` patching the new fetch.

No graph reshaping, no global state, no `if source == 'shodan'` branches anywhere downstream.

---

## Observability

Everything logs through `structlog`. Set `LOG_FORMAT=json` and every event is a single-line JSON record with `event`, `agent`, `run_id`, `duration_ms`, and any contextual fields — which is itself ECS-compatible enough to ingest into the same stack that receives the alerts.

Per-agent timing is captured inside each agent and surfaces on `AgentResult.duration_ms`, which the report coordinator renders into the markdown run-metadata footer.

---

## Testing

```bash
pytest                    # 43 tests, all async-aware
pytest --cov=src          # coverage (covers models, normalizer, swarm, agents)
pytest -k ioc             # subset by keyword
```

Split:

* `tests/unit/test_models_and_pipeline.py` — Pydantic validators, severity derivation, normalization, content-hash determinism.
* `tests/unit/test_tool_clients.py` — NVD/OTX/AbuseIPDB parsers against canned API payloads.
* `tests/integration/test_swarm_pipeline.py` — full `run_swarm()` happy path and all-agents-fail path, with every external API mocked. Exercises the LangGraph DAG end-to-end including the state-bridge re-hydration.

All tests use `pytest-asyncio` in `asyncio_mode = "auto"` — no per-test decorators.

---

## Portfolio context

What this project is designed to demonstrate:

* **AI orchestration beyond single-prompt apps** — a real DAG with four parallel agents, a correlation agent with forced-tool output, and an explicit state schema. Not a "chatbot with a database."
* **Async system design** — nested `asyncio.gather` with partial-failure isolation, bounded connection pool (`aiohttp.TCPConnector(limit=20, keepalive_timeout=30)`), exponential backoff *plus* a `retry_on_disconnect` decorator that handles the distinct case of socket close before HTTP response.
* **Typed contracts at every boundary** — Pydantic v2 models across the whole flow, computed fields, `model_validator(mode="after")` for cross-field derivations, discriminated enums for sources and severities. No `dict[str, Any]` exposed outside of model internals.
* **Security domain fluency** — CVSS v3.1 scoring, MITRE ATT&CK tactic/technique modelling, ECS-aligned alert emission, KEV/OTX/AbuseIPDB/GreyNoise integration. The output plugs into real SIEM pipelines, not a toy dashboard.
* **Test discipline** — 43 tests covering the model layer, every tool client, and the full DAG end-to-end, using `AsyncMock` to stub the async boundary without integration-testing the external APIs.

---

## Stack

| Layer | Choice | Why |
|---|---|---|
| Orchestration | LangGraph `StateGraph` | Typed state schema, declarative edges, checkpointable |
| LLM | Anthropic Claude (Sonnet) via structured `tool_choice` | No JSON parsing; schema-validated output |
| Contracts | Pydantic v2 | `model_validator`, `computed_field`, `Field(pattern=...)` |
| HTTP | `aiohttp` with `TCPConnector(limit=20)` | Shared pool across agents, keep-alive |
| Persistence | `aiosqlite` | Reports + SIEM alerts queried via FastAPI |
| API | FastAPI + uvicorn | `/api/v1/runs`, `/reports`, `/alerts`, OpenAPI docs at `/docs` |
| Logging | `structlog` | JSON logs ready for SIEM ingest |
| Tests | `pytest-asyncio` + `unittest.mock.AsyncMock` | Full async coverage, no external deps |

Python 3.11+, declared in `pyproject.toml`.
