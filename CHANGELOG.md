# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — P1 follow-ups from audit run #2

- **`NormalizedThreat.original_confidence`** — provider-original IOC
  confidence snapshotted at normalization time (`normalize_ioc`), so the
  report coordinator's IOC sidecar can emit the raw value for
  `scripts/extract_iocs.py`'s firewall gate instead of deriving a
  synthetic value from (possibly enrichment-bumped) severity.
- **`NormalizedThreat.enrichments_applied`** — per-agent idempotency
  marker. The three mutating enrichment agents (EPSS, VirusTotal, Shodan)
  now short-circuit on re-entry if their name is already in the list. The
  current graph runs enrichment once, but the flag makes a future
  remediation loop double-bump-safe.
- Unit coverage for both contracts in
  `tests/unit/test_enrichment_idempotency.py` (6 tests): confidence
  snapshot preservation, per-instance list isolation, EPSS double-pass
  no-op.

### Changed — CI

- **mypy strict promoted from advisory → blocking** in
  `.github/workflows/ci.yml`. With the codebase at 0 mypy errors across 38
  source files, any regression now fails the build. Revert via
  `continue-on-error: true` during major refactors.

### Added

- **Docker image** (`Dockerfile`) — multi-stage, non-root `tia` user (uid
  10001), tini as PID 1, curl-based `HEALTHCHECK` against `/api/v1/health`.
  Entrypoint (`docker-entrypoint.sh`) dispatches on first arg: `cli` for
  one-shot swarm runs, `api` for long-running uvicorn, `dry-run` for a
  smoke check, `shell` for debugging.
- **`docker-compose.yml`** — local dev stack with a named-volume `api`
  service and a profile-gated `cli` sibling for ad-hoc runs.
- **systemd units** (`deploy/systemd/`) — `threat-intel-api.service` for
  the long-running dashboard; templated `threat-intel@.service` +
  `.timer` for keyword-specific cron-style runs. Both ship with a strict
  sandboxing envelope (`NoNewPrivileges`, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, empty `CapabilityBoundingSet`, restricted
  syscall filter).
- **Pre-commit hooks** (`.pre-commit-config.yaml`) — ruff check + format
  auto-fix on commit; mypy strict as a manual-stage hook (`pre-commit run
  mypy --hook-stage manual`). Standard hygiene hooks: trailing whitespace,
  EOF-fixer, merge-conflict check, private-key detector, large-file
  guard.
- **ECS field-name contract test** (`tests/unit/test_ecs_schema.py::TestECSFieldContract`)
  — pins Elastic Common Schema version `9.3.0`, walks every
  `_to_ecs()` output and asserts every dotted field path is in the
  declared ECS allow-list. Catches rename drift at CI time.
- **`_stratified_sample` perf canary** (`tests/unit/test_correlation_sampling_perf.py`)
  — zero-dep `time.perf_counter` budget tests at n=100 / 1000 / 10000,
  with generous ceilings (20 / 50 / 500 ms) that catch quadratic
  regressions without flaking. Current observed: n=10k in ~3 ms.

### Changed

- README — quickstart now documents container + systemd deploys and
  local-dev pre-commit setup.

---

## [2.0.0] — 2026-04-16 — Enterprise swarm

V2 layers dynamic routing, LLM enrichment, immutable overlays, and a real
security envelope on top of the V1 ingest-and-correlate core.

### Added

- **Supervisor agent** (`src/agents/supervisor.py`) — analyses query keywords and
  emits `swarm_config.activate_agents` via a Claude structured tool call. The
  DAG's ingestion + enrichment fan-outs honor the activation list through the
  `_INGEST_AGENTS` and `_ENRICHMENT_AGENTS_TIER1` name registries in
  `src/graph/swarm.py`. Falls back to a default full-swarm config when the
  supervisor is skipped (no keywords / no key) or the LLM call fails.
- **Enrichment tier** — four new agents run after normalization:
  - `epss_enrichment` (FIRST.org EPSS — exploit probability)
  - `virustotal_enrichment` (detection ratios + malware families, free tier)
  - `github_advisory` (supply-chain CVE context — affected packages, GHSA ids)
  - `shodan_enrichment` (exposed services + dangerous-port flag)
- **Immutable-overlay pattern** — `NormalizedThreat.enriched_severity` and
  `enriched_tags` land every enrichment write; `effective_severity` and
  `effective_tags` are computed fields that merge the provider-original and
  enrichment views. Enrichment agents never mutate `severity` / `tags` /
  `cve_ids` in place, so `content_hash` stays valid.
- **Reflection agent** (`src/agents/reflection.py`) — LLM scores report
  confidence 0–1, identifies intelligence gaps, appends an "Analyst reflection"
  section to the markdown. Deliberately passive; the non-goal (conditional
  edge back to enrichment) is documented in the module docstring.
- **Post-enrichment dedup pass** — `_enrichment_node` runs
  `NormalizationPipeline.dedup()` a second time over the enrichment-merged
  threat list so EPSS "top actively exploited" extras don't duplicate CVEs
  already in the ingest pass.
- **`raw_iocs` end-to-end** — `ioc_extractor_agent` returns the raw
  `IOCRecord` list alongside `agent_results`; `_parallel_ingest_node`
  accumulates into `SwarmState.raw_iocs`; the report coordinator emits the
  IOC sidecar from real provider data instead of synthesising from severity.
- **Typed IOC type + threat type** — `NormalizedThreat.ioc_type` is a
  `Literal["ipv4","ipv6","domain","md5","sha1","sha256","url","email"]`
  populated by `normalize_ioc`; `NormalizedThreat.threat_type` is a
  `Literal["cve","technique","ioc","feed_item"]`. Downstream consumers read
  typed fields instead of fishing from `tags`.
- **API auth gate** — `X-API-Key` header required on `/api/v1/runs` + all
  report/alert read endpoints when `TIA_API_KEY` is set. Uses
  `secrets.compare_digest` for constant-time comparison. `/api/v1/health`
  stays unauthenticated for k8s-liveness.
- **CORS pinning** — `TIA_CORS_ORIGINS` env var (comma-separated, wildcards
  stripped). Default is localhost only.
- **SecretStr wrapping** — every `*_API_KEY` env read in `main.py::_build_config`
  and `src/api/app.py::_run_swarm_background` wraps in `pydantic.SecretStr`.
  `BaseAPIClient` unwraps on construction; three Anthropic SDK call sites use
  `unwrap_secret(...)` at the point of use.
- **SSRF validators** — `is_valid_ip` / `is_valid_domain` / `is_valid_hash`
  in `src/tools/base_client.py`. Applied to Shodan `lookup_ip`, VirusTotal
  `enrich_ip` / `enrich_domain` / `enrich_hash`, AbuseIPDB `check_ip`,
  GreyNoise `fetch_riot_data` / `fetch_noise_status`.
- **Real `/health` endpoint** — probes SQLite, reports Anthropic-key presence
  (not value), reports auth mode (`enabled` / `dev-mode`).
- **SQLite WAL + indexes** — `PRAGMA journal_mode=WAL`,
  `synchronous=NORMAL`, `busy_timeout=5000`; indexes on
  `reports.generated_at DESC`, `siem_alerts.created_at DESC`,
  `siem_alerts.severity`, `siem_alerts.run_id`.
- **`StateGraph(SwarmState)` native** — LangGraph now owns the Pydantic state
  directly; node signatures are typed `(state: SwarmState, config: RunnableConfig)`.
  The legacy dict-bridge `_to_state()` is retained only as defensive
  coercion at the graph-exit boundary.
- **`structlog.contextvars.bind_contextvars(run_id=…)`** — every log line
  during a swarm run carries the `run_id` for free.
- **Enrichment boilerplate decorator** — `src/agents/_enrichment_base.py::enrichment_agent(name=...)`
  absorbs the stopwatch + try/except + envelope pattern. Enrichment agent
  bodies are 30–50 LOC instead of 80+.
- **Operational scripts** (`scripts/`):
  - `auto_block.sh` — orchestrator: extract → nftables → DNS → Wazuh syslog
  - `extract_iocs.py` — sidecar-first IOC extractor
  - `nftables_block.sh` — idempotent firewall set loader with IPv4 regex guard
  - `dns_block.sh` — `/etc/hosts` sinkhole with env-overridable `OUTPUT_DIR`
  - `verify_blocks.sh` — post-block verification
  - `install_cron.sh` / `uninstall_cron.sh` — 6-hour schedule
  - `cleanup_output.sh` — rotate old reports
- **Prometheus exporter** (`src/integrations/prometheus_exporter.py`) —
  pushgateway payload with per-severity / per-IOC-type / per-agent metrics.
  `prometheus_client` import is lazy; exporter gracefully skips when the dep
  is absent or the pushgateway is unreachable.
- **Wazuh UDP forwarder** (`src/integrations/wazuh_client.py`) — RFC 5424
  syslog to the Wazuh manager's `:1514`; graceful skip on port-unreachable.
- **Tests** — 205 total (up from 43 at V1):
  - `test_base_client_reliability.py` — RateLimiter token-bucket + retry
    decorator + SecretStr unwrap
  - `test_url_validators.py` — 27 cases for `is_valid_ip` / `_domain` / `_hash`
  - `test_correlation_sampling.py` — `_stratified_sample` round-robin +
    quota rollover + `effective_severity` consumption
  - `test_supervisor_agent.py` — LLM-mocked routing, failure fallback,
    SecretStr unwrap at SDK boundary
  - `test_reflection_agent.py` — markdown append, gaps in executive
    summary, all failure-mode no-ops
  - `test_api_auth.py` — dev-mode pass-through, 401 paths, health
    unauthenticated, CORS wildcard stripping
  - `test_ecs_schema.py` — inline schema validator over every `_to_ecs()`
    output + severity integer mapping
  - `test_dns_block_idempotency.py` — `dns_block.sh` convergence
- **CI / tooling**:
  - `pyproject.toml` — upper-bound pins on every core dep
    (`anthropic<2`, `langgraph<1`, `pydantic<3`, `aiohttp<4`, …)
  - `prometheus-client<1` as a core dep
  - Ruff config with documented ignore list (`TC001/002/003` — cosmetic
    given `from __future__ import annotations`)
  - mypy strict mode: 0 errors across 38 source files
  - `StrEnum` migration for `Severity` and `ThreatSource` (Python 3.11+)

### Changed

- **NVD 2.0 client** — `pubStartDate` / `pubEndDate` are now required query
  params (empty windows previously 404'd fatally); `keywordExactMatch`
  removed (string bool rejected by NVD v2); `calls_per_second = 5.0`
  unkeyed / `50.0` keyed to match NVD's published rate limits.
- **CISA KEV keyword filter** — now matches on `tags` too. Ransomware-tagged
  KEVs (313 across the catalogue, only ~1 per 30-item window) were being
  starved; fetch window widens to 300 when keywords are active.
- **AbuseIPDB rate limiting** — honors `Retry-After` up to a
  `MAX_RETRY_AFTER_SECONDS = 60` cap. AbuseIPDB's free tier sends
  19-hour retry-after values on exhaustion; the cap converts those to a
  fail-fast so they can't stall the whole swarm.
- **Correlation prompt sampling** — `_stratified_sample` now round-robins
  across `threat_type` inside each severity tier *regardless of input size*.
  The old `len(threats) <= limit` short-circuit returned CVE-heavy inputs
  verbatim and starved IOCs / techniques.
- **Enrichment agents' sidecar input** — `_sidecar_from_state` reads
  `effective_severity` (enrichment-informed) so EPSS / VT / Shodan severity
  upgrades flow through to the firewall/DNS blocklist gate in
  `scripts/extract_iocs.py`.

### Fixed

- `CVERecord.severity` derivation — was never triggered because
  `field_validator(mode="before")` is skipped when a field falls back to its
  default; migrated to `model_validator(mode="after")`.
- LangGraph state-bridge `raw_iocs` mismatch — `report_coordinator` read
  `state.raw_iocs` but the field didn't exist on `SwarmState`; now declared
  and populated.
- VirusTotal client — `enrich_batch` was called on a closed session (the
  `async with` block ended one line too early).
- All remaining `datetime.utcnow()` → `datetime.now(UTC)` across the
  codebase (Python 3.12+ deprecates naive UTC).

### Removed

- Dead supervisor code path — before V2 the supervisor's `swarm_config`
  output was billed but ignored by the fan-out nodes. Either honor it or
  delete; V2 honors it.

---

## [1.0.0] — 2026-01 — Initial swarm

First public cut. Establishes the core pattern the V2 tier builds on.

### Added

- **LangGraph `StateGraph` DAG** with four parallel ingestion agents:
  `cve_scraper` (NVD), `attack_mapper` (MITRE ATT&CK STIX),
  `ioc_extractor` (OTX + AbuseIPDB), `feed_aggregator` (CISA KEV +
  GreyNoise). All fire concurrently via `asyncio.gather`; inner
  per-agent gathers isolate partial failures.
- **Pydantic v2 contracts** end-to-end — `CVERecord`, `ATTACKTechnique`,
  `IOCRecord`, `ThreatFeedItem` per source; `NormalizedThreat` as the
  cross-source canonical shape; `CorrelatedIntelReport` as the LLM
  output schema.
- **Content-hash dedup** — SHA-256 over lowercase title + sorted CVE /
  TTP / IOC ids, truncated to 16 chars. Cross-source CVEs from NVD +
  MITRE hash to the same value and merge their `sources` lists.
- **Claude correlation** via `tool_choice={"type":"tool","name":"produce_intel_report"}`.
  No free-text JSON parsing; the tool's `input_schema` mirrors
  `CorrelatedIntelReport`.
- **Three output artifacts** per run under `output/TIA-<id>_<ts>`:
  - `.md` — markdown brief (executive summary, severity histogram,
    patch priority, threat clusters, SIEM alert table, run metadata)
  - `.json` — full `CorrelatedIntelReport.model_dump(mode="json")`
  - `_siem_alerts.ndjson` — ECS-aligned SIEM events with
    `event.severity` as the 1–100 integer Elastic expects
- **FastAPI dashboard** (`src/api/app.py`) — `POST /api/v1/runs`,
  `GET /api/v1/reports`, `GET /api/v1/reports/{run_id}`,
  `GET /api/v1/reports/{run_id}/markdown`,
  `GET /api/v1/alerts?severity=HIGH`, `GET /api/v1/health`.
- **aiohttp base client** (`BaseAPIClient`) — token-bucket rate limiter,
  exponential-backoff retries on 5xx/429/timeout, bounded `TCPConnector`
  (`limit=20`, `keepalive_timeout=30`), `retry_on_disconnect` decorator
  for socket-level failures before any response.
- **structlog** JSON logs (toggleable via `LOG_FORMAT=json`).
- **CLI** — `python main.py --keywords … --max-cves …`, `--dry-run`,
  `--serve`.
- 43 async-aware tests with `pytest-asyncio` in `auto` mode.

[Unreleased]: https://example.com/compare/v2.0.0...HEAD
[2.0.0]: https://example.com/compare/v1.0.0...v2.0.0
[1.0.0]: https://example.com/releases/tag/v1.0.0
