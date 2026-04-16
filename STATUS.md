# Project Status — handoff snapshot

**Last updated:** 2026-04-16
**Remote:** https://github.com/richmuscle/threat-intel-aggregator (public)
**Branch:** `main` — clean, in sync with origin
**Latest commit:** `50514fc chore(hardening): post-release audit polish`

---

## One-paragraph state

V2 enterprise swarm — eleven LangGraph-orchestrated agents (4 ingest, 4
enrichment, supervisor, reflection, report coordinator, correlation agent)
feeding a Claude correlation layer and emitting markdown + JSON + ECS SIEM
alerts. The codebase is at the **"production-ready, engineer would hand to
oncall"** baseline: 219 tests pass, mypy strict at 0 errors across 38
source files, ruff lint + format at 0 violations. Six audit/engineering
sessions have moved the composite score from 6.8 → ~9.0 with two `/audit`
pipeline runs documented under `AUDIT_REPORT.md` + `PATCHES.md`.

---

## Verification — what's green right now

| Check | Expected |
|---|---|
| `python -m pytest tests/ -q` | **219 passed / 0 failed** in ~2.6s |
| `python -m mypy src/` (strict) | **0 errors / 38 files** |
| `python -m ruff check src/ tests/` | **All checks passed** |
| `python -m ruff format --check src/ tests/` | **59 files formatted, 0 drift** |
| `python main.py --dry-run` | **exit 0** (warnings for missing optional keys) |
| GitHub Actions `CI` run on `50514fc` | **success in 45s** (ruff + format + mypy strict + pytest, all blocking) |

---

## Verification — one-command sanity from clean clone

```bash
git clone git@github.com:richmuscle/threat-intel-aggregator.git
cd threat-intel-aggregator
pip install -e ".[dev]"
cp .env.example .env                 # fill ANTHROPIC_API_KEY at minimum
pre-commit install                   # local hooks
python -m pytest tests/ -q           # 219 pass
python main.py --dry-run             # config validated
```

---

## Architecture — where to look for what

```
main.py                              # CLI entrypoint; _build_config wraps env in SecretStr
src/
├── agents/
│   ├── _enrichment_base.py          # @enrichment_agent decorator
│   ├── attack_mapper.py             # MITRE ATT&CK ingest
│   ├── correlation_agent.py         # Claude structured tool_choice; _stratified_sample
│   ├── cve_scraper.py               # NVD 2.0 ingest
│   ├── epss_enrichment.py           # EPSS exploit probability overlay
│   ├── feed_aggregator.py           # CISA KEV + GreyNoise
│   ├── github_advisory.py           # Supply-chain CVE context (records-producer, not mutator)
│   ├── ioc_extractor.py             # OTX + AbuseIPDB; returns raw_iocs alongside agent_results
│   ├── reflection.py                # Passive post-correlation scorer (NOT a loop — see docstring)
│   ├── report_coordinator.py        # Markdown + JSON + ECS NDJSON + IOC sidecar
│   ├── shodan_enrichment.py         # Internet exposure overlay
│   ├── supervisor.py                # LLM routing — emits swarm_config.activate_agents
│   └── virustotal_enrichment.py     # Detection ratio + malware family overlay
├── graph/swarm.py                   # StateGraph(SwarmState); _INGEST_AGENTS + _ENRICHMENT_AGENTS_TIER1 registries
├── models/threat.py                 # Pydantic v2 contracts — StrEnum Severity/ThreatSource, Literal ThreatType/IOCType
├── pipeline/normalizer.py           # normalize_cve/_technique/_ioc/_feed_item + NormalizationPipeline.dedup
├── tools/base_client.py             # TCPConnector + RateLimiter + retry_on_disconnect + SSRF validators + SecretStr unwrap
├── tools/nvd_client.py              # NVD 2.0 with pubStartDate + 404-as-empty
├── tools/shodan_client.py           # ?key= (API constraint — not a bug)
├── tools/virustotal_client.py       # is_valid_ip / _domain / _hash guards
└── api/app.py                       # FastAPI + X-API-Key + CORS pinning + /health

tests/                               # 17 files, 219 tests
├── integration/test_swarm_pipeline.py
└── unit/                            # models, tool clients, agents, reliability, ECS, perf canary, etc.

scripts/                             # operational automation (nftables, DNS, cron)
deploy/systemd/                      # threat-intel-api.service + @keyword.service/.timer + README.md
Dockerfile + docker-compose.yml + docker-entrypoint.sh
.github/workflows/ci.yml             # ruff + format + mypy strict (blocking) + pytest
.pre-commit-config.yaml              # ruff auto-fix + hygiene hooks; mypy manual-stage
```

---

## Key design invariants (don't break these)

1. **Immutable enrichment.** Enrichment agents never mutate
   `NormalizedThreat.severity` / `tags` / `cve_ids` in place. They write to
   `enriched_severity` / `enriched_tags` overlays. Consumers read
   `effective_severity` / `effective_tags` (computed fields) when they want
   the post-enrichment view.
2. **Content hash is identity-only.** `compute_hash()` deliberately excludes
   `severity` / `tags` / `enriched_*` so enrichment mutations don't shift
   the hash. Dedup converges; re-enrichment is possible.
3. **Per-agent idempotency.** Enrichment agents check
   `"<name>" in threat.enrichments_applied` on entry, skip if set, append
   their name after touching. The graph runs enrichment once today; the
   flag makes a future remediation loop double-bump-safe.
4. **Secrets never repr.** Every `*_API_KEY` env read goes through
   `pydantic.SecretStr`. `BaseAPIClient.__init__` unwraps once on
   construction; three Anthropic SDK sites use `unwrap_secret(...)` at
   point of use. A stray `logger.info("config", config=cfg)` would print
   `SecretStr('**********')`, not the key.
5. **API gate.** When `TIA_API_KEY` is set, every non-health endpoint
   requires `X-API-Key`. Comparison uses `secrets.compare_digest`
   (constant-time). `/api/v1/health` stays unauthenticated for k8s
   liveness.
6. **SSRF guards.** Any IP / domain / hash that reaches a URL path goes
   through `is_valid_ip` / `is_valid_domain` / `is_valid_hash` first.
   Seven tool-client methods gated.
7. **Supervisor output is honoured.** `_parallel_ingest_node` and
   `_enrichment_node` gate fan-out on `state.swarm_config.activate_agents`
   via the `_INGEST_AGENTS` / `_ENRICHMENT_AGENTS_TIER1` registries.
   Supervisor's LLM call is not dead code.

---

## What's queued (not blocking ship)

### P2 — code layer

- **P2-A** Split `src/agents/report_coordinator.py` (420 LOC) into
  `report_markdown.py` + `ioc_sidecar.py` + `ecs_emitter.py`. Three
  concerns, one module today.
- **P2-C** Generalise `_hydrate` / `_to_state` into a field-walker over
  `SwarmState.model_fields` so new rehydrated types don't need an
  `isinstance` branch.
- **P2-D** Per-node TypedDict envelopes for LangGraph node returns.
  **Previously rejected** (cost 70 LOC, benefit catches typos that don't
  occur). Only revisit if a silent-key bug actually ships.

### Ops / infra (not in the report because they're infrastructure, not code)

- **SECURITY.md** — vuln-disclosure policy + contact. ~10 min.
- **`.github/dependabot.yml`** or Renovate config. ~10 min.
- **Grafana dashboard JSON** for the Prometheus metrics exporter emits but
  the repo ships no dashboard. ~30 min.
- **Alerting rules** for `threat_intel_run_duration_seconds` (stall
  detection) + `threat_intel_siem_alerts_total` (surge detection). ~20 min.
- **Real ECS E2E test** — GitHub Actions job that spins
  `docker run elastic/elasticsearch`, POSTs the generated NDJSON, confirms
  the mapping works against a live Elastic. ~60 min.

### Known coverage gaps (unit-level, not integration)

- `src/integrations/es_indexer.py` — ~0% coverage (conditional on a live
  Elastic cluster). Add `tests/unit/test_es_indexer.py` with
  `aioresponses`-mocked client.
- `src/integrations/prometheus_exporter.py` — payload shape tested; push-
  gateway failure paths light.
- Enrichment agent error-path unit tests — happy paths covered; failures
  currently rely on the integration test.

---

## Session history highlights

Six engineering sessions produced the current state. Headline deltas:

| Session | Outcome |
|---|---|
| Initial | Fixed two real bugs (CVERecord severity derivation, LangGraph state bridge); 43 → 43 tests pass after. |
| Audit run #1 | Scored 6.8 / 10. P0 queue: immutable enrichment, supervisor wiring, `raw_iocs` end-to-end, post-enrichment dedup, SecretStr, API auth + CORS, `StateGraph(SwarmState)`, reliability unit tests. |
| Tier 1+2 polish | All P0 queue cleared. `.env.example` adds `TIA_API_KEY` / `TIA_CORS_ORIGINS`. Score ≈ 9.0. |
| Tier 3 polish | Enrichment decorator, ECS contract test, SSRF validators extended, stratified-sample fix, ruff clean, 197 tests. |
| Nice-to-haves | Pre-commit config, perf canary (n=10k in 3ms), Docker + compose + systemd units, CHANGELOG (Keep-a-Changelog V1/V2), StrEnum migration. |
| Audit run #2 | Scored 7.1 / 10 raw; orchestrator-adjusted to 9.0 (two of four P0s rejected: Shodan API-contract false positive, TypedDict envelopes subjective). LLM_MODEL parameterized. |
| P1 follow-ups | `original_confidence` snapshot, `enrichments_applied` idempotency, mypy promoted to CI-blocking. 219 tests. |

Full history in `CHANGELOG.md` (Keep-a-Changelog format) + `AUDIT_REPORT.md`
+ `PATCHES.md`.

---

## Gotchas / landmines for the next engineer

1. **Shodan API key in URL query param is correct** — Shodan's REST API
   does not support `Authorization: Bearer`. Don't "fix" it.
2. **`_hydrate` isinstance branches will grow** — three today; if we cross
   ~6, refactor to the field-walker (P2-C) before adding the next.
3. **`prometheus_exporter.py` lazy-imports `prometheus_client`** — the
   import lives inside `push_metrics()` so the module loads fine without
   the dep. Core install ships it anyway since 2.0.0.
4. **`.env.example` has a host-specific path** for `ES_CA_CERT` — fine for
   development reference; replace if this repo ever becomes community-
   facing documentation.
5. **The one commit pushed with `ee25b58` ≠ V1.0.0 literally** — there's
   no V1.0.0 tag. CHANGELOG's [1.0.0] section is a retroactive
   reconstruction. If you cut a V3 tag, also backfill tags for V1 + V2
   against the relevant commits.
6. **Remote is SSH** — `git@github.com:richmuscle/threat-intel-aggregator.git`.
   HTTPS push was rejected by an OAuth scope check on `.github/workflows/`.
   Either keep SSH, or refresh your gh token: `gh auth refresh -h github.com -s workflow`.

---

## If something regresses

CI blocks ruff + format + mypy strict + pytest. A push that fails any of
these gets a red X on the PR. First action on a red CI:

1. Pull the failing job log from the Actions tab.
2. Reproduce locally — `python -m pytest tests/ -q` or
   `python -m mypy src/` or `python -m ruff check src/ tests/`.
3. Fix, re-run, push. Don't `--no-verify` or `continue-on-error` the
   blocking step — if mypy strict genuinely needs to be advisory for a
   refactor, flip the flag, land the refactor, flip back in the same PR.

---

*Session closed cleanly. Everything that can be on remote, is.*
