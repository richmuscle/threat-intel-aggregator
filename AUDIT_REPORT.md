# AUDIT_REPORT.md — Threat Intel Aggregator

**Audit date:** 2026-04-16
**Orchestrator:** Claude Opus 4.6 (1M) · effort=max · Palantir-style agentic run
**Subagents:** audit-agent (Haiku · five-lens) · recon-agent (Haiku · shell) · security-agent (Haiku · posture)
**Scope:** read-only. No code changes in this pass. Patch gate is at the end of this document.

---

## Composite Verdict

| Field | Value |
|-------|-------|
| **Composite score** | **8.7 / 10** |
| **Hire signal** | **Strong Pass** — principal-level submission |
| **Best-fit role** | AI orchestration / async platform / detection engineering |
| **Dominant strength** | Contract-driven async orchestration. LangGraph DAG + Pydantic v2 + forced `tool_choice` JSON — no loose dicts cross agent boundaries, no regex prompt parsing, no silent key drops. |
| **Root-cause gap** | Documentation drift. CLAUDE.md trails the code by two sessions; claims 43 tests when pytest passes 219; lists P1–P4 as pending when they're implemented. One moderate security seam (optional `TIA_API_KEY` auth bypass) and a handful of ruff E501 violations. |

**One-sentence verdict:** *Production-grade AI-swarm threat-intel platform with rigorous typed contracts, 219 passing tests, and mature async patterns — held back from 9+ only by documentation drift, one optional-auth escape hatch, and light coverage on optional enrichment clients.*

---

## Scores (per lens)

| Lens | Score | Note |
|------|:-:|------|
| Architecture | **9** | LangGraph `StateGraph(dict)` with full-state-return invariant; supervisor → parallel ingest → normalize → parallel enrich → correlate → reflect → report. Extensibility seam (`@enrichment_agent` decorator, `enrichments_applied` idempotency list) is load-bearing and explicit. |
| CS depth | **9** | Async-correct (no `time.sleep`/`requests` in async paths), typed at every public boundary, `MAX_RETRY_AFTER_SECONDS=60` guard against hostile `Retry-After`, stratified-sampling math handles rounding leftover, SecretStr wrapping at config points. |
| Domain modeling | **9** | Immutable-enrichment overlay (`enriched_severity` / `enriched_tags`) protects `content_hash` dedup; SHA-256 content hashing; ECS-aligned SIEM NDJSON (`event.kind`, `rule.name`, `threat.technique.id`, `vulnerability.id`). |
| Testing | **8** | 219/219 green, 75% overall coverage, strong golden-path coverage. Shodan (23%) and VirusTotal (19%) clients are under-tested; enrichment error paths rely on integration rather than unit. |
| Ops / Security | **8** | Strict CORS (wildcards stripped), `secrets.compare_digest` for API-key check, structlog kv logging, no hardcoded keys. Lowered from 9 by optional `TIA_API_KEY` bypass, unbounded string fields into LLM prompts, and 12 ruff E501 line-length warnings. |

---

## Built-in Health Check (project `/audit` protocol)

| Step | Command | Result |
|---|---|---|
| 1. Test suite | `python -m pytest tests/ -q` | **219 passed** in 2.97s (CLAUDE.md claims 43 — stale) |
| 2. Dry run | `python main.py --dry-run` | ✓ "Dry run complete — config validated" |
| 3. Import check | cross-module smoke import | ✓ OK |
| 4. Syntax / ruff | `ruff check src/ tests/ --select E,F` | ✗ **12+ E501 line-too-long** violations |
| 5. Pending count | `grep "^### P" CLAUDE.md` | 6 listed — but grep of actual code shows P1–P4 **already applied** |

**Health = YELLOW** (tests/dry-run green; ruff red; CLAUDE.md stale).

---

## § P0 Actions — Ship Blockers

*None are blocking release. These are elevated from audit-agent P1 because of portfolio-visibility and operator-trust impact.*

### P0-1 · Fix ruff E501 violations
**Severity:** MEDIUM-as-P0 (public-repo quality signal)
**Files:** `src/agents/correlation_agent.py:217,226` · `src/agents/reflection.py:41,46,60,96,118` · `src/agents/supervisor.py:5,23,42,106` · `src/api/app.py:46`
**Why:** A shipped public portfolio project should pass its own lint. Recruiter/PM clone → `ruff check` → red exit → wrong first impression. Cheap to fix (minutes).
**Fix sketch:** Wrap long docstring/description lines at 100 chars; for log-message strings use parenthesised multiline concatenation.
**Verify:** `python -m ruff check src/ tests/ --select E,F` returns exit 0.

### P0-2 · Update CLAUDE.md to reflect current code
**Severity:** MEDIUM-as-P0 (memory-layer integrity)
**File:** `CLAUDE.md`
**Why:** CLAUDE.md is the project's session-to-session memory. It claims 43 tests (actual: 219), lists P1–P4 as pending (all implemented), stops at Session 6 (current post-release hardening is Session 8+). Every future Claude session loads this as authoritative context — stale claims silently corrupt planning.
**Fix sketch:** (a) Update "Test status" header from `43/43` → `219/219`; (b) move P1–P4 from "Pending" to an "Applied" section with dates; (c) add Session 7 (post-release hardening / STATUS.md) and Session 8 (this audit) to the Session Log; (d) document the `enrichments_applied` idempotency contract and the immutable-enrichment overlay pattern (both are load-bearing and undocumented in CLAUDE.md — STATUS.md has them, but CLAUDE.md is what sessions load first).
**Verify:** `grep -c "^### P[0-9]" CLAUDE.md` reports accurate remaining count; `grep "219" CLAUDE.md` returns at least one hit.

### P0-3 · Harden `TIA_API_KEY` enforcement
**Severity:** HIGH (auth bypass in dev-mode fallback)
**File:** `src/api/app.py:40-63`
**Why:** When `TIA_API_KEY` is unset, `require_api_key()` returns early (line 60-61). The author's comment at line 32-35 says "still *require* a header" — but the implementation contradicts the comment. If `uvicorn` is launched with `--host 0.0.0.0` (docker-compose default is often this) and `TIA_API_KEY` is forgotten in the env, every write endpoint (`POST /api/v1/runs`) is unauthenticated. The loud startup warning depends on someone reading logs before the blast radius expands.
**Impact:** Anonymous internet clients can trigger swarm runs, read report history, and extract SIEM alert payloads.
**Fix sketch:** Fail fast. In `lifespan()`, if `_API_KEY_ENV` is `None` AND `TIA_API_HOST` is not `127.0.0.1`, raise `RuntimeError("TIA_API_KEY must be set for non-loopback binds")`. For explicit dev bypass, require `TIA_AUTH_MODE=disabled` (sentinel), never implicit-on-unset.
**Verify:** Add `tests/unit/test_api_auth.py::test_startup_fails_when_key_unset_and_nonloopback_bind`.

---

## § P1 Actions — This Week

### P1-1 · Cap unbounded LLM-facing string fields
**File:** `src/models/threat.py:151-152`
**Why:** `title: str` and `description: str` on `NormalizedThreat` have no `max_length`. These are interpolated into the Claude prompt via `correlation_agent._build_prompt()`. The structured `tool_choice` forcing is a strong defence against jailbreaks, but a multi-kilobyte adversarial `title` (e.g. a malicious OTX pulse name) can still crowd the context window and influence the `narrative` field inside the tool schema.
**Fix:** `title: str = Field(..., max_length=200)` · `description: str = Field(..., max_length=2000)`. Truncate at client parse time in the affected `src/tools/*_client.py` modules so validation failures don't cascade.
**Verify:** Add `tests/unit/test_normalized_threat_bounds.py` with adversarial 10KB title input → expect `ValidationError`.

### P1-2 · Raise test coverage on enrichment clients
**Files:** `src/tools/shodan_client.py` (23%) · `src/tools/virustotal_client.py` (19%) · `src/tools/attack_client.py` (28%) · `src/agents/correlation_agent.py` (29%) · `src/agents/report_coordinator.py` (19%)
**Why:** Already called out as P6 in CLAUDE.md. The optional enrichment clients are the most brittle ingestion points (rate limits, quota exhaustion, API schema drift) and the least tested.
**Fix:** For each client, add parameterised `aioresponses`-mocked tests for 200, 404, 429 (incl. hostile `Retry-After`), 5xx, malformed JSON, and socket timeout.

### P1-3 · Snapshot `effective_severity` / `effective_tags` before correlation
**File:** `src/graph/swarm.py` (post-enrichment node) · `src/models/threat.py`
**Why:** Today `effective_severity` is a `@computed_field` that reads live enrichment overlays. If a future reflection loop ever re-triggers enrichment (explicitly out-of-scope today but a landmine), the stratified-sample distribution for the re-run differs from the first pass — subtly non-deterministic.
**Fix:** Add `final_severity: Severity | None = None` / `final_tags: list[str] = []` fields, populated once at the end of enrichment. `correlation_agent` and the report read snapshots.

### P1-4 · Refactor `report_coordinator.py` (430 LOC, three concerns)
**File:** `src/agents/report_coordinator.py`
**Why:** Merges markdown rendering, ECS NDJSON serialisation, and IOC sidecar extraction. High touch-friction; any change ripples through three test suites.
**Fix:** Split into `report_markdown.py`, `report_ecs_emitter.py`, `ioc_sidecar_extractor.py`. Coordinator becomes a dispatcher.

### P1-5 · Tighten `.env` file permissions to 0600
**File:** `~/dev/projects/threat-intel-aggregator/.env`
**Why:** Currently 640 (group-readable). Six real keys present (ANTHROPIC, NVD, OTX, AbuseIPDB, VirusTotal, GitHub). Gitignored (never committed, verified via `git log --all -- .env`). Low risk on single-user box; non-zero on shared hosts.
**Fix:** `chmod 600 ~/dev/projects/threat-intel-aggregator/.env`. No code change.

---

## § P2 Actions — This Month

| # | Title | File | Note |
|---|---|---|---|
| P2-1 | Parameterised tests for `_SEVERITY_CONFIDENCE` map | `src/agents/report_coordinator.py:290` | Silent change to mapping flips IOC sidecar gates |
| P2-2 | `TypedDict` envelopes for LangGraph node returns | `src/graph/swarm.py:104-289` | Catches typo'd state keys at type-check time (~70 LOC) |
| P2-3 | Generalise `_hydrate` field rehydration | `src/graph/swarm.py:58-95` | Three `isinstance` branches → single annotation-walker |
| P2-4 | Sanitise error messages in log lines | `src/agents/cve_scraper.py:59`, others | `str(exc)` can leak library internals; log exception **type + status** only |
| P2-5 | Document `enrichments_applied` invariant in docstring | `src/models/threat.py:190-197` | Load-bearing; currently only comment-level |
| P2-6 | Add pre-commit hook for ruff + secret-scan | `.pre-commit-config.yaml` | Prevents future E501 drift and accidental key leaks |

---

## § Adversarial Critiques (steelmanned)

Six critiques a skeptical reviewer might raise — and the neutralising move already present in the code.

1. **"Stratified sampling loses budget to rounding."**
   → Code explicitly carries leftover: `leftover = int(_TIER_QUOTA[tier] * effective_limit) - target + leftover; if leftover < 0: leftover = 0`. Final fill-loop consumes remaining budget. Verified by `test_correlation_sampling.py::test_stratified_sample_convergence`.

2. **"SecretStr wrapping could be bypassed at a new call site."**
   → Wrapping happens once per config source; downstream call sites must explicitly `unwrap_secret(...)` at the point of use. A new bare-dict call site would stand out in review.

3. **"`raw_iocs` silently defaults to empty on ioc_extractor failure."**
   → Intentional graceful-degradation (STATUS.md documents this). Sidecar falls back to synthesising from `NormalizedThreat`. Tested in `test_ioc_extractor_agent` with mock failures.

4. **"Reflection agent could be turned into an active loop and break dedup."**
   → Docstring at `src/agents/reflection.py:7-17` is explicit: "Explicitly does **not** trigger re-enrichment or re-ingestion when confidence is low — diagnostic, not remedial." Design decision deserves a `DECISIONS.md` entry so a future contributor doesn't inadvertently add a conditional edge.

5. **"Supervisor LLM outage silently degrades to full-swarm mode."**
   → Intentional. Supervisor is an optimisation, not a requirement. `supervisor_failed_using_defaults` log entry is alertable.

6. **"Unbounded Pydantic strings → prompt injection via scraped titles."**
   → Real seam; see P1-1. `tool_choice` forcing mitigates jailbreaks but not content manipulation within the schema.

---

## § CLAUDE.md Drift Inventory

What CLAUDE.md claims vs. what the repo actually contains (verified by direct file reads, not trust):

| Claim | Reality |
|---|---|
| "43/43 tests passing" | 219/219 passing (2.97s) |
| P1 stratified sampling pending | Implemented in `correlation_agent._stratified_sample` with tier quotas + round-robin |
| P2 TCPConnector pending | Implemented in `base_client.__aenter__` (limit=20, keepalive=30) |
| P3 ServerDisconnectedError retry pending | Implemented in `base_client` retry decorator |
| P4 `NormalizationPipeline.dedup()` pending | Implemented; swarm.py calls the method |
| Session log ends at Session 6 (V2 build) | Repo has Session 7 (public release, hardening) and Session 8 (STATUS.md) commits |
| `enrichments_applied` idempotency pattern | Undocumented in CLAUDE.md; documented in STATUS.md |
| Immutable-enrichment overlay (`enriched_severity`/`enriched_tags`) | Undocumented in CLAUDE.md; documented in `threat.py` comment at line 180-188 |

---

## § Recon Appendix — Technical Inventory

### Largest source files
`src/agents/report_coordinator.py` (430 LOC) · `src/api/app.py` (~385) · `src/graph/swarm.py` (~290) · `src/agents/correlation_agent.py` (~235).

### Dependency posture
All pinned to major-version boundaries. No known active CVEs.

| Package | Version | Risk |
|---|---|:-:|
| `anthropic` | 0.95.0 | Low |
| `aiohttp` | 3.13.5 | Low |
| `pydantic` | 2.13.1 | Low |
| `langgraph` | 1.1.6 | Low |
| `fastapi`, `uvicorn`, `aiosqlite`, `structlog` | — | Low |

### Env var inventory
`ANTHROPIC_API_KEY`, `NVD_API_KEY`, `OTX_API_KEY`, `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY`, `GITHUB_TOKEN`, `TIA_API_KEY`, `TIA_CORS_ORIGINS`, `TIA_API_HOST` (deployment).

### Test/source ratio
21 test files · 38 source files · ratio 0.55. Healthy for a Python swarm project.

### Git hygiene
3 clean commits on `main` — `feat:` (initial release) → `chore(hardening):` (post-release polish) → `docs:` (STATUS.md). Conventional-commit discipline. No `main` pushes mid-work.

### Code-smell sweep
One `except Exception:` in `src/integrations/es_indexer.py:75` worth narrowing (see P2). No `print()` in async paths. No `time.sleep`/`requests`/`urllib` in async code. Zero hardcoded secrets.

---

## § Security Appendix

| Area | Posture | Note |
|---|---|---|
| Secrets in source | ✓ clean | Zero hardcoded keys; `.env` gitignored; `git log --all -- .env` empty |
| `.env` perms | ⚠ 640 | Group-readable; recommend 600 (P1-5) |
| CORS | ✓ strict | Wildcards explicitly stripped in `src/api/app.py:42` |
| API-key compare | ✓ timing-safe | `secrets.compare_digest` |
| Auth enforcement | ✗ optional fallback | P0-3: unset env → dev-mode bypass |
| Prompt-injection | ~ medium seam | `tool_choice` strong; unbounded `title`/`description` = see P1-1 |
| Async resource leaks | ✓ clean | `async with` correctly used on clients and aiosqlite |
| SSRF | ✓ none | No user-supplied URL fetch endpoints |
| Rate-limit defence | ✓ guarded | `MAX_RETRY_AFTER_SECONDS=60` blocks hostile `Retry-After` (Session 5 fix) |

---

## § Patch Log

**No patches applied in this pass.**

Per user operating rule — *"Plan before implementing. State the plan. Get confirmation. Then act."* — the patch-agent was **not** spawned. P0 fixes are gated on explicit human approval.

When you authorise, the patch flow is:
1. Spawn `patch-agent` in an isolated worktree with **only P0-1, P0-2, P0-3**.
2. patch-agent runs tests after each change; stops on red.
3. `verify-agent` re-runs built-in `/audit` to confirm green.
4. Orchestrator reports final health + diff summary.
5. Human reviews and `git commit` — no auto-push.

---

## § Terminal Summary

```
╔══════════════════════════════════════════════════════════════╗
║       ORCHESTRATION COMPLETE — OPUS 4.6 AGENTIC RUN          ║
╠══════════════════════════════════════════════════════════════╣
║  Composite Score:    8.7 / 10                                ║
║  Engineer Profile:   Principal / Staff — AI orchestration    ║
║                      and async platform engineering          ║
║  Root Cause Gap:     Documentation drift + optional-auth     ║
║                      escape hatch                            ║
║  Hire Signal:        Strong Pass                             ║
║  Best-Fit Role:      AI orchestration · detection eng        ║
╠══════════════════════════════════════════════════════════════╣
║  Subagents run:      3  (audit · recon · security)           ║
║  P0 actions:         3  (ruff · CLAUDE.md · TIA_API_KEY)     ║
║  P1 actions:         5  (coverage · bounds · snapshots ...)  ║
║  P2 actions:         6  (typedicts · docs · pre-commit ...)  ║
║  Patches applied:    0  (gated on user approval)             ║
╠══════════════════════════════════════════════════════════════╣
║  #1 Remaining Action:                                        ║
║  Approve P0 list → orchestrator spawns patch-agent in        ║
║  isolated worktree, fixes ruff + CLAUDE.md + TIA_API_KEY     ║
║  enforcement, verify-agent re-runs /audit, human reviews.    ║
╚══════════════════════════════════════════════════════════════╝
```
