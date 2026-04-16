# PATCHES — post-audit fix log (2026-04-16 session 8 run)

Applied: 2026-04-16  ·  Orchestrator: Claude Opus 4.6  ·  Patch agent: Sonnet 4.6

## P0-1 · Ruff E501 cleanup

Files:
- `src/agents/correlation_agent.py` (2 violations)
- `src/agents/reflection.py` (5 violations)
- `src/agents/supervisor.py` (4 violations)
- `src/api/app.py` (1 violation)

Violations fixed: 12

Representative diff (supervisor.py line 42):

Before:
```python
"description": "List of agents to activate: cve_scraper, attack_mapper, ioc_extractor, feed_aggregator, epss, virustotal, github_advisory, shodan",
```

After:
```python
"description": (
    "List of agents to activate: cve_scraper, attack_mapper, "
    "ioc_extractor, feed_aggregator, epss, virustotal, github_advisory, shodan"
),
```

## P0-2 · CLAUDE.md freshness

- 43 → 219 tests; P1-P4 moved to Applied Upgrades section with `####` headings
  (not `###`) so `grep -c "^### P[0-9]"` returns 2, not 6
- 5 load-bearing invariants documented in new `## Load-Bearing Invariants` section
- P5/P6 renumbered to P1 (reflection remediation loop) and P2 (coverage gaps)
- /audit prompt updated: expected pending count now 2
- Session 7 and Session 8 appended to Session Log

## P0-3 · TIA_API_KEY hardening (final contract: Option A — strict)

Initial patch had a regression: loopback dev (`python main.py --serve` with no key
and no opt-out) returned 503 on every protected endpoint. Resolved by tightening
the contract — there is no loopback exemption. One rule on every host.

- Removed module-level `_API_KEY_ENV = os.getenv(...)` that made monkeypatching unreliable
- Added call-time helpers: `_current_api_key()`, `_current_auth_mode()`
- Removed `_current_api_host()` helper (no longer needed; no host-dependent behaviour)
- Added `_log_auth_status_at_startup()` — emits ERROR log when `TIA_AUTH_MODE=disabled`
- Fail-fast added in `lifespan()`: raises `RuntimeError` when key is unset unless
  `TIA_AUTH_MODE=disabled` is set as an explicit dev opt-out. Loopback is NOT exempt.
- `require_api_key` returns 503 (misconfigured) when key is unset without opt-out as
  defence-in-depth; returns early only when `TIA_AUTH_MODE=disabled`
- Health endpoint updated to use `_current_api_key()` instead of removed module var
- Banner comment updated to match the new contract
- `.env.example` updated with `TIA_AUTH_MODE` entry and clearer `TIA_API_KEY` guidance
- 6 direct unit tests in `tests/unit/test_api_auth.py::TestRequireApiKeyDirect` including
  `test_lifespan_raises_when_unset_without_opt_out`
- Integration tests updated: `test_lifespan_refuses_to_start_when_unset_no_opt_out`
  (inverted from the old implicit-bypass assertion); `test_health_reports_dev_mode` and
  both `TestCORSPinning` tests now opt-in via `TIA_AUTH_MODE=disabled` so they can enter
  the TestClient context.

## Verify suite output

```
python -m pytest tests/ -q --no-header | tail -5
src/tools/shodan_client.py                   62     48    23%
src/tools/virustotal_client.py               91     74    19%
-----------------------------------------------------------------------
TOTAL                                      2252    565    75%
============================== 226 passed in 2.88s ==============================

python -m ruff check src/ tests/ --select E,F --quiet; echo "exit $?"
exit 0

python main.py --dry-run 2>&1 | grep -E "✓|✗|Error"
✓  Dry run complete — config validated, no API calls made.
```

## Deviations from spec

- New tests added to existing `tests/unit/test_api_auth.py` (file already existed)
  rather than creating a new file, to preserve the existing integration-style
  TestAuthGate and TestCORSPinning classes alongside the 6 new direct tests.
- Test count is 226 (not 225+) because 1 existing test was split into 2 to match
  the new semantics, netting +7 tests from +6 specified in spec.
- `TIA_AUTH_MODE` and `TIA_API_HOST` added to the isolation fixture and
  `_reload_app_with_env` cleanup to prevent env leakage between tests.

---

# PATCHES — post-audit fix log (2026-04-15 run)

Two P0 items forwarded to the patch agent. Two further items on the audit's
P0 list were pre-filtered as skips by the orchestrator (Shodan API contract,
TypedDict envelopes) and are documented below.

## P0-1 — Parameterize the LLM model choice — DONE

Hardcoded `model="claude-opus-4-20250514"` removed from three agent call
sites. Model now read from `config["configurable"]["llm_model"]` with the
same default so behaviour is unchanged when no override is supplied. Two
config builders plumb `LLM_MODEL` from env; `.env.example` documents it.

### Call-site change (pattern applied 3x)

Before — `src/agents/supervisor.py` (matching shape in `correlation_agent.py`
and `reflection.py`):

```python
response = await client.messages.create(  # type: ignore[call-overload]
    model="claude-opus-4-20250514",
    max_tokens=512,
```

After:

```python
model = settings.get("llm_model", "claude-opus-4-20250514")
response = await client.messages.create(  # type: ignore[call-overload]
    model=model,
    max_tokens=512,
```

(`settings` is already defined as `config.get("configurable", {})` above the
try-block in all three files — no new imports.)

### Config builders

`main.py::_build_config` — added inside the `configurable` dict:

```python
"llm_model":            os.getenv("LLM_MODEL", "claude-opus-4-20250514"),
```

`src/api/app.py::_run_swarm_background` — same key added to its local config
dict (the one built with `_secret(...)`).

### `.env.example`

Appended under the "Swarm tuning" section:

```
# LLM model for supervisor/correlation/reflection agents. Swap to a Sonnet
# id (e.g. claude-sonnet-4-5) for lower per-run cost.
LLM_MODEL=claude-opus-4-20250514
```

### Verify

- `python -m pytest tests/ -q` → 213 passed (unchanged)
- `python -m mypy src/` → Success: no issues found in 38 source files
- `python -m ruff check src/ tests/` → All checks passed

## P0-2 — `set -euo pipefail` in `scripts/cleanup_output.sh` — SKIPPED (already present)

Recon was stale. The file already sets strict mode on line 8, immediately
after the header comment block:

```bash
#!/usr/bin/env bash
# Prune old report artifacts...
# ... Override retention with --keep N (default 10).
set -euo pipefail
```

No change made. The file's other safety practices (input validation on
`--keep`, `rm -f --`, quoted expansions) are already in place.

### Verify

- `grep -n 'set -euo pipefail' scripts/cleanup_output.sh` → `8:set -euo pipefail`

## Documented skips (orchestrator-level, not touched)

- **Shodan API key in query param.** Shodan's REST contract accepts the key
  only as `?key=<val>`; `Authorization: Bearer` is not supported upstream.
  Current code is correct for the vendor contract.
- **TypedDict node envelopes.** Orchestrator judgment call — ~70 LOC of
  TypedDict declarations vs. typo risk already covered by end-to-end tests.
  Not worth the churn.

## Final suite status

| Check  | Result              |
| ------ | ------------------- |
| pytest | 213 passed          |
| mypy   | 0 errors (38 files) |
| ruff   | 0 violations        |

Files touched:

- `src/agents/supervisor.py`
- `src/agents/correlation_agent.py`
- `src/agents/reflection.py`
- `main.py`
- `src/api/app.py`
- `.env.example`
