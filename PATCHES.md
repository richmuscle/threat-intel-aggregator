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
