# P0 Patch Log — 2026-04-15

## Summary
- P0-1: done — added `raw_iocs` field to `SwarmState` and wired rehydration in `_to_state()`.
- P0-2: done — replaced `datetime.utcnow()` in `src/api/app.py` with `datetime.now(timezone.utc)`.
- P0-3: done — moved `client.enrich_batch(...)` inside the `async with VirusTotalClient` block.
- P0-4: skipped — audit flagged, code was actually correct. `scripts/nftables_block.sh` already validates IPv4 via regex at line 83 (`^([0-9]{1,3}\.){3}[0-9]{1,3}$`) before calling `nft add element`. `scripts/auto_block.sh` does not pass IPs to `nft` directly — it delegates the full blocklist file to `nftables_block.sh`. No injection surface; no diff needed.

## Test status
Before:  76 passed, 1 failed (per audit baseline)
        Actual local baseline before edits: 77 passed, 0 failed (the failing test was already green in this tree — possibly resolved between audit and patch, but the defensive fix still applies).
After:   77 passed, 0 failed.

## Per-fix diffs

### P0-1 — raw_iocs on SwarmState
**Files:** src/models/threat.py, src/graph/swarm.py
**Before (threat.py, SwarmState body):**
```python
    normalized_threats: list[NormalizedThreat] = Field(default_factory=list)
    dedup_removed: int = 0
```
**After:**
```python
    normalized_threats: list[NormalizedThreat] = Field(default_factory=list)
    raw_iocs: list[IOCRecord] = Field(default_factory=list)
    dedup_removed: int = 0
```
**Before (swarm.py, _to_state):** rehydrated only `agent_results` and `normalized_threats`.
**After:** added parallel block rehydrating `raw_iocs` from dicts to `IOCRecord`, plus added `IOCRecord` to the `src.models` import. Drop-unknown-fields filter preserved.
**Verify:**
- `pytest tests/integration/test_swarm_pipeline.py::test_full_swarm_pipeline_happy_path -xvs` -> 1 passed.
- `pytest tests/ -q` -> 77 passed.

### P0-2 — datetime.utcnow() in src/api/app.py
**Files:** src/api/app.py
**Before:**
```python
from datetime import datetime
...
                            datetime.utcnow().isoformat(),
```
**After:**
```python
from datetime import datetime, timezone
...
                            datetime.now(timezone.utc).isoformat(),
```
**Verify:**
- `python -m py_compile src/api/app.py` -> OK.
- `grep -n datetime.utcnow src/api/app.py` -> no matches.
- `pytest tests/ -q` -> 77 passed.

### P0-3 — virustotal async-context leak
**Files:** src/agents/virustotal_enrichment.py
**Before (lines 60-64):**
```python
        ioc_pairs = [(v, t) for v, t in ioc_pairs if t in ("ipv4", "ipv6", "sha256", "md5", "sha1")]
        async with VirusTotalClient(api_key=vt_key) as client:
            # Cap at 10 to stay within free tier time budget per run
            ioc_pairs = [(v,t) for v,t in ioc_pairs if t in ("ipv4","sha256","md5")]
        vt_results = await client.enrich_batch(ioc_pairs, max_lookups=10)
```
The filter reassignment was inside the `async with`, but `client.enrich_batch(...)` was dedented outside — so the context manager `__aexit__` ran (closing the httpx session) before the network call fired, which would surface as "client is closed" at runtime whenever a real VT key was configured.

**After:**
```python
        ioc_pairs = [(v, t) for v, t in ioc_pairs if t in ("ipv4", "ipv6", "sha256", "md5", "sha1")]
        # Cap at 10 to stay within free tier time budget per run
        ioc_pairs = [(v, t) for v, t in ioc_pairs if t in ("ipv4", "sha256", "md5")]
        async with VirusTotalClient(api_key=vt_key) as client:
            vt_results = await client.enrich_batch(ioc_pairs, max_lookups=10)
```
The redundant filter (safe — second filter is a subset of the first) is kept as-is since removing it is gold-plating outside P0 scope. `enrich_batch` now fires while the client session is still open.
**Verify:**
- `python -m py_compile src/agents/virustotal_enrichment.py` -> OK.
- `pytest tests/ -q` -> 77 passed.

### P0-4 — nftables unquoted variable path-injection (skipped)
**Files inspected:** scripts/nftables_block.sh, scripts/auto_block.sh, scripts/dns_block.sh.
**Finding:** `nftables_block.sh` line 83 already enforces `^([0-9]{1,3}\.){3}[0-9]{1,3}$` on every IP before `nft add element` (line 91), and the IP is passed inside `{ $ip }` with the surrounding table/set/family names quoted via `"$TABLE_FAMILY"` etc. Invalid lines increment an `invalid` counter and `continue`. `auto_block.sh` never reaches `nft` directly — it extracts IOCs with `extract_iocs.py`, then calls `bash scripts/nftables_block.sh "$blocklist"`, so validation responsibility lives entirely in the validated script. `dns_block.sh` writes to `/etc/hosts` only, no `nft` surface.
No diff applied. Audit claim was incorrect.
**Verify:**
- `bash -n scripts/nftables_block.sh scripts/auto_block.sh` -> syntax OK.
