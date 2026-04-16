"""
Performance canary for `_stratified_sample`.

`_stratified_sample` runs on every swarm invocation before the Claude call —
if it becomes quadratic, every run pays the cost linearly in threat-count
growth. We target a loose budget that's ~10x today's headroom so CI doesn't
flake on runner variance, but tight enough to catch an accidental `O(n²)`
regression.

Budgets (single-core, uncontended runner — GitHub-hosted `ubuntu-latest`
Linux VMs are slower than a dev laptop; the ceilings here allow ~5x of that):

  *   100 threats  →  ≤  20 ms  (mean over 5 runs)
  *  1 000 threats →  ≤  50 ms
  * 10 000 threats →  ≤ 500 ms

The mean-over-5 smooths warmup noise; the three orders of magnitude cover
small/medium/large runs so a regression that's only visible at scale still
trips the budget.

Zero-dep by design — `pytest-benchmark` is overkill for a single function
with a fixed budget. `time.perf_counter` is fine.
"""

from __future__ import annotations

import random
import time

import pytest

from src.agents.correlation_agent import MAX_PROMPT_THREATS, _stratified_sample
from src.models import NormalizedThreat, Severity

_SEVS = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
_TYPES = ("cve", "technique", "ioc", "feed_item")


def _mk_threats(n: int, seed: int = 42) -> list[NormalizedThreat]:
    """Generate `n` deterministic threats spanning all severity/type combos.

    Deterministic seed keeps run-to-run timings comparable; mix across
    severity + type forces the round-robin path inside the sampler rather
    than hitting the tier-fills-itself shortcut.
    """
    rng = random.Random(seed)
    return [
        NormalizedThreat(
            threat_type=rng.choice(_TYPES),  # type: ignore[arg-type]
            title=f"t-{i}",
            description="-",
            severity=rng.choice(_SEVS),
        )
        for i in range(n)
    ]


def _mean_ms(fn, runs: int = 5) -> float:
    """Return the mean wall-clock ms over `runs` executions of `fn()`."""
    samples: list[float] = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)
    return sum(samples) / len(samples)


class TestStratifiedSamplePerf:
    """Budget canaries — trip on quadratic regressions without flaking."""

    @pytest.mark.parametrize(
        "size, budget_ms",
        [
            (100, 20.0),
            (1_000, 50.0),
            (10_000, 500.0),
        ],
    )
    def test_within_budget(self, size: int, budget_ms: float, capsys) -> None:
        """`_stratified_sample(N)` stays within the per-size budget."""
        threats = _mk_threats(size)
        mean_ms = _mean_ms(lambda: _stratified_sample(threats, limit=MAX_PROMPT_THREATS))
        # Log the result so CI shows the actual number even when the test
        # passes — lets us spot creeping regressions before they trip.
        with capsys.disabled():
            print(f"\n  _stratified_sample(n={size}): {mean_ms:.2f} ms (budget {budget_ms} ms)")
        assert mean_ms < budget_ms, (
            f"_stratified_sample({size}) took {mean_ms:.2f} ms, "
            f"budget is {budget_ms} ms — check for an accidental O(n²)."
        )

    def test_output_size_is_limit_capped(self) -> None:
        """Sanity: perf test inputs produce the expected output shape."""
        result = _stratified_sample(_mk_threats(10_000), limit=MAX_PROMPT_THREATS)
        assert len(result) == MAX_PROMPT_THREATS
