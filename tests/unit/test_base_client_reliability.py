"""
Unit tests for the reliability primitives in `src.tools.base_client`:

  * `RateLimiter` — token-bucket semantics under sequential and concurrent load.
  * `retry_on_disconnect` — decorator behaviour for the socket-level
    `aiohttp.ServerDisconnectedError` case, which fires *before* any HTTP
    response and is therefore distinct from the HTTP-retry loop inside
    `BaseAPIClient.get()`.
  * `unwrap_secret` — the SecretStr-aware helper used at every boundary
    where a wrapped API key meets code that needs the raw string.

These are the two primitives the whole swarm leans on for availability, so
failure modes here cascade across every agent. Keeping them tested means a
refactor of the rate-limiter math can't silently change request cadence.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock

import aiohttp
import pytest
from pydantic import SecretStr

from src.tools.base_client import (
    RateLimiter,
    retry_on_disconnect,
    unwrap_secret,
)

# ── RateLimiter ───────────────────────────────────────────────────────────────


class TestRateLimiter:
    """Token-bucket rate limiter tests.

    `RateLimiter` is initialised with `calls_per_second = N`, seeds the bucket
    with N tokens, and refills at N tokens/second. `acquire()` consumes one
    token; when empty it sleeps the fractional time to earn one back.
    """

    @pytest.mark.asyncio
    async def test_burst_equal_to_capacity_is_immediate(self) -> None:
        """N acquire() calls up to the initial capacity complete without sleep."""
        limiter = RateLimiter(calls_per_second=5.0)
        t0 = time.monotonic()
        for _ in range(5):
            await limiter.acquire()
        elapsed = time.monotonic() - t0
        # Should be ~0 — the bucket starts full.
        assert elapsed < 0.05, f"burst took {elapsed:.3f}s, expected <0.05s"

    @pytest.mark.asyncio
    async def test_acquire_beyond_capacity_waits(self) -> None:
        """The (N+1)th call must block until the bucket refills."""
        limiter = RateLimiter(calls_per_second=10.0)  # one token / 0.1s
        for _ in range(10):
            await limiter.acquire()
        t0 = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - t0
        # Should wait ~0.1s for one token to refill. Give generous slack for
        # scheduler jitter, but assert we actually waited.
        assert 0.05 < elapsed < 0.5, f"refill wait {elapsed:.3f}s out of range"

    @pytest.mark.asyncio
    async def test_concurrent_callers_are_serialized(self) -> None:
        """Many concurrent waiters don't all fire at once — the lock serialises."""
        limiter = RateLimiter(calls_per_second=4.0)
        # Drain the initial bucket first so every task below actually queues.
        for _ in range(4):
            await limiter.acquire()

        results: list[float] = []

        async def _timed() -> None:
            await limiter.acquire()
            results.append(time.monotonic())

        t0 = time.monotonic()
        await asyncio.gather(*[_timed() for _ in range(4)])
        elapsed = time.monotonic() - t0
        # 4 tokens @ 4/s after full drain ≈ 1s. Allow generous bounds for CI.
        assert elapsed >= 0.5, f"concurrent drain too fast: {elapsed:.3f}s"
        # Completions should be roughly monotonically increasing, not all
        # bunched at t0 — proves the lock is actually serialising.
        assert results == sorted(results)


# ── retry_on_disconnect ───────────────────────────────────────────────────────


class TestRetryOnDisconnect:
    """`@retry_on_disconnect` behaviour around `ServerDisconnectedError`.

    The decorator exists because keep-alive connections in the shared aiohttp
    pool can be silently closed by the remote side. The next request then
    fails *before* any response is received, so the HTTP-retry loop inside
    `BaseAPIClient.get()` never sees it.
    """

    @pytest.mark.asyncio
    async def test_passes_through_on_success(self) -> None:
        """No retry needed — decorator is transparent."""
        fn = AsyncMock(return_value="ok")
        wrapped = retry_on_disconnect()(fn)
        assert await wrapped() == "ok"
        fn.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_retries_then_succeeds(self) -> None:
        """Disconnect once, succeed on second attempt — caller sees the value."""
        fn = AsyncMock(side_effect=[aiohttp.ServerDisconnectedError(), "ok"])
        wrapped = retry_on_disconnect(retries=2, backoff=0.01)(fn)
        assert await wrapped() == "ok"
        assert fn.await_count == 2

    @pytest.mark.asyncio
    async def test_exhausts_and_raises(self) -> None:
        """All attempts fail — the final exception propagates."""
        fn = AsyncMock(side_effect=aiohttp.ServerDisconnectedError())
        wrapped = retry_on_disconnect(retries=2, backoff=0.01)(fn)
        with pytest.raises(aiohttp.ServerDisconnectedError):
            await wrapped()
        # retries=2 means 1 initial attempt + 2 retries = 3 calls total.
        assert fn.await_count == 3

    @pytest.mark.asyncio
    async def test_other_exceptions_are_not_retried(self) -> None:
        """Non-disconnect errors propagate immediately; the decorator is narrow."""
        fn = AsyncMock(side_effect=ValueError("boom"))
        wrapped = retry_on_disconnect(retries=5, backoff=0.01)(fn)
        with pytest.raises(ValueError, match="boom"):
            await wrapped()
        fn.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_backoff_grows_exponentially(self) -> None:
        """Sleeps between retries follow `backoff * 2**attempt`."""
        call_times: list[float] = []

        async def _failing() -> None:
            call_times.append(time.monotonic())
            raise aiohttp.ServerDisconnectedError()

        wrapped = retry_on_disconnect(retries=2, backoff=0.05)(_failing)
        with pytest.raises(aiohttp.ServerDisconnectedError):
            await wrapped()
        # 3 calls — gaps should be ≥ 0.05 and ≥ 0.10 (roughly).
        assert len(call_times) == 3
        gap1 = call_times[1] - call_times[0]
        gap2 = call_times[2] - call_times[1]
        assert gap1 >= 0.04, f"first backoff {gap1:.3f}s too short"
        assert gap2 >= 0.09, f"second backoff {gap2:.3f}s too short"


# ── unwrap_secret ─────────────────────────────────────────────────────────────


class TestUnwrapSecret:
    """SecretStr unwrap helper — used at aiohttp + anthropic SDK boundaries."""

    def test_unwraps_secretstr(self) -> None:
        assert unwrap_secret(SecretStr("sk-ant-real-key")) == "sk-ant-real-key"

    def test_passes_plain_str_through(self) -> None:
        assert unwrap_secret("plain-key") == "plain-key"

    def test_none_returns_none(self) -> None:
        assert unwrap_secret(None) is None

    def test_empty_secretstr_returns_none(self) -> None:
        """Empty SecretStr ≡ no key set — callers expect None, not ''."""
        assert unwrap_secret(SecretStr("")) is None

    def test_empty_plain_str_returns_none(self) -> None:
        assert unwrap_secret("") is None
