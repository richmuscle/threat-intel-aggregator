"""
Base async HTTP client with exponential backoff, rate limiting, and structured logging.
Every tool client inherits from this — no raw aiohttp usage elsewhere.
"""

from __future__ import annotations

import asyncio
import functools
import ipaddress
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any, Literal, Self, TypeVar

import aiohttp
import structlog
from pydantic import SecretStr

logger = structlog.get_logger(__name__)


# ── URL-path input validators ─────────────────────────────────────────────────
#
# Any value that a client splices into a URL path (e.g. Shodan's
# `/shodan/host/{ip}`, VirusTotal's `/api/v3/files/{hash}`) is an SSRF / path-
# traversal surface. A malformed feed or a bug in the normalizer that lets
# `"../admin"` reach the client would otherwise build a crafted URL against a
# trusted host. These validators fail closed — they return False on anything
# that isn't a canonical IP / domain / hex hash — and callers are expected
# to short-circuit to `None` when validation fails.

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"  # total length ≤ 253
    r"(?!-)[a-z0-9-]{1,63}(?<!-)"  # first label (no leading/trailing hyphen)
    r"(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"  # one or more additional labels
)

_HASH_RE: dict[int, re.Pattern[str]] = {
    32: re.compile(r"^[a-f0-9]{32}$"),  # MD5
    40: re.compile(r"^[a-f0-9]{40}$"),  # SHA1
    64: re.compile(r"^[a-f0-9]{64}$"),  # SHA256
}


def is_valid_ip(value: str) -> bool:
    """True if `value` is a canonical IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_domain(value: str) -> bool:
    """True if `value` is a DNS-safe domain label sequence (no IPs)."""
    if not value or is_valid_ip(value):
        return False
    return bool(_DOMAIN_RE.fullmatch(value.lower()))


def is_valid_hash(
    value: str,
    kind: Literal["md5", "sha1", "sha256", "any"] = "any",
) -> bool:
    """True if `value` matches the canonical hex pattern for the given kind."""
    if not value:
        return False
    value = value.lower()
    if kind == "any":
        return any(pat.fullmatch(value) for pat in _HASH_RE.values())
    expected_len = {"md5": 32, "sha1": 40, "sha256": 64}[kind]
    return bool(_HASH_RE[expected_len].fullmatch(value))


# Type alias for API keys that may come wrapped in SecretStr (from config
# builders) or as a plain str (from tests / direct instantiation).
SecretLike = SecretStr | str | None


def unwrap_secret(val: SecretLike) -> str | None:
    """Return the underlying string of a `SecretStr`/`str`, or None.

    Used at every boundary where a wrapped key meets code that needs the raw
    value (aiohttp headers, anthropic SDK, syslog forwarding). The wrapping
    itself happens once in `main.py::_build_config` and
    `src/api/app.py::_run_swarm_background`; everything else stays oblivious.
    """
    if val is None:
        return None
    if isinstance(val, SecretStr):
        raw = val.get_secret_value()
        return raw or None
    return val or None


DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=30, connect=10)
MAX_RETRIES = 3
BASE_BACKOFF = 1.0  # seconds
POOL_LIMIT = 20
KEEPALIVE_TIMEOUT = 30.0
# Upper bound on `Retry-After` sleeps. Some providers (notably AbuseIPDB's
# free tier) send values measured in hours, which would block the entire
# swarm. Beyond this cap we treat the endpoint as unavailable and fail fast.
MAX_RETRY_AFTER_SECONDS = 60

T = TypeVar("T")


def retry_on_disconnect(
    retries: int = 2,
    backoff: float = 0.5,
) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    """
    Decorator: retry an async call on transient socket-level errors.

    Targets `aiohttp.ServerDisconnectedError` specifically — keep-alive
    connections in the pooled session can be silently closed by the remote
    side, and the very next request then fails before any HTTP response is
    seen. `BaseAPIClient.get()` already handles HTTP-level retries; this
    covers the pre-HTTP case.
    """

    def _decorator(fn: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(fn)
        async def _wrapper(*args: Any, **kwargs: Any) -> T:
            last_exc: Exception | None = None
            for attempt in range(retries + 1):
                try:
                    return await fn(*args, **kwargs)
                except aiohttp.ServerDisconnectedError as exc:
                    last_exc = exc
                    if attempt == retries:
                        break
                    await asyncio.sleep(backoff * (2**attempt))
            assert last_exc is not None
            raise last_exc

        return _wrapper

    return _decorator


class RateLimiter:
    """Token-bucket rate limiter per API client."""

    def __init__(self, calls_per_second: float = 2.0) -> None:
        self._rate = calls_per_second
        self._tokens = calls_per_second
        self._last_check = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_check
            self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
            self._last_check = now
            if self._tokens < 1:
                wait = (1 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                self._tokens = 0
            else:
                self._tokens -= 1


class BaseAPIClient:
    """
    Async HTTP client base class.
    Subclasses define base_url and override _build_headers().
    """

    base_url: str = ""
    calls_per_second: float = 2.0

    def __init__(self, api_key: SecretLike = None) -> None:
        # Accept `SecretStr` from config builders, plain `str` from tests, or
        # `None`. Store the unwrapped string internally so subclass headers
        # (e.g. NVD's `apiKey`, Shodan's `key`) don't accidentally serialise
        # `SecretStr('**********')` into the wire.
        self._api_key: str | None = unwrap_secret(api_key)
        self._session: aiohttp.ClientSession | None = None
        self._rate_limiter = RateLimiter(self.calls_per_second)
        self._log = logger.bind(client=self.__class__.__name__)

    async def __aenter__(self) -> Self:
        # Bounded connection pool — prevents unbounded fan-out when four parallel
        # agents each hit multiple endpoints, and keep-alive amortises TCP/TLS
        # cost when the same API is hit repeatedly within a run.
        connector = aiohttp.TCPConnector(
            limit=POOL_LIMIT,
            keepalive_timeout=KEEPALIVE_TIMEOUT,
            enable_cleanup_closed=True,
        )
        self._session = aiohttp.ClientSession(
            base_url=self.base_url,
            timeout=DEFAULT_TIMEOUT,
            headers=self._build_headers(),
            connector=connector,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._session:
            await self._session.close()

    def _build_headers(self) -> dict[str, str]:
        return {"Accept": "application/json", "User-Agent": "ThreatIntelAggregator/1.0"}

    @retry_on_disconnect(retries=2, backoff=0.5)
    async def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        retries: int = MAX_RETRIES,
    ) -> Any:
        """GET with automatic retry + exponential backoff.

        Returns whatever `response.json()` produced — typically `dict[str, Any]`
        but occasionally `list[Any]` (NVD 2.0, CISA KEV, EPSS top-exploited).
        Typed as `Any` so each caller narrows on its own shape; callers that
        always get a dict back can just `.get(...)`, callers that get a list
        iterate directly. A `dict | list` union would force every call site
        into an `isinstance` dance with no real safety gain.

        HTTP-level retries (429, 5xx, timeouts) are handled here. Socket-level
        `ServerDisconnectedError` — which fires *before* any response — is
        caught by the outer `retry_on_disconnect` decorator.
        """
        assert self._session, "Client must be used as async context manager"
        await self._rate_limiter.acquire()

        for attempt in range(retries + 1):
            try:
                t0 = time.monotonic()
                async with self._session.get(path, params=params) as resp:
                    duration_ms = (time.monotonic() - t0) * 1000
                    if resp.status == 429:
                        raw_retry_after = int(
                            resp.headers.get("Retry-After", BASE_BACKOFF * 2**attempt)
                        )
                        if raw_retry_after > MAX_RETRY_AFTER_SECONDS:
                            # Providers occasionally send absurd values (hours).
                            # Surfacing a 429 to the caller lets the agent fall
                            # back to an empty result instead of stalling the
                            # whole swarm on a single misbehaving endpoint.
                            self._log.warning(
                                "rate_limit_exceeds_cap",
                                path=path,
                                retry_after=raw_retry_after,
                                cap=MAX_RETRY_AFTER_SECONDS,
                            )
                            resp.raise_for_status()
                        self._log.warning("rate_limited", path=path, retry_after=raw_retry_after)
                        await asyncio.sleep(raw_retry_after)
                        continue
                    if resp.status >= 500:
                        raise aiohttp.ClientResponseError(
                            resp.request_info, resp.history, status=resp.status
                        )
                    resp.raise_for_status()
                    data = await resp.json(content_type=None)
                    self._log.debug(
                        "request_ok",
                        path=path,
                        status=resp.status,
                        duration_ms=round(duration_ms, 1),
                    )
                    return data
            except (TimeoutError, aiohttp.ClientError) as exc:
                if attempt == retries:
                    self._log.error(
                        "request_failed", path=path, error=str(exc), attempts=attempt + 1
                    )
                    raise
                backoff = BASE_BACKOFF * 2**attempt
                self._log.warning("retrying", path=path, attempt=attempt + 1, backoff=backoff)
                await asyncio.sleep(backoff)

        raise RuntimeError(f"Exhausted retries for {path}")
