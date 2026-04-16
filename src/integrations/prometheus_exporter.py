"""Prometheus pushgateway exporter for swarm-run metrics.

After every `run_swarm()` invocation `main.py` calls :func:`push_metrics`
which serialises a fresh :class:`prometheus_client.CollectorRegistry`
populated from a :class:`~src.models.SwarmState` and pushes it to the
pushgateway at ``$PUSHGATEWAY_URL`` (default ``http://127.0.0.1:9091``).

Graceful skip — never raises:

  * ``prometheus_client`` not installed → log warning, return False
  * Pushgateway unreachable / 5 s timeout → log warning, return False
  * ``nft`` / ``/etc/hosts`` lookups fail → emit 0 for those gauges only

Job label is hard-coded to ``threat_intel_aggregator`` so the
pushgateway groups all runs under one job and the most recent push
overwrites the previous (a Counter monotonically increasing across runs
is what scrape-side ``rate()`` expects).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections import Counter as _PyCounter
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from src.models import SwarmState

logger = structlog.get_logger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

JOB_NAME = "threat_intel_aggregator"
DEFAULT_PUSHGATEWAY_URL = "http://127.0.0.1:9091"
PUSH_TIMEOUT_SECONDS = 5.0

# Hosts-file marker the dns_block.sh script writes for each blocked domain.
HOSTS_BLOCK_MARKER = "threat-intel-aggregator"
NFT_SET_NAME = "threat_block_ips"


# ── nftables / hosts probes (graceful skip) ──────────────────────────────────


def _count_blocked_ips() -> int:
    """Return the number of IPs in the nftables blocklist set, or 0 on failure."""
    nft = shutil.which("nft")
    if nft is None:
        logger.debug("nft_not_available")
        return 0
    try:
        proc = subprocess.run(
            [nft, "list", "set", "inet", "filter", NFT_SET_NAME],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("nft_invocation_failed", error=str(exc))
        return 0
    if proc.returncode != 0:
        return 0

    # The set body is enclosed in `elements = { ... }` — count the
    # comma-separated entries. Fall back to 0 on any structural surprise.
    try:
        body = proc.stdout.split("elements = {", 1)[1].split("}", 1)[0]
    except IndexError:
        return 0
    items = [s.strip() for s in body.replace("\n", ",").split(",") if s.strip()]
    return len(items)


def _count_blocked_domains() -> int:
    """Count entries in /etc/hosts tagged by the dns_block.sh marker."""
    try:
        with open("/etc/hosts", encoding="utf-8") as fh:
            return sum(1 for line in fh if HOSTS_BLOCK_MARKER in line)
    except OSError as exc:
        logger.debug("hosts_read_failed", error=str(exc))
        return 0


# ── Public API ────────────────────────────────────────────────────────────────


def push_metrics(state: SwarmState, run_duration_seconds: float) -> bool:
    """Push a snapshot of `state` to the configured pushgateway.

    Returns True on success, False on graceful skip (missing client,
    unreachable gateway, etc.). Never raises.
    """
    try:
        from prometheus_client import (
            CollectorRegistry,
            Counter,
            Gauge,
            push_to_gateway,
        )
    except ImportError:
        logger.warning("prometheus_client_not_installed")
        return False

    registry = CollectorRegistry()

    # ── Run-level gauges ──────────────────────────────────────────────────────
    duration = Gauge(
        "threat_intel_run_duration_seconds",
        "Wall-clock duration of the latest swarm run.",
        registry=registry,
    )
    duration.set(run_duration_seconds)

    clusters_gauge = Gauge(
        "threat_intel_clusters_total",
        "Number of correlated threat clusters in the latest report.",
        registry=registry,
    )
    cluster_count = len(state.report.threat_clusters) if state.report else 0
    clusters_gauge.set(cluster_count)

    # ── Per-IOC counters ──────────────────────────────────────────────────────
    iocs_counter = Counter(
        "threat_intel_iocs_total",
        "IOCs observed in the latest swarm run.",
        labelnames=("severity", "ioc_type"),
        registry=registry,
    )
    cves_counter = Counter(
        "threat_intel_cves_total",
        "CVEs observed in the latest swarm run.",
        labelnames=("severity",),
        registry=registry,
    )

    ioc_buckets: _PyCounter[tuple[str, str]] = _PyCounter()
    cve_buckets: _PyCounter[str] = _PyCounter()
    for threat in state.normalized_threats:
        sev = threat.severity.value
        if threat.threat_type == "ioc":
            # An IOC normalized record may carry several ioc_values from dedup.
            for raw_value in threat.ioc_values or [""]:
                ioc_type = _classify_ioc_value(raw_value)
                ioc_buckets[(sev, ioc_type)] += 1
        elif threat.threat_type == "cve":
            cve_buckets[sev] += 1

    for (sev, ioc_type), n in ioc_buckets.items():
        iocs_counter.labels(severity=sev, ioc_type=ioc_type).inc(n)
    for sev, n in cve_buckets.items():
        cves_counter.labels(severity=sev).inc(n)

    # ── SIEM alert counter (per severity) ─────────────────────────────────────
    siem_counter = Counter(
        "threat_intel_siem_alerts_total",
        "SIEM alert proposals emitted by the latest correlation report.",
        labelnames=("severity",),
        registry=registry,
    )
    if state.report:
        sev_alerts: _PyCounter[str] = _PyCounter()
        for alert in state.report.siem_alerts:
            sev_alerts[str(alert.get("severity", "UNKNOWN"))] += 1
        for sev, n in sev_alerts.items():
            siem_counter.labels(severity=sev).inc(n)

    # ── Per-agent gauges ──────────────────────────────────────────────────────
    agent_duration = Gauge(
        "threat_intel_agent_duration_seconds",
        "Per-agent runtime in seconds for the latest swarm run.",
        labelnames=("agent",),
        registry=registry,
    )
    agent_records = Gauge(
        "threat_intel_agent_records_total",
        "Per-agent record count for the latest swarm run.",
        labelnames=("agent",),
        registry=registry,
    )
    for ar in state.agent_results:
        agent_duration.labels(agent=ar.agent_name).set(ar.duration_ms / 1000.0)
        agent_records.labels(agent=ar.agent_name).set(ar.items_fetched)

    # ── Side-channel gauges (nft / hosts) ─────────────────────────────────────
    blocked_ips = Counter(
        "threat_intel_blocked_ips_total",
        "Distinct IPs currently in the nftables threat_block_ips set.",
        registry=registry,
    )
    blocked_ips.inc(_count_blocked_ips())

    blocked_domains = Counter(
        "threat_intel_blocked_domains_total",
        "Distinct domains currently sink-holed in /etc/hosts.",
        registry=registry,
    )
    blocked_domains.inc(_count_blocked_domains())

    # ── Push ──────────────────────────────────────────────────────────────────
    gateway_url = os.getenv("PUSHGATEWAY_URL", DEFAULT_PUSHGATEWAY_URL)
    try:
        push_to_gateway(
            gateway_url,
            job=JOB_NAME,
            registry=registry,
            timeout=PUSH_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        # urllib raises URLError (subclass of OSError) on connection refused /
        # timeout; pushgateway 4xx/5xx surfaces as HTTPError. Catch broadly.
        logger.warning(
            "pushgateway_unreachable",
            gateway=gateway_url,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        return False

    logger.info(
        "pushgateway_push_ok",
        gateway=gateway_url,
        job=JOB_NAME,
        clusters=cluster_count,
        agents=len(state.agent_results),
    )
    return True


def _classify_ioc_value(value: str) -> str:
    """Best-effort `ioc_type` label without re-importing pydantic models.

    Mirrors the IOCRecord `ioc_type` regex set: ipv4, ipv6, domain, md5,
    sha1, sha256, url, email. Anything we cannot classify becomes
    ``unknown`` so the metric label stays low-cardinality.
    """
    v = value.strip().lower()
    if not v:
        return "unknown"
    if v.startswith(("http://", "https://")):
        return "url"
    if "@" in v and "." in v.split("@", 1)[1]:
        return "email"
    if v.count(".") == 3 and all(p.isdigit() for p in v.split(".")):
        return "ipv4"
    if ":" in v and v.replace(":", "").replace(".", "").isalnum():
        return "ipv6"
    if len(v) == 32 and all(c in "0123456789abcdef" for c in v):
        return "md5"
    if len(v) == 40 and all(c in "0123456789abcdef" for c in v):
        return "sha1"
    if len(v) == 64 and all(c in "0123456789abcdef" for c in v):
        return "sha256"
    if "." in v:
        return "domain"
    return "unknown"


__all__: list[str] = ["push_metrics"]
