"""Elasticsearch indexer — bulk-uploads swarm output into the SOC stack.

Three monthly indices are written per run; all are auto-created by ES on
first write so no schema bootstrap is required:

  * ``threat-intel-iocs-YYYY.MM``    — one doc per IOC ``NormalizedThreat``
    (``_id`` = content_hash → idempotent dedup)
  * ``threat-intel-reports-YYYY.MM`` — one doc per ``CorrelatedIntelReport``
    (``_id`` = report_id → idempotent re-runs)
  * ``threat-intel-alerts-YYYY.MM``  — one doc per ``state.report.siem_alerts``
    entry (``_id`` = sha256(alert)[:16])

Connection is HTTPS basic-auth against the soc-stack node. The CA at
``$ES_CA_CERT`` is pinned for verification — same pattern as ADR-002 for
Wazuh / MISP.

Graceful skip — never raises:

  * ``ELASTIC_PASSWORD`` unset
  * ES unreachable inside the 5 s connect timeout
  * 401 / 403 on the bulk request
"""

from __future__ import annotations

import hashlib
import json
import os
import ssl
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import aiohttp
import structlog

if TYPE_CHECKING:
    from src.models import CorrelatedIntelReport, NormalizedThreat, SwarmState

logger = structlog.get_logger(__name__)

# ── Defaults ──────────────────────────────────────────────────────────────────

DEFAULT_ES_URL = "https://127.0.0.1:9201"
DEFAULT_ES_CA_CERT = "/home/richmuscle/dev/floorp/soc-stack/certs/soc-internal-ca.crt"
ES_USERNAME = "elastic"
CONNECT_TIMEOUT_SECONDS = 5.0
TOTAL_TIMEOUT_SECONDS = 30.0

INDEX_IOCS_PREFIX = "threat-intel-iocs"
INDEX_REPORTS_PREFIX = "threat-intel-reports"
INDEX_ALERTS_PREFIX = "threat-intel-alerts"


# ── Helpers ───────────────────────────────────────────────────────────────────


def _month_suffix(when: datetime | None = None) -> str:
    """Return the YYYY.MM suffix used for monthly index rotation."""
    when = when or datetime.now(UTC)
    return when.strftime("%Y.%m")


def _iso(ts: datetime) -> str:
    """Serialise a datetime as ISO-8601 UTC with trailing Z."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _safe_str(exc: BaseException) -> str:
    """str(exc) wrapped — some aiohttp exceptions raise during __str__ if
    constructed with sentinel kwargs (e.g. ClientConnectorError(connection_key=None))."""
    try:
        return str(exc)
    except Exception:
        return f"<unstringable {type(exc).__name__}>"


def _alert_id(alert: dict[str, Any]) -> str:
    """Stable 16-char hash for a SIEM alert dict — survives re-runs."""
    payload = json.dumps(alert, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _make_ssl_context(ca_cert_path: str) -> ssl.SSLContext | bool:
    """Build an SSL context that pins the soc-stack CA, or False on failure.

    `ES_INSECURE_SKIP_VERIFY=1` opt-out: the auto-generated soc-internal-ca.crt
    used by docker-compose lacks the `keyUsage` X509 extension required by
    OpenSSL 3.x strict profile. Same root cause as ADR-002 (pin Wazuh leaf).
    The honest long-term fix is to regenerate the CA with
    `keyUsage=critical,keyCertSign,cRLSign`. Until then, opt-in skip lets the
    integration land docs while the CA fix is scheduled.
    """
    if os.getenv("ES_INSECURE_SKIP_VERIFY", "").lower() in ("1", "true", "yes"):
        logger.warning(
            "es_insecure_skip_verify",
            reason="ES_INSECURE_SKIP_VERIFY=1; soc-internal-ca lacks keyUsage",
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if not os.path.exists(ca_cert_path):
        logger.warning("es_ca_missing", path=ca_cert_path)
        return False
    ctx = ssl.create_default_context(cafile=ca_cert_path)
    return ctx


def _bulk_body(actions: list[tuple[dict[str, Any], dict[str, Any]]]) -> str:
    """Render actions as ES bulk NDJSON (action line + source line, repeat)."""
    lines: list[str] = []
    for action, source in actions:
        lines.append(json.dumps(action, default=str))
        lines.append(json.dumps(source, default=str))
    return "\n".join(lines) + "\n"


def _build_ioc_actions(
    threats: list[NormalizedThreat],
    index: str,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    actions: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for t in threats:
        if t.threat_type != "ioc":
            continue
        doc = t.model_dump(mode="json")
        doc["@timestamp"] = _iso(t.ingested_at)
        actions.append(
            ({"index": {"_index": index, "_id": t.content_hash}}, doc),
        )
    return actions


def _build_report_action(
    report: CorrelatedIntelReport,
    index: str,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    doc = {
        "@timestamp": _iso(report.generated_at),
        "report_id": report.report_id,
        "generated_at": _iso(report.generated_at),
        "executive_summary": report.executive_summary,
        "critical_findings": report.critical_findings,
        "recommended_actions": report.recommended_actions,
        "total_threats_processed": report.total_threats_processed,
        "severity_breakdown": report.severity_breakdown,
        "sources_queried": report.sources_queried,
        "cluster_summary": [
            {
                "cluster_name": c.get("cluster_name", ""),
                "severity": c.get("severity", "UNKNOWN"),
                "cve_count": len(c.get("cve_ids", []) or []),
                "technique_count": len(c.get("mitre_techniques", []) or []),
                "ioc_count": len(c.get("threat_ids", []) or []),
            }
            for c in report.threat_clusters
        ],
    }
    return [({"index": {"_index": index, "_id": report.report_id}}, doc)]


def _build_alert_actions(
    report: CorrelatedIntelReport,
    index: str,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    actions: list[tuple[dict[str, Any], dict[str, Any]]] = []
    ts = _iso(report.generated_at)
    for alert in report.siem_alerts:
        doc = dict(alert)
        doc["@timestamp"] = ts
        doc["report_id"] = report.report_id
        actions.append(
            ({"index": {"_index": index, "_id": _alert_id(alert)}}, doc),
        )
    return actions


async def _bulk_post(
    session: aiohttp.ClientSession,
    es_url: str,
    body: str,
    auth: aiohttp.BasicAuth,
    ssl_ctx: ssl.SSLContext | bool,
) -> tuple[int, str]:
    """POST a bulk body and return (status, body-snippet)."""
    url = es_url.rstrip("/") + "/_bulk"
    async with session.post(
        url,
        data=body,
        auth=auth,
        headers={"Content-Type": "application/x-ndjson"},
        ssl=ssl_ctx,
    ) as resp:
        text = await resp.text()
        return resp.status, text


# ── Public API ────────────────────────────────────────────────────────────────


async def index_run(state: SwarmState) -> dict[str, Any]:
    """Bulk-index a completed swarm run into Elasticsearch.

    Returns a dict of counts. On graceful skip the dict carries
    ``{"skipped": True}`` and the swarm continues. Never raises.
    """
    password = os.getenv("ELASTIC_PASSWORD")
    if not password:
        logger.warning("es_password_missing")
        return {"skipped": True, "reason": "ELASTIC_PASSWORD unset"}

    es_url = os.getenv("ES_URL", DEFAULT_ES_URL)
    ca_cert = os.getenv("ES_CA_CERT", DEFAULT_ES_CA_CERT)
    ssl_ctx = _make_ssl_context(ca_cert)
    if ssl_ctx is False:
        return {"skipped": True, "reason": "CA cert missing"}

    auth = aiohttp.BasicAuth(ES_USERNAME, password)
    suffix = _month_suffix()
    iocs_index = f"{INDEX_IOCS_PREFIX}-{suffix}"
    reports_index = f"{INDEX_REPORTS_PREFIX}-{suffix}"
    alerts_index = f"{INDEX_ALERTS_PREFIX}-{suffix}"

    ioc_actions = _build_ioc_actions(state.normalized_threats, iocs_index)
    report_actions = _build_report_action(state.report, reports_index) if state.report else []
    alert_actions = _build_alert_actions(state.report, alerts_index) if state.report else []

    counts: dict[str, Any] = {
        "iocs": len(ioc_actions),
        "report": len(report_actions),
        "alerts": len(alert_actions),
        "skipped": False,
    }

    if not (ioc_actions or report_actions or alert_actions):
        logger.info("es_index_empty_run", run_id=state.run_id)
        return counts

    timeout = aiohttp.ClientTimeout(total=TOTAL_TIMEOUT_SECONDS, connect=CONNECT_TIMEOUT_SECONDS)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for label, actions in (
                ("iocs", ioc_actions),
                ("report", report_actions),
                ("alerts", alert_actions),
            ):
                if not actions:
                    continue
                body = _bulk_body(actions)
                status, text = await _bulk_post(session, es_url, body, auth, ssl_ctx)
                if status in (401, 403):
                    logger.warning(
                        "es_auth_failed",
                        status=status,
                        url=es_url,
                        body_snippet=text[:200],
                    )
                    return {"skipped": True, "reason": f"HTTP {status}"}
                if status >= 400:
                    logger.warning(
                        "es_bulk_error",
                        label=label,
                        status=status,
                        body_snippet=text[:200],
                    )
                    counts[f"{label}_failed"] = True
                else:
                    logger.info(
                        "es_bulk_ok",
                        label=label,
                        status=status,
                        docs=len(actions),
                    )
    except aiohttp.ClientConnectorError as exc:
        logger.warning(
            "es_unreachable",
            url=es_url,
            error=_safe_str(exc),
            error_type=type(exc).__name__,
        )
        return {"skipped": True, "reason": "connection refused"}
    except TimeoutError as exc:
        logger.warning("es_timeout", url=es_url, error=_safe_str(exc))
        return {"skipped": True, "reason": "timeout"}
    except aiohttp.ClientError as exc:
        logger.warning(
            "es_client_error",
            url=es_url,
            error=_safe_str(exc),
            error_type=type(exc).__name__,
        )
        return {"skipped": True, "reason": type(exc).__name__}

    return counts


__all__: list[str] = ["index_run"]
