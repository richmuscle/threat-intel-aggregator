"""Report Coordinator — renders final markdown report and SIEM-ready JSON."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import re
from collections import Counter

import structlog

from src.models import CorrelatedIntelReport, Severity, SwarmState

logger = structlog.get_logger(__name__)

OUTPUT_DIR = Path("output")

BLOCKS_LOG = Path("/var/log/threat-intel-blocks.log")

# Distinguish vendor advisories from generic references in the Patch Priority
# section. Anything hosted on these domains gets surfaced as an authoritative
# source; everything else is a fallback link.
VENDOR_ADVISORY_DOMAINS = (
    "msrc.microsoft.com",
    "security.microsoft.com",
    "access.redhat.com",
    "ubuntu.com/security",
    "security.apple.com",
    "chromereleases.googleblog.com",
    "security.paloaltonetworks.com",
    "tools.cisco.com/security",
    "fortiguard.com",
    "security.netapp.com",
    "nvidia.com/security",
    "oracle.com/security-alerts",
    "security.snyk.io",
    "advisories.mageia.org",
    "debian.org/security",
)


async def report_coordinator(state: SwarmState, config: dict) -> dict:
    """
    LangGraph node: renders the correlated report to markdown + JSON artifacts.
    Also produces Elastic-compatible SIEM alert payloads.
    """
    t0 = time.monotonic()
    agent_name = "report_coordinator"

    if not state.report:
        logger.error("no_report_to_render", agent=agent_name)
        return {"errors": state.errors + ["report_coordinator: no report in state"]}

    report = state.report
    OUTPUT_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # ── Markdown report ──────────────────────────────────────────────────────
    md = _render_markdown(report, state)
    md_path = OUTPUT_DIR / f"{report.report_id}_{timestamp}.md"
    md_path.write_text(md, encoding="utf-8")

    # ── Structured JSON artifact ─────────────────────────────────────────────
    json_path = OUTPUT_DIR / f"{report.report_id}_{timestamp}.json"
    json_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, default=str),
        encoding="utf-8",
    )

    # ── SIEM alert payloads (Elastic Common Schema) ──────────────────────────
    siem_path = OUTPUT_DIR / f"{report.report_id}_{timestamp}_siem_alerts.ndjson"
    with siem_path.open("w", encoding="utf-8") as f:
        for alert in report.siem_alerts:
            ecs_event = _to_ecs(alert, report)
            f.write(json.dumps(ecs_event) + "\n")

    # ── IOC sidecar (consumed by scripts/extract_iocs.py) ───────────────────
    # Prefer real `IOCRecord` objects from `state.raw_iocs` (populated by
    # `ioc_extractor_agent` + collected in `_parallel_ingest_node`) so the
    # sidecar carries provider-sourced `confidence` / `abuse_score` /
    # `sources` verbatim. Fall back to synthesising from `NormalizedThreat`
    # (severity → confidence mapping) only when `raw_iocs` is empty — e.g.
    # tests that bypass the ingest node, or runs where IOC extraction
    # failed entirely.
    iocs_path = OUTPUT_DIR / f"{report.report_id}_{timestamp}_iocs.json"
    if state.raw_iocs:
        sidecar = [ioc.model_dump(mode="json") for ioc in state.raw_iocs]
    else:
        sidecar = _sidecar_from_state(state)
    iocs_path.write_text(
        json.dumps(sidecar, indent=2, default=str),
        encoding="utf-8",
    )

    duration_ms = (time.monotonic() - t0) * 1000
    logger.info(
        "report_written",
        agent=agent_name,
        markdown=str(md_path),
        json=str(json_path),
        siem_alerts=str(siem_path),
        iocs=str(iocs_path),
        duration_ms=round(duration_ms, 1),
    )

    updated_report = report.model_copy(update={"markdown_report": md})
    return {"report": updated_report, "completed": True}


def _render_markdown(report: CorrelatedIntelReport, state: SwarmState) -> str:
    lines: list[str] = [
        f"# Threat Intelligence Report: {report.report_id}",
        f"**Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Threats processed:** {report.total_threats_processed}  ",
        f"**Sources:** {', '.join(report.sources_queried)}  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        report.executive_summary,
        "",
        "---",
        "",
        "## Severity Breakdown",
        "",
    ]

    for sev in Severity:
        count = report.severity_breakdown.get(sev.value, 0)
        if count:
            bar = "█" * min(count, 40)
            lines.append(f"- **{sev.value}**: {bar} {count}")

    # ── IOC count by type ─────────────────────────────────────────────────────
    ioc_type_counts = _ioc_type_breakdown(state)
    if ioc_type_counts:
        lines += ["", "**IOC count by type:**"]
        for ioc_type, n in ioc_type_counts.most_common():
            lines.append(f"- {ioc_type}: {n}")

    lines += [
        "",
        "---",
        "",
        "## Critical Findings",
        "",
    ]
    for i, finding in enumerate(report.critical_findings, 1):
        lines.append(f"{i}. {finding}")

    # ── Patch Priority — CVEs sorted CVSS desc ────────────────────────────────
    patch_rows = _patch_priority_rows(state)
    if patch_rows:
        lines += [
            "",
            "---",
            "",
            "## Patch Priority",
            "",
            "CVEs ordered by CVSS v3 base score (highest first). Vendor-advisory",
            "links are surfaced when present; otherwise the first reference URL.",
            "",
            "| CVE | CVSS | Severity | Advisory |",
            "|-----|-----:|----------|----------|",
        ]
        for cve_id, score, severity, advisory in patch_rows:
            score_cell = f"{score:.1f}" if score is not None else "—"
            advisory_cell = f"[link]({advisory})" if advisory else "—"
            lines.append(f"| `{cve_id}` | {score_cell} | {severity} | {advisory_cell} |")

    lines += [
        "",
        "---",
        "",
        "## Threat Clusters",
        "",
    ]
    for cluster in report.threat_clusters:
        severity = cluster.get("severity", "UNKNOWN")
        lines.append(f"### {cluster['cluster_name']} `[{severity}]`")
        lines.append("")
        lines.append(cluster.get("narrative", ""))
        if cluster.get("cve_ids"):
            lines.append(f"- **CVEs:** {', '.join(cluster['cve_ids'])}")
        if cluster.get("mitre_techniques"):
            lines.append(f"- **MITRE TTPs:** {', '.join(cluster['mitre_techniques'])}")
        lines.append("")

    lines += [
        "---",
        "",
        "## Recommended Actions",
        "",
    ]
    for i, action in enumerate(report.recommended_actions, 1):
        lines.append(f"{i}. {action}")

    lines += [
        "",
        "---",
        "",
        "## SIEM Alerts",
        "",
        "| Rule | Severity | CVE | TTP | Description |",
        "|------|----------|-----|-----|-------------|",
    ]
    for alert in report.siem_alerts:
        lines.append(
            f"| {alert.get('rule_name', '-')} "
            f"| {alert.get('severity', '-')} "
            f"| {alert.get('cve_ref', '-')} "
            f"| {alert.get('mitre_technique', '-')} "
            f"| {alert.get('description', '')[:80]} |"
        )

    # ── Blocked This Run — from /var/log/threat-intel-blocks.log ──────────────
    blocked_entries = _tail_blocks_log()
    if blocked_entries:
        lines += [
            "",
            "---",
            "",
            "## Blocked This Run",
            "",
            "Last 40 entries from `/var/log/threat-intel-blocks.log`. These are",
            "the IPs/domains auto_block.sh has pushed into nftables or /etc/hosts.",
            "",
            "| Timestamp | Kind | Target |",
            "|-----------|------|--------|",
        ]
        for ts, kind, target in blocked_entries:
            lines.append(f"| {ts} | {kind} | `{target}` |")

    lines += [
        "",
        "---",
        "",
        "## Run Metadata",
        "",
        f"- **Run ID:** `{state.run_id}`",
        f"- **Triggered at:** {state.triggered_at.strftime('%Y-%m-%d %H:%M UTC')}",
        f"- **Raw records ingested:** {state.total_raw_records}",
        f"- **Dedup removed:** {state.dedup_removed}",
        f"- **Agent results:**",
    ]
    for r in state.agent_results:
        status = "✓" if r.success else "✗"
        lines.append(
            f"  - {status} `{r.agent_name}`: {r.items_fetched} records "
            f"in {round(r.duration_ms)}ms"
        )
        if r.error:
            lines.append(f"    - Error: {r.error}")

    return "\n".join(lines)


_IOC_TYPE_SET = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"}


def _ioc_type_breakdown(state: SwarmState) -> Counter[str]:
    """Count IOCs by `ioc_type` (`ipv4`, `domain`, `url`, etc.).

    Reads the typed `NormalizedThreat.ioc_type` field set by `normalize_ioc`;
    any legacy threat dict that predates the field still produces a reasonable
    fallback via the tag-scan, but new records take the direct path.
    """
    counter: Counter[str] = Counter()
    for t in state.normalized_threats:
        if t.threat_type != "ioc":
            continue
        if t.ioc_type:
            counter[t.ioc_type] += 1
            continue
        # Legacy fallback — pre-typed-ioc-type records.
        for tag in t.tags:
            if tag in _IOC_TYPE_SET:
                counter[tag] += 1
                break
    return counter


# Synthesize IOCRecord-shaped dicts from NormalizedThreat for the sidecar.
# extract_iocs.py gates on `malicious OR confidence >= 0.7`; mapping severity
# back to a synthetic confidence keeps that gate meaningful without requiring
# the lossy normalizer to preserve the raw record.
_SEVERITY_CONFIDENCE = {
    "CRITICAL": 1.0,
    "HIGH":     0.85,
    "MEDIUM":   0.6,
    "LOW":      0.3,
    "INFO":     0.1,
    "UNKNOWN":  0.0,
}


def _sidecar_from_state(state: SwarmState) -> list[dict]:
    """
    Synthesize IOC sidecar records from normalized threats.

    Uses `effective_severity` (post-enrichment) on purpose: if EPSS flags a
    CVE as actively exploited or VT confirms high detection ratio on an IP,
    we *want* that upgrade to flow through to the firewall/DNS blocklist.
    Provider-original severity lives on `t.severity` and is available for
    auditing, but the defensive gate runs off the enrichment-informed view.
    """
    records: list[dict] = []
    for t in state.normalized_threats:
        if t.threat_type != "ioc" or not t.ioc_values:
            continue
        eff_tags = t.effective_tags
        # Prefer the typed field; fall back to tag-scan for legacy records.
        ioc_type = t.ioc_type or next(
            (tag for tag in eff_tags if tag in _IOC_TYPE_SET), "ipv4"
        )
        eff_sev = t.effective_severity
        confidence = _SEVERITY_CONFIDENCE.get(eff_sev.value, 0.5)
        for value in t.ioc_values:
            records.append({
                "ioc_type": ioc_type,
                "value": value,
                "confidence": confidence,
                "malicious": eff_sev.value in ("CRITICAL", "HIGH"),
                "tags": [tag for tag in eff_tags if tag not in _IOC_TYPE_SET],
                "sources": [s.value if hasattr(s, "value") else s for s in t.sources],
            })
    return records


def _patch_priority_rows(
    state: SwarmState,
) -> list[tuple[str, float | None, str, str | None]]:
    """Walk the raw CVE agent result (if any) to produce patch-priority rows
    sorted by CVSS v3 base score descending. Ties are broken alphabetically
    on CVE id for deterministic output."""
    rows: list[tuple[str, float | None, str, str | None]] = []
    # Raw CVERecords aren't persisted in SwarmState (normalizer is lossy for
    # references), so we derive as much as we can from NormalizedThreat.
    for t in state.normalized_threats:
        if t.threat_type != "cve":
            continue
        cve_id = t.cve_ids[0] if t.cve_ids else t.title
        advisory = _pick_advisory(t.references)
        rows.append((cve_id, t.cvss_score, t.effective_severity.value, advisory))
    rows.sort(key=lambda r: (-(r[1] if r[1] is not None else -1), r[0]))
    return rows[:20]


def _pick_advisory(references: list[str]) -> str | None:
    for url in references:
        if any(domain in url for domain in VENDOR_ADVISORY_DOMAINS):
            return url
    return references[0] if references else None


_BLOCK_LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<kind>added|dns_block)\s+(?P<target>\S+)"
)


def _tail_blocks_log(n: int = 40) -> list[tuple[str, str, str]]:
    """Return the last `n` entries from the blocks log as (ts, kind, target).
    Silently returns [] if the log doesn't exist or can't be read — the
    report must not crash when running as an unprivileged user."""
    try:
        if not BLOCKS_LOG.exists():
            return []
        with BLOCKS_LOG.open("r", encoding="utf-8", errors="replace") as fh:
            tail = fh.readlines()[-n:]
    except (OSError, PermissionError):
        return []
    parsed: list[tuple[str, str, str]] = []
    for line in tail:
        m = _BLOCK_LINE_RE.match(line)
        if not m:
            continue
        kind = "ip" if m["kind"] == "added" else "domain"
        parsed.append((m["ts"], kind, m["target"]))
    return parsed


def _to_ecs(alert: dict, report: CorrelatedIntelReport) -> dict:
    """Convert alert dict to Elastic Common Schema event."""
    return {
        "@timestamp": report.generated_at.isoformat(),
        "event": {
            "kind": "alert",
            "category": ["threat"],
            "type": ["indicator"],
            "severity": _ecs_severity(alert.get("severity", "MEDIUM")),
            "dataset": "threat_intel.aggregator",
            "module": "threat_intel_aggregator",
        },
        "rule": {
            "name": alert.get("rule_name", ""),
            "description": alert.get("description", ""),
        },
        "threat": {
            "technique": {
                "id": alert.get("mitre_technique", ""),
            },
        },
        "vulnerability": {
            "id": alert.get("cve_ref", ""),
        },
        "tags": alert.get("tags", []) + ["threat-intel-aggregator"],
        "labels": {
            "report_id": report.report_id,
        },
    }


def _ecs_severity(severity: str) -> int:
    return {"CRITICAL": 99, "HIGH": 73, "MEDIUM": 47, "LOW": 21, "INFO": 1}.get(
        severity.upper(), 47
    )
