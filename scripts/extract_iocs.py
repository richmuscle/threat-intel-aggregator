#!/usr/bin/env python3
"""Extract malicious IPv4 IOCs from the latest threat-intel report.

Prefers the `_iocs.json` sidecar (real IOCRecord data) when present, otherwise
falls back to parsing CRITICAL-severity `threat_clusters` in the main report.
"""
from __future__ import annotations

import ipaddress
import json
import re
import sys
from collections import Counter
from pathlib import Path

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "output"

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

# Synthetic confidence when falling back to threat_clusters (no real field there)
SEVERITY_CONFIDENCE = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2}


def _is_valid_ipv4(s: str) -> bool:
    if not IPV4_RE.match(s):
        return False
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def _sidecar_path(report_path: Path) -> Path:
    return report_path.with_name(report_path.stem + "_iocs.json")


def extract_from_sidecar(sidecar: Path) -> tuple[list[str], dict]:
    records = json.loads(sidecar.read_text())
    ips: list[str] = []
    confidences: list[float] = []
    tag_counter: Counter[str] = Counter()
    for rec in records:
        if rec.get("ioc_type") != "ipv4":
            continue
        if not _is_valid_ipv4(rec.get("value", "")):
            continue
        malicious = bool(rec.get("malicious"))
        confidence = float(rec.get("confidence", 0.0))
        if not (malicious or confidence >= 0.7):
            continue
        ips.append(rec["value"])
        confidences.append(confidence)
        for tag in rec.get("tags", []):
            tag_counter[tag] += 1
    summary = {
        "source": "sidecar",
        "sidecar": str(sidecar),
        "count": len(ips),
        "confidence_min": min(confidences) if confidences else None,
        "confidence_max": max(confidences) if confidences else None,
        "top_tags": tag_counter.most_common(5),
    }
    return sorted(set(ips)), summary


def extract_from_report(report_path: Path) -> tuple[list[str], dict]:
    report = json.loads(report_path.read_text())
    ips: list[str] = []
    confidences: list[float] = []
    cluster_names: list[str] = []
    severity_counts: Counter[str] = Counter()
    for cluster in report.get("threat_clusters", []):
        severity = str(cluster.get("severity", "UNKNOWN")).upper()
        confidence = SEVERITY_CONFIDENCE.get(severity, 0.0)
        # Gate: malicious (CRITICAL implies malicious) OR confidence >= 0.7
        if not (severity == "CRITICAL" or confidence >= 0.7):
            continue
        cluster_ips = [
            tid for tid in cluster.get("threat_ids", []) if _is_valid_ipv4(tid)
        ]
        if not cluster_ips:
            continue
        cluster_names.append(cluster.get("cluster_name", "?"))
        severity_counts[severity] += len(cluster_ips)
        ips.extend(cluster_ips)
        confidences.extend([confidence] * len(cluster_ips))
    summary = {
        "source": "threat_clusters_fallback",
        "report": str(report_path),
        "count": len(ips),
        "confidence_min": min(confidences) if confidences else None,
        "confidence_max": max(confidences) if confidences else None,
        "top_tags": [(name, severity_counts.most_common(1)[0][1] if severity_counts else 0) for name in cluster_names[:5]],
        "severity_breakdown": dict(severity_counts),
    }
    return sorted(set(ips)), summary


def _report_id(report_path: Path) -> str:
    # TIA-XXXXXXXX_YYYYMMDD_HHMMSS.json  -> TIA-XXXXXXXX_YYYYMMDD_HHMMSS
    return report_path.stem


def main() -> int:
    if len(sys.argv) > 1:
        report_path = Path(sys.argv[1]).expanduser().resolve()
    else:
        candidates = sorted(
            OUTPUT_DIR.glob("TIA-*.json"),
            key=lambda p: p.stat().st_mtime,
        )
        candidates = [p for p in candidates if not p.name.endswith("_iocs.json")]
        if not candidates:
            print("ERROR: no TIA-*.json reports found in output/", file=sys.stderr)
            return 1
        report_path = candidates[-1]

    if not report_path.exists():
        print(f"ERROR: report not found: {report_path}", file=sys.stderr)
        return 1

    sidecar = _sidecar_path(report_path)
    if sidecar.exists():
        ips, summary = extract_from_sidecar(sidecar)
    else:
        ips, summary = extract_from_report(report_path)

    blocklist_path = OUTPUT_DIR / f"blocklist_{_report_id(report_path)}.txt"
    blocklist_path.write_text("\n".join(ips) + ("\n" if ips else ""))

    print(f"Report:         {report_path.name}")
    print(f"Source:         {summary['source']}")
    print(f"Blocklist:      {blocklist_path}")
    print(f"IPs extracted:  {summary['count']}")
    if summary["confidence_min"] is not None:
        print(
            f"Confidence:     {summary['confidence_min']:.2f} – "
            f"{summary['confidence_max']:.2f}"
        )
    if summary.get("top_tags"):
        print("Top tags/clusters:")
        for tag, n in summary["top_tags"]:
            print(f"  - {tag}: {n}")
    if "severity_breakdown" in summary:
        print(f"Severity breakdown: {summary['severity_breakdown']}")

    return 0 if ips else 2


if __name__ == "__main__":
    sys.exit(main())
