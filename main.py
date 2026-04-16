#!/usr/bin/env python3
"""
main.py — CLI entrypoint for the Threat Intel Aggregator swarm.

Usage:
    python main.py                              # full run, all sources
    python main.py --keywords ransomware        # keyword-filtered run
    python main.py --max-cves 100 --max-iocs 200
    python main.py --serve                      # start FastAPI dashboard
    python main.py --dry-run                    # validate config only
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from src.logging_config import configure_logging

configure_logging(
    json_logs=os.getenv("LOG_FORMAT", "console") == "json",
    log_level=os.getenv("LOG_LEVEL", "INFO"),
)

import structlog

logger = structlog.get_logger(__name__)


def _secret(name: str):
    """Wrap an env-var API key in `SecretStr` so `repr(config)` can't leak it.

    The tool-client layer (`BaseAPIClient`) unwraps on construction; the three
    Anthropic-SDK call sites unwrap at the point of use. Everywhere else in
    the swarm, the key travels as a `SecretStr` whose `__repr__` masks it.
    """
    from pydantic import SecretStr
    raw = os.getenv(name)
    return SecretStr(raw) if raw else None


def _build_config() -> dict:
    return {
        "configurable": {
            "nvd_api_key":          _secret("NVD_API_KEY"),
            "otx_api_key":          _secret("OTX_API_KEY"),
            "abuseipdb_api_key":    _secret("ABUSEIPDB_API_KEY"),
            "greynoise_api_key":    _secret("GREYNOISE_API_KEY"),
            "anthropic_api_key":    _secret("ANTHROPIC_API_KEY"),
            "virustotal_api_key":   _secret("VIRUSTOTAL_API_KEY"),
            "shodan_api_key":       _secret("SHODAN_API_KEY"),
            "github_token":         _secret("GITHUB_TOKEN"),
            "cve_days_back":        int(os.getenv("CVE_DAYS_BACK", "7")),
            "attack_platform":      os.getenv("ATTACK_PLATFORM", "Windows"),
            "llm_model":            os.getenv("LLM_MODEL", "claude-opus-4-20250514"),
        }
    }


def _validate_config(config: dict) -> list[str]:
    warnings = []
    cfg = config["configurable"]
    if not cfg.get("anthropic_api_key"):
        warnings.append("ANTHROPIC_API_KEY not set — correlation agent will fail")
    if not cfg.get("nvd_api_key"):
        warnings.append("NVD_API_KEY not set — unauthenticated NVD (rate limited)")
    if not cfg.get("otx_api_key"):
        warnings.append("OTX_API_KEY not set — OTX IOC collection skipped")
    if not cfg.get("abuseipdb_api_key"):
        warnings.append("ABUSEIPDB_API_KEY not set — AbuseIPDB skipped")
    if not cfg.get("greynoise_api_key"):
        warnings.append("GREYNOISE_API_KEY not set — GreyNoise skipped")
    if not cfg.get("virustotal_api_key"):
        warnings.append("VIRUSTOTAL_API_KEY not set — VT enrichment skipped")
    if not cfg.get("shodan_api_key"):
        warnings.append("SHODAN_API_KEY not set — Shodan enrichment skipped")
    return warnings


async def _run(args: argparse.Namespace) -> int:
    from src.graph.swarm import run_swarm

    config = _build_config()
    warnings = _validate_config(config)

    print("\n╔══════════════════════════════════════════════════════╗")
    print("║       Threat Intel Aggregator  —  AI Swarm Run       ║")
    print("╚══════════════════════════════════════════════════════╝\n")

    if warnings:
        print("⚠  Configuration warnings:")
        for w in warnings:
            print(f"   • {w}")
        print()

    if args.dry_run:
        print("✓  Dry run complete — config validated, no API calls made.")
        return 0

    print(f"▶  Keywords : {args.keywords or '(none — all recent threats)'}")
    print(f"▶  Max CVEs : {args.max_cves}")
    print(f"▶  Max IOCs : {args.max_iocs}")
    print("▶  Agents   : CVE scraper · ATT&CK mapper · IOC extractor · Feed aggregator\n")

    t0 = time.monotonic()
    state = await run_swarm(
        query_keywords=args.keywords,
        max_cves=args.max_cves,
        max_iocs=args.max_iocs,
        config=config,
    )
    elapsed = time.monotonic() - t0

    print(f"\n{'═' * 56}")
    print(f"  Run complete in {elapsed:.1f}s")
    print(f"{'═' * 56}\n")

    # ── Side-channel integrations (graceful skip) ────────────────────────────
    try:
        from src.integrations.prometheus_exporter import push_metrics
        push_ok = push_metrics(state, run_duration_seconds=elapsed)
        print(f"  Prometheus push: {'✓' if push_ok else '⊘ skipped'}")
    except Exception as e:
        print(f"  Prometheus push: ✗ {e}")

    try:
        from src.integrations.es_indexer import index_run
        es_result = await index_run(state)
        if es_result.get("skipped"):
            print("  ES indexing: ⊘ skipped")
        else:
            print(
                f"  ES indexing: ✓ iocs={es_result['iocs']} "
                f"report={es_result['report']} alerts={es_result['alerts']}"
            )
    except Exception as e:
        print(f"  ES indexing: ✗ {e}")

    print("  Agent results:")
    for r in state.agent_results:
        status = "✓" if r.success else "✗"
        print(f"    {status}  {r.agent_name:<22} {r.items_fetched:>4} records  {r.duration_ms:>6.0f}ms")
        if r.error:
            print(f"       ↳ Error: {r.error}")

    print(f"\n  Raw records : {state.total_raw_records}")
    print(f"  After dedup : {len(state.normalized_threats)} ({state.dedup_removed} removed)")

    if state.report:
        rep = state.report
        print(f"\n  Report ID   : {rep.report_id}")
        print(f"  Clusters    : {len(rep.threat_clusters)}")
        print(f"  SIEM alerts : {len(rep.siem_alerts)}")
        print(f"  CRITICAL    : {rep.severity_breakdown.get('CRITICAL', 0)}")
        print(f"  HIGH        : {rep.severity_breakdown.get('HIGH', 0)}\n")

        output_files = list(Path("output").glob(f"{rep.report_id}*"))
        if output_files:
            print("  Output files:")
            for f in sorted(output_files):
                print(f"    • {f.name}  ({f.stat().st_size / 1024:.1f} KB)")

        print(f"\n  Executive summary:\n  {rep.executive_summary[:300]}...\n")
    else:
        print("\n  ✗ No report generated.")
        for err in state.errors:
            print(f"    • {err}")
        return 1

    return 0


def _serve() -> None:
    try:
        import uvicorn
    except ImportError:
        print("uvicorn not installed. Run: pip install uvicorn")
        sys.exit(1)
    print("\n  Starting API server...")
    print("  Swagger UI: http://localhost:8000/docs\n")
    uvicorn.run(
        "src.api.app:app",
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", "8000")),
        reload=True,
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Swarm Threat Intelligence Aggregator")
    parser.add_argument("--keywords", "-k", nargs="*", default=[], help="Filter keywords")
    parser.add_argument("--max-cves",  type=int, default=50)
    parser.add_argument("--max-iocs",  type=int, default=100)
    parser.add_argument("--serve",     action="store_true", help="Start FastAPI dashboard")
    parser.add_argument("--dry-run",   action="store_true", help="Validate config only")
    args = parser.parse_args()

    if args.serve:
        _serve()
    else:
        sys.exit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
