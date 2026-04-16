"""
FastAPI dashboard — REST API + SQLite cache for reports and SIEM alert delivery.
Run: uvicorn src.api.app:app --reload
"""

from __future__ import annotations

import json
import os
import secrets as _py_secrets
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import aiosqlite
import structlog
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

logger = structlog.get_logger(__name__)

DB_PATH = "output/reports.db"

# ── Auth + CORS ───────────────────────────────────────────────────────────────
#
# `TIA_API_KEY` gates every write + read endpoint. If it's unset we log a
# loud warning and *still* require a header, which forces explicit opt-in
# for unauthenticated local runs (set `TIA_API_KEY=` to the empty string to
# disable — but that path is a deliberate escape hatch, not the default).
#
# `TIA_CORS_ORIGINS` is a comma-separated origin list. Default is localhost
# only; wildcards are rejected to stop an accidental `*` in prod.

_API_KEY_ENV = os.getenv("TIA_API_KEY")
_CORS_ORIGINS_ENV = os.getenv("TIA_CORS_ORIGINS", "http://localhost:3000,http://localhost:8000")
CORS_ORIGINS = [o.strip() for o in _CORS_ORIGINS_ENV.split(",") if o.strip() and o.strip() != "*"]
if not _API_KEY_ENV:
    logger.warning(
        "tia_api_key_unset",
        message="TIA_API_KEY not set — API is unauthenticated. Set TIA_API_KEY in .env for any network-exposed run.",
    )

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(provided: str | None = Security(_api_key_header)) -> None:
    """
    Reject requests without a matching `X-API-Key` header.

    Uses `secrets.compare_digest` to avoid a timing-side-channel on the
    comparison. When `TIA_API_KEY` is unset the check passes (dev mode) —
    lifespan logs a warning at startup so this doesn't silently ship.
    """
    if not _API_KEY_ENV:
        return  # dev mode — warning already logged at import time
    if not provided or not _py_secrets.compare_digest(provided, _API_KEY_ENV):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


# ── Lifespan (replaces deprecated on_event) ───────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    Path("output").mkdir(exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        # WAL mode lets concurrent readers coexist with one writer — matters
        # when a background swarm run is inserting while the dashboard is
        # reading `/api/v1/reports`. Without WAL, concurrent writers trip
        # `SQLITE_BUSY` on anything beyond a single background task.
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=NORMAL")  # WAL-safe, faster than FULL
        await db.execute("PRAGMA busy_timeout=5000")  # 5s grace on contention

        await db.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                run_id TEXT PRIMARY KEY,
                report_id TEXT,
                generated_at TEXT,
                executive_summary TEXT,
                total_threats INTEGER,
                severity_breakdown TEXT,
                sources TEXT,
                markdown_report TEXT,
                full_json TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS siem_alerts (
                id TEXT PRIMARY KEY,
                run_id TEXT,
                rule_name TEXT,
                severity TEXT,
                description TEXT,
                cve_ref TEXT,
                mitre_technique TEXT,
                created_at TEXT,
                tags TEXT
            )
        """)

        # Indexes for the ORDER-BY and WHERE columns used by the list / filter
        # endpoints — without these, every list call does a full table scan
        # and latency grows linearly with history.
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_reports_generated_at ON reports(generated_at DESC)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON siem_alerts(created_at DESC)"
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON siem_alerts(severity)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_run_id ON siem_alerts(run_id)")
        await db.commit()
    logger.info("database_initialized", path=DB_PATH)
    yield


app = FastAPI(
    title="Threat Intel Aggregator API",
    description="AI swarm-powered threat intelligence correlation platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
    allow_credentials=True,
)


# ── Request/Response schemas ──────────────────────────────────────────────────


class RunRequest(BaseModel):
    keywords: list[str] = []
    max_cves: int = 50
    max_iocs: int = 100


class RunStatus(BaseModel):
    run_id: str
    status: str
    message: str


class ReportSummary(BaseModel):
    run_id: str
    report_id: str
    generated_at: str
    executive_summary: str
    total_threats: int
    severity_breakdown: dict[str, int]
    sources: list[str]


# ── Background swarm runner ───────────────────────────────────────────────────


async def _run_swarm_background(run_id: str, request: RunRequest) -> None:
    import os

    from pydantic import SecretStr

    from src.graph.swarm import run_swarm

    def _secret(name: str) -> SecretStr | None:
        raw = os.getenv(name)
        return SecretStr(raw) if raw else None

    config = {
        "configurable": {
            "nvd_api_key": _secret("NVD_API_KEY"),
            "otx_api_key": _secret("OTX_API_KEY"),
            "abuseipdb_api_key": _secret("ABUSEIPDB_API_KEY"),
            "greynoise_api_key": _secret("GREYNOISE_API_KEY"),
            "anthropic_api_key": _secret("ANTHROPIC_API_KEY"),
            "virustotal_api_key": _secret("VIRUSTOTAL_API_KEY"),
            "shodan_api_key": _secret("SHODAN_API_KEY"),
            "github_token": _secret("GITHUB_TOKEN"),
            "cve_days_back": 7,
            "attack_platform": "Windows",
            "llm_model": os.getenv("LLM_MODEL", "claude-opus-4-20250514"),
        }
    }

    try:
        state = await run_swarm(
            query_keywords=request.keywords,
            max_cves=request.max_cves,
            max_iocs=request.max_iocs,
            config=config,
        )

        if state.report:
            async with aiosqlite.connect(DB_PATH) as db:
                await db.execute(
                    """INSERT OR REPLACE INTO reports
                       (run_id, report_id, generated_at, executive_summary,
                        total_threats, severity_breakdown, sources, markdown_report, full_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        run_id,
                        state.report.report_id,
                        state.report.generated_at.isoformat(),
                        state.report.executive_summary,
                        state.report.total_threats_processed,
                        json.dumps(state.report.severity_breakdown),
                        json.dumps(state.report.sources_queried),
                        state.report.markdown_report,
                        json.dumps(state.report.model_dump(mode="json"), default=str),
                    ),
                )

                for alert in state.report.siem_alerts:
                    await db.execute(
                        """INSERT OR IGNORE INTO siem_alerts
                           (id, run_id, rule_name, severity, description,
                            cve_ref, mitre_technique, created_at, tags)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            str(uuid.uuid4()),
                            run_id,
                            alert.get("rule_name", ""),
                            alert.get("severity", ""),
                            alert.get("description", ""),
                            alert.get("cve_ref", ""),
                            alert.get("mitre_technique", ""),
                            datetime.now(UTC).isoformat(),
                            json.dumps(alert.get("tags", [])),
                        ),
                    )
                await db.commit()
            logger.info("report_persisted", run_id=run_id, report_id=state.report.report_id)

    except Exception as exc:
        logger.error("swarm_background_failed", run_id=run_id, error=str(exc))


# ── Routes ────────────────────────────────────────────────────────────────────


@app.post(
    "/api/v1/runs",
    response_model=RunStatus,
    status_code=202,
    dependencies=[Depends(require_api_key)],
)
async def trigger_run(request: RunRequest, background_tasks: BackgroundTasks) -> RunStatus:
    """Trigger a new threat intel aggregation swarm run."""
    run_id = str(uuid.uuid4())
    background_tasks.add_task(_run_swarm_background, run_id, request)
    logger.info("run_triggered", run_id=run_id, keywords=request.keywords)
    return RunStatus(
        run_id=run_id,
        status="accepted",
        message=f"Swarm run {run_id} started. Poll /api/v1/reports for results.",
    )


@app.get(
    "/api/v1/reports", response_model=list[ReportSummary], dependencies=[Depends(require_api_key)]
)
async def list_reports(limit: int = 20) -> list[ReportSummary]:
    """List recent threat intelligence reports."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM reports ORDER BY generated_at DESC LIMIT ?", (limit,)
        ) as cursor:
            rows = await cursor.fetchall()

    return [
        ReportSummary(
            run_id=row["run_id"],
            report_id=row["report_id"],
            generated_at=row["generated_at"],
            executive_summary=row["executive_summary"],
            total_threats=row["total_threats"],
            severity_breakdown=json.loads(row["severity_breakdown"]),
            sources=json.loads(row["sources"]),
        )
        for row in rows
    ]


@app.get(
    "/api/v1/reports/{run_id}",
    response_model=dict[str, Any],
    dependencies=[Depends(require_api_key)],
)
async def get_report(run_id: str) -> dict[str, Any]:
    """Get full report JSON for a run."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT full_json FROM reports WHERE run_id = ?", (run_id,)
        ) as cursor:
            row = await cursor.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail=f"Report not found: {run_id}")
    return cast("dict[str, Any]", json.loads(row["full_json"]))


@app.get(
    "/api/v1/reports/{run_id}/markdown",
    response_class=PlainTextResponse,
    dependencies=[Depends(require_api_key)],
)
async def get_report_markdown(run_id: str) -> str:
    """Get markdown-rendered report."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT markdown_report FROM reports WHERE run_id = ?", (run_id,)
        ) as cursor:
            row = await cursor.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail=f"Report not found: {run_id}")
    return cast("str", row["markdown_report"])


@app.get(
    "/api/v1/alerts", response_model=list[dict[str, Any]], dependencies=[Depends(require_api_key)]
)
async def list_alerts(severity: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    """List SIEM alerts, optionally filtered by severity."""
    query = "SELECT * FROM siem_alerts"
    params: list[Any] = []
    if severity:
        query += " WHERE severity = ?"
        params.append(severity.upper())
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()

    return [dict(row) for row in rows]


@app.get("/api/v1/health")
async def health() -> dict[str, Any]:
    """
    Liveness + dependency probe. Intentionally unauthenticated — k8s-style
    liveness/readiness checks must work without credentials.

    Returns a per-component status dict so ops tooling can distinguish "the
    process is alive but SQLite is missing" from "everything's fine." No
    key *values* are reported; only presence.
    """
    components: dict[str, str] = {}
    overall = "ok"

    # SQLite: open + simple round-trip
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT 1") as cur:
                row = await cur.fetchone()
            components["sqlite"] = "ok" if row and row[0] == 1 else "degraded"
    except Exception as exc:
        components["sqlite"] = f"down: {type(exc).__name__}"
        overall = "degraded"

    # Anthropic key presence — correlation agent won't work without it.
    components["anthropic_key"] = "present" if os.getenv("ANTHROPIC_API_KEY") else "missing"
    if components["anthropic_key"] == "missing":
        overall = "degraded"

    # Auth gate status — "enabled" when TIA_API_KEY is set, else "dev-mode".
    components["api_auth"] = "enabled" if _API_KEY_ENV else "dev-mode"

    return {"status": overall, "version": app.version, "components": components}
