# syntax=docker/dockerfile:1.7
#
# Threat Intel Aggregator — multi-stage build.
#
# Stage 1 (`builder`) installs the project and its runtime deps into a venv.
# Stage 2 (`runtime`) copies just the venv + source into a slim image and
# runs as a non-root user. Two stages keep the final image at ~200 MB instead
# of the ~1 GB that comes with build toolchains pulled in by pip.
#
# Dispatch shape:
#   docker run ghcr.io/you/threat-intel cli --keywords ransomware
#   docker run -p 8000:8000 ghcr.io/you/threat-intel api
#
# Build:   docker build -t threat-intel .
# Run CLI: docker run --rm --env-file .env threat-intel cli --dry-run
# Run API: docker run --rm -p 8000:8000 --env-file .env threat-intel api

# ───────────────────────────────────────────────────────────────────────────────
# Stage 1 — builder
# ───────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv

# Build tooling for wheel-less deps (aiohttp's c-extensions ship wheels for
# most archs, but pydantic-core occasionally needs rustc on exotic platforms).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /build

# Copy project metadata first so the dep layer stays cached when only source
# changes. `pip install -e .` reads pyproject.toml; deps resolve once.
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY main.py ./

RUN pip install --upgrade pip && \
    pip install .

# ───────────────────────────────────────────────────────────────────────────────
# Stage 2 — runtime
# ───────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/app"

# `tini` reaps zombie children — uvicorn spawns workers that need a proper
# PID-1 to clean up on `docker stop`. `curl` powers the HEALTHCHECK.
RUN apt-get update && apt-get install -y --no-install-recommends \
        tini \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user. Numeric uid/gid match the BSI/CIS baseline for containerised
# services (avoid uid 1000 collisions with host users on bind mounts).
RUN groupadd --system --gid 10001 tia && \
    useradd  --system --uid 10001 --gid tia --home-dir /app --shell /sbin/nologin tia

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=tia:tia src/   ./src/
COPY --chown=tia:tia main.py ./main.py
COPY --chown=tia:tia scripts/ ./scripts/
COPY --chown=tia:tia docker-entrypoint.sh /usr/local/bin/entrypoint

RUN chmod +x /usr/local/bin/entrypoint && \
    mkdir -p /app/output /app/logs && \
    chown -R tia:tia /app/output /app/logs

USER tia

# Persistent state — reports, SIEM alerts, sidecars, SQLite DB, logs.
VOLUME ["/app/output", "/app/logs"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/v1/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint"]
CMD ["api"]
