"""
Structured logging — compatible with structlog 24+ and Python 3.14.
Call configure_logging() at application startup.
"""

from __future__ import annotations

import logging
from typing import Any

import structlog


def configure_logging(json_logs: bool = False, log_level: str = "INFO") -> None:
    # `renderer` is either a `JSONRenderer` or a `ConsoleRenderer` — mypy
    # infers the first branch and rejects the reassignment. Widening the
    # annotation is simpler than importing both concrete types for a union.
    renderer: Any
    if json_logs:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.TimeStamper(fmt="iso"),
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(log_level.upper())
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
