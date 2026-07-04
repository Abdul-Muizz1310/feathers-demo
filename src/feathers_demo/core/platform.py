"""Platform middleware shared across feathers-generated services.

Provides the cross-cutting concerns every backend needs to be discoverable by a
control plane:

- ``X-Request-Id`` propagation (generated if absent, echoed on response)
- ``X-Platform-Token`` verification (demo mode accepts any token; see
  ``platform_token``)
- ``/health`` — liveness probe
- ``/version`` — build identifier
- ``/metrics`` — Prometheus exposition (via prometheus-fastapi-instrumentator)
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
import structlog

from feathers_demo.core.config import settings
from feathers_demo.core.db import check_db
from feathers_demo.core.platform_token import install_platform_token

_Handler = Callable[[Request], Awaitable[Response]]


def _parse_origins(raw: str) -> list[str]:
    """Split the comma-separated ``CORS_ORIGINS`` setting; empty → no origins."""
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def configure_logging() -> None:
    """Configure process logging from ``LOG_LEVEL`` (called once at startup)."""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(level=level)

    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def install_platform_middleware(app: FastAPI, *, service_name: str) -> None:
    """Attach platform endpoints and request-id middleware to ``app``."""

    origins = _parse_origins(settings.cors_origins)
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    install_platform_token(app, demo_mode=settings.demo_mode)

    @app.middleware("http")
    async def _request_id_middleware(request: Request, call_next: _Handler) -> Response:
        rid = request.headers.get("x-request-id") or str(uuid.uuid4())
        response = await call_next(request)
        response.headers["x-request-id"] = rid
        return response

    commit_sha = os.environ.get("GIT_SHA") or os.environ.get("RENDER_GIT_COMMIT", "unknown")

    @app.get("/health", include_in_schema=False)
    async def _health() -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "service": service_name,
                "version": "0.1.0",
                "commit_sha": commit_sha,
                "db": await check_db(),
            }
        )

    @app.get("/version", include_in_schema=False)
    async def _version() -> JSONResponse:
        return JSONResponse(
            {
                "service": service_name,
                "version": "0.1.0",
                "commit_sha": commit_sha,
            }
        )

    Instrumentator().instrument(app).expose(app, include_in_schema=False)
