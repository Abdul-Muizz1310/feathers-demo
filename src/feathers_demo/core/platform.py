"""Platform plumbing shared by feathers-generated services.

- ``X-Request-Id`` propagation (generated if absent, echoed on the response)
- platform token verification and rate limiting (``platform_token``, contract v2)
- ``/health`` (liveness and a live database probe) and ``/version``
- ``/metrics`` — Prometheus exposition (via prometheus-fastapi-instrumentator)
- CORS for the configured origins, outermost so a preflight never meets the token check
"""

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import Awaitable, Callable

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

from feathers_demo.core.config import settings
from feathers_demo.core.db import check_db
from feathers_demo.core.platform_token import install_platform_token

_Handler = Callable[[Request], Awaitable[Response]]

# Contract v2: browsers may send the token, a request id and JSON; nothing else.
_CORS_REQUEST_HEADERS = ["authorization", "content-type", "x-platform-token", "x-request-id"]


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
    """Attach platform endpoints and middleware to ``app``.

    Middleware added later wraps what was added earlier, so the order below is
    innermost first: token check, request id, metrics, then CORS on the outside.
    """
    install_platform_token(app)

    @app.middleware("http")
    async def _request_id_middleware(request: Request, call_next: _Handler) -> Response:
        rid = request.headers.get("x-request-id") or str(uuid.uuid4())
        response = await call_next(request)
        response.headers["x-request-id"] = rid
        return response

    Instrumentator().instrument(app).expose(app, include_in_schema=False)

    origins = _parse_origins(settings.cors_origins)
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=_CORS_REQUEST_HEADERS,
            expose_headers=["x-request-id"],
        )

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
