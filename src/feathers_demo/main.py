"""FastAPI entry point for feathers_demo."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from feathers_demo.core.db import get_engine, init_models
from feathers_demo.core.platform import configure_logging, install_platform_middleware
from feathers_demo.api.routers.users import router as users_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create the schema on SQLite startup; Postgres is managed by Alembic."""
    if get_engine().dialect.name == "sqlite":
        await init_models()
    yield


configure_logging()
app = FastAPI(title="feathers_demo", version="0.1.0", lifespan=lifespan)
install_platform_middleware(app, service_name="feathers_demo")

app.include_router(users_router)
