"""Async SQLAlchemy engine, session factory, and FastAPI session dependency.

When ``DATABASE_URL`` is unset, the service falls back to a local SQLite file
(``sqlite+aiosqlite``) so it runs and persists with no external database.
Production sets ``DATABASE_URL`` to a Postgres DSN.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from feathers_demo.core.config import settings

DEFAULT_DATABASE_URL = "sqlite+aiosqlite:///./feathers_demo.db"

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Get or create the process-wide async engine.

    For non-SQLite (i.e. serverless Postgres such as Neon), enable
    ``pool_pre_ping`` and a short ``pool_recycle`` so connections dropped during
    idle compute suspension are detected and replaced instead of handed out dead
    (which would 500 the first request after any idle window).
    """
    global _engine
    if _engine is None:
        url = settings.database_url or DEFAULT_DATABASE_URL
        kwargs: dict[str, object] = {"echo": False}
        if not url.startswith("sqlite"):
            kwargs["pool_pre_ping"] = True
            kwargs["pool_recycle"] = 300
        _engine = create_async_engine(url, **kwargs)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get or create the async session factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _session_factory


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a committed session per request."""
    session = get_session_factory()()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def init_models() -> None:
    """Create all tables from the ORM metadata (idempotent)."""
    from feathers_demo.models import Base

    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def check_db() -> str:
    """Probe database connectivity. Returns 'ok' or 'down'."""
    from sqlalchemy import text

    try:
        async with get_engine().connect() as conn:
            await conn.execute(text("SELECT 1"))
        return "ok"
    except Exception:
        return "down"
