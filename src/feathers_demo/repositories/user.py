"""Async repository for User — all User database access."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from feathers_demo.models.user import User


async def create(
    session: AsyncSession,
    data: dict[str, Any],
) -> User:
    """Insert a User and return it (server defaults loaded)."""
    obj = User(**data)
    session.add(obj)
    await session.flush()
    await session.refresh(obj)
    return obj


async def _live(
    session: AsyncSession,
    id: UUID,
) -> User | None:
    """Fetch a live User by primary key, or None.

    The single primary-key lookup every CRUD path goes through, so none of them can
    forget the soft-delete filter: once ``deleted_at`` is set the row is retained in
    the database but is indistinguishable from absent to readers and writers alike.
    """
    obj = await session.get(User, id)
    if obj is not None and obj.deleted_at is not None:
        return None
    return obj


async def get(
    session: AsyncSession,
    id: UUID,
) -> User | None:
    """Fetch a User by primary key, or None."""
    return await _live(session, id)


# A hard ceiling on how many rows a single list query may return, enforced in
# the repository so no caller (router bound or otherwise) can exhaust memory.
MAX_LIMIT = 100


def _clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIMIT))


async def list_after(
    session: AsyncSession,
    *,
    cursor: UUID | None = None,
    limit: int = 50,
) -> list[User]:
    """List users after the ``cursor`` primary key (keyset; limit capped)."""
    stmt = select(User)
    stmt = stmt.where(User.deleted_at.is_(None))
    if cursor is not None:
        stmt = stmt.where(User.id > cursor)
    stmt = stmt.order_by(User.id)
    stmt = stmt.limit(_clamp_limit(limit))
    return list((await session.scalars(stmt)).all())


async def update(
    session: AsyncSession,
    id: UUID,
    data: dict[str, Any],
) -> User | None:
    """Apply a partial update; None when the row is absent or soft-deleted."""
    obj = await _live(session, id)
    if obj is None:
        return None
    for key, value in data.items():
        setattr(obj, key, value)
    await session.flush()
    await session.refresh(obj)
    return obj


async def delete(
    session: AsyncSession,
    id: UUID,
) -> bool:
    """Soft-delete a User; False when it is absent or already deleted."""
    obj = await _live(session, id)
    if obj is None:
        return False
    obj.deleted_at = datetime.now(UTC)
    await session.flush()
    return True
