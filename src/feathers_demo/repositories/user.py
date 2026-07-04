"""Async repository for User — all User DB access."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from feathers_demo.models.user import User


async def create(session: AsyncSession, data: dict[str, Any]) -> User:
    """Insert a User and return it (server defaults loaded)."""
    obj = User(**data)
    session.add(obj)
    await session.flush()
    await session.refresh(obj)
    return obj


async def get(session: AsyncSession, id: UUID) -> User | None:
    """Fetch a User by primary key, or None."""
    return await session.get(User, id)


# A hard ceiling on how many rows a single list query may return, enforced in
# the repository so no caller (router bound or otherwise) can exhaust memory.
MAX_LIMIT = 100


def _clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIMIT))


async def list_all(
    session: AsyncSession, *, limit: int = 50, offset: int = 0
) -> list[User]:
    """List users with offset pagination (limit hard-capped at MAX_LIMIT)."""
    stmt = (
        select(User)
        .where(User.deleted_at.is_(None))
        .order_by(User.id)
        .limit(_clamp_limit(limit))
        .offset(max(0, offset))
    )
    return list((await session.scalars(stmt)).all())


async def list_after(
    session: AsyncSession, *, cursor: UUID | None = None, limit: int = 50
) -> list[User]:
    """Keyset (cursor) pagination on id; pass the last row's id to page forward."""
    stmt = select(User)
    stmt = stmt.where(User.deleted_at.is_(None))
    if cursor is not None:
        stmt = stmt.where(User.id > cursor)
    stmt = stmt.order_by(User.id).limit(_clamp_limit(limit))
    return list((await session.scalars(stmt)).all())


async def update(
    session: AsyncSession, id: UUID, data: dict[str, Any]
) -> User | None:
    """Apply a partial update; returns None if the row does not exist."""
    obj = await session.get(User, id)
    if obj is None:
        return None
    for key, value in data.items():
        setattr(obj, key, value)
    await session.flush()
    await session.refresh(obj)
    return obj


async def delete(session: AsyncSession, id: UUID) -> bool:
    """Soft-delete a User; returns False if it does not exist."""
    obj = await session.get(User, id)
    if obj is None:
        return False
    obj.deleted_at = datetime.now(UTC)
    await session.flush()
    return True
