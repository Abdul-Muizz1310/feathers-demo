"""Business logic for User.

A thin pass-through to the repository today — this is the seam where you add
validation, authorization, and cross-entity rules as the service grows. Routers
call these functions; they never reach the database directly.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from feathers_demo.models.user import User
from feathers_demo.repositories import user as repo


async def create(
    session: AsyncSession,
    data: dict[str, Any],
) -> User:
    """Create a User."""
    return await repo.create(session, data)


async def get(
    session: AsyncSession,
    id: UUID,
) -> User | None:
    """Fetch a User by primary key."""
    return await repo.get(session, id)


async def list_after(
    session: AsyncSession,
    *,
    cursor: UUID | None = None,
    limit: int = 50,
) -> list[User]:
    """List users with keyset pagination."""
    return await repo.list_after(session, cursor=cursor, limit=limit)


async def update(
    session: AsyncSession,
    id: UUID,
    data: dict[str, Any],
) -> User | None:
    """Apply a partial update to a User."""
    return await repo.update(session, id, data)


async def delete(
    session: AsyncSession,
    id: UUID,
) -> bool:
    """Delete a User."""
    return await repo.delete(session, id)
