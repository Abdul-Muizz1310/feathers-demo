"""Routes for User."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from feathers_demo.core.db import get_session
from feathers_demo.core.platform_token import require_role
from feathers_demo.services import user as service
from feathers_demo.schemas.user import (
    UserCreate,
    UserResponse,
    UserUpdate,
)

router = APIRouter(prefix="/users", tags=["users"])


@router.post("", response_model=UserResponse, status_code=201, dependencies=[Depends(require_role("admin"))])
async def users_create(
    body: UserCreate, session: AsyncSession = Depends(get_session)
) -> UserResponse:
    """POST /users"""
    obj = await service.create(session, body.model_dump())
    return UserResponse.model_validate(obj)


@router.get("/{id}", response_model=UserResponse, dependencies=[Depends(require_role("any"))])
async def users_get(
    id: UUID, session: AsyncSession = Depends(get_session)
) -> UserResponse:
    """GET /users/{id}"""
    obj = await service.get(session, id)
    if obj is None:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.model_validate(obj)


@router.get("", response_model=list[UserResponse], dependencies=[Depends(require_role("any"))])
async def users_list(
    limit: int = Query(50, ge=1, le=100),
    cursor: UUID | None = Query(None),
    session: AsyncSession = Depends(get_session),
) -> list[UserResponse]:
    """GET /users (keyset/cursor pagination on id)"""
    rows = await service.list_after(session, cursor=cursor, limit=limit)
    return [UserResponse.model_validate(r) for r in rows]


@router.patch("/{id}", response_model=UserResponse, dependencies=[Depends(require_role("admin"))])
async def users_update(
    id: UUID,
    body: UserUpdate,
    session: AsyncSession = Depends(get_session),
) -> UserResponse:
    """PATCH /users/{id}"""
    obj = await service.update(session, id, body.model_dump(exclude_unset=True))
    if obj is None:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.model_validate(obj)


@router.delete("/{id}", status_code=204, dependencies=[Depends(require_role("admin"))])
async def users_delete(
    id: UUID, session: AsyncSession = Depends(get_session)
) -> None:
    """DELETE /users/{id}"""
    if not await service.delete(session, id):
        raise HTTPException(status_code=404, detail="User not found")
