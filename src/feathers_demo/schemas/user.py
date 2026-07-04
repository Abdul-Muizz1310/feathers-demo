"""Pydantic request/response schemas for User."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict


class UserCreate(BaseModel):
    """Request body for creating a User."""

    email: str
    full_name: str
    role: Literal['admin', 'editor', 'viewer'] = 'viewer'


class UserUpdate(BaseModel):
    """Patch body for a User — every field optional."""

    email: str | None = None
    full_name: str | None = None
    role: Literal['admin', 'editor', 'viewer'] | None = None


class UserResponse(BaseModel):
    """Response body for a User."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    full_name: str
    role: Literal['admin', 'editor', 'viewer']
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None = None
