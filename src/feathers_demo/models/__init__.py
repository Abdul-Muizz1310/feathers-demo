"""ORM models. Importing this package registers every table on Base.metadata."""

from __future__ import annotations

from feathers_demo.models.base import Base
from feathers_demo.models.user import User

__all__ = [
    "Base",
    "User",
]
