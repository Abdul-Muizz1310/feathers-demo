"""Initial schema for feathers_demo.

Creates every table from the ORM metadata. Subsequent changes should be
captured with ``alembic revision --autogenerate``.

Revision ID: 0001
Revises:
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    from feathers_demo.models import Base

    Base.metadata.create_all(op.get_bind())


def downgrade() -> None:
    from feathers_demo.models import Base

    Base.metadata.drop_all(op.get_bind())
