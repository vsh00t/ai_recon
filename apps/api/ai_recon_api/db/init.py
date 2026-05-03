"""Schema bootstrapping (used in dev; Alembic in prod)."""

from __future__ import annotations

from ai_recon_api.db.models import Base
from ai_recon_api.db.session import engine


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
