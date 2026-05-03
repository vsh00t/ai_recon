"""Initial admin bootstrap from env vars."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

from sqlalchemy import select

from ai_recon_api.auth.security import hash_password
from ai_recon_api.db.models import User
from ai_recon_api.db.session import SessionLocal
from ai_recon_api.logging import get_logger
from ai_recon_api.settings import get_settings

logger = get_logger("bootstrap")


async def ensure_admin() -> None:
    settings = get_settings()
    if not settings.bootstrap_admin_email or not settings.bootstrap_admin_password:
        return
    async with SessionLocal() as db:
        res = await db.execute(select(User).where(User.email == settings.bootstrap_admin_email))
        if res.scalar_one_or_none():
            return
        user = User(
            id=secrets.token_hex(12),
            email=settings.bootstrap_admin_email,
            password_hash=hash_password(settings.bootstrap_admin_password),
            role="admin",
            created_at=datetime.now(timezone.utc),
        )
        db.add(user)
        await db.commit()
        logger.info("admin_bootstrapped", email=settings.bootstrap_admin_email)
