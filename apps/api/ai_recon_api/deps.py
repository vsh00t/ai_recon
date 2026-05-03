"""FastAPI dependencies (current user, db session, RBAC)."""

from __future__ import annotations

from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ai_recon_api.auth.security import decode_access_token
from ai_recon_api.db.models import User
from ai_recon_api.db.session import get_session
from ai_recon_api.settings import get_settings

DbSession = Annotated[AsyncSession, Depends(get_session)]


async def current_user(
    db: DbSession,
    session_cookie: Annotated[str | None, Cookie(alias=get_settings().cookie_name)] = None,
) -> User:
    if not session_cookie:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing session")
    payload = decode_access_token(session_cookie)
    if not payload:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid session")
    user_id = payload.get("sub")
    res = await db.execute(select(User).where(User.id == user_id))
    user = res.scalar_one_or_none()
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown user")
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def require_role(*roles: str):
    async def _check(user: CurrentUser) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        return user

    return _check
