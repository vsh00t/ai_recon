"""Auth endpoints: login, logout, me."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Response, status
from sqlalchemy import select

from ai_recon_api.auth.security import create_access_token, verify_password
from ai_recon_api.db.models import User
from ai_recon_api.deps import CurrentUser, DbSession
from ai_recon_api.schemas.auth import LoginRequest, UserOut
from ai_recon_api.schemas.common import Message
from ai_recon_api.settings import get_settings

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=UserOut)
async def login(payload: LoginRequest, response: Response, db: DbSession) -> UserOut:
    res = await db.execute(select(User).where(User.email == payload.email))
    user = res.scalar_one_or_none()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    settings = get_settings()
    token = create_access_token(user.id, user.role)
    response.set_cookie(
        key=settings.cookie_name,
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,  # type: ignore[arg-type]
        max_age=settings.jwt_expires_minutes * 60,
        path="/",
    )
    return UserOut(
        id=user.id,
        email=user.email,  # type: ignore[arg-type]
        role=user.role,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


@router.post("/logout", response_model=Message)
async def logout(response: Response) -> Message:
    settings = get_settings()
    response.delete_cookie(settings.cookie_name, path="/")
    return Message(detail="logged out")


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,  # type: ignore[arg-type]
        role=user.role,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )
