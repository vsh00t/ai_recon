"""Auth-related DTOs."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)


class UserOut(BaseModel):
    id: str
    email: EmailStr
    role: str
    created_at: datetime
    last_login_at: datetime | None = None
