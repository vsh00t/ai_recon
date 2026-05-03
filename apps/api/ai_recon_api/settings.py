"""Application settings loaded from environment."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AI_RECON_",
        env_file=".env",
        extra="ignore",
    )

    env: str = Field(default="dev")
    log_level: str = Field(default="INFO")

    db_url: str = Field(default="sqlite+aiosqlite:///./ai_recon_api.db")
    reports_dir: Path = Field(default=Path("./reports"))

    jwt_secret: str = Field(default="change-me-in-prod")
    jwt_algorithm: str = Field(default="HS256")
    jwt_expires_minutes: int = Field(default=60 * 12)

    cookie_name: str = Field(default="ai_recon_session")
    cookie_secure: bool = Field(default=False)
    cookie_samesite: str = Field(default="lax")

    allowed_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])

    bootstrap_admin_email: str | None = Field(default=None)
    bootstrap_admin_password: str | None = Field(default=None)


@lru_cache
def get_settings() -> Settings:
    return Settings()
