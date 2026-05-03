"""System endpoints: health, version."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from ai_recon_api import __version__

router = APIRouter(prefix="/system", tags=["system"])


class HealthOut(BaseModel):
    status: str
    version: str


class VersionOut(BaseModel):
    api: str
    lib: str | None


@router.get("/health", response_model=HealthOut)
async def health() -> HealthOut:
    return HealthOut(status="ok", version=__version__)


@router.get("/version", response_model=VersionOut)
async def version() -> VersionOut:
    try:
        import ai_recon

        lib_version = getattr(ai_recon, "__version__", None)
    except Exception:
        lib_version = None
    return VersionOut(api=__version__, lib=lib_version)
