"""Adapters listing."""

from __future__ import annotations

from fastapi import APIRouter

from ai_recon_api.deps import CurrentUser
from ai_recon_api.services import catalog as catalog_svc

router = APIRouter(prefix="/adapters", tags=["adapters"])


@router.get("")
async def list_adapters(_: CurrentUser) -> dict[str, list[str]]:
    return catalog_svc.list_adapters()
