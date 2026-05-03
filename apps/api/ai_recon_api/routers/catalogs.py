"""Catalog browsing endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from ai_recon_api.deps import CurrentUser
from ai_recon_api.services import catalog as catalog_svc

router = APIRouter(prefix="/catalogs", tags=["catalogs"])


@router.get("")
async def list_catalogs(_: CurrentUser) -> list[str]:
    return catalog_svc.list_catalog_files()


@router.get("/{name}")
async def get_catalog(name: str, _: CurrentUser):
    try:
        return catalog_svc.get_catalog(name)
    except FileNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"catalog '{name}' not found")
