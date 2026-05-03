"""Techniques inspection endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from ai_recon_api.deps import CurrentUser
from ai_recon_api.services import catalog as catalog_svc

router = APIRouter(prefix="/techniques", tags=["techniques"])


@router.get("")
async def list_techniques(_: CurrentUser) -> list[dict]:
    return catalog_svc.list_techniques()


@router.get("/{technique_id}")
async def get_technique(technique_id: str, _: CurrentUser) -> dict:
    try:
        return catalog_svc.get_technique_meta(technique_id)
    except Exception as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))
