"""Profiles endpoints (built-in + custom CRUD)."""

from __future__ import annotations

import yaml
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select

from ai_recon_api.db.models import ProfileCustom
from ai_recon_api.deps import CurrentUser, DbSession
from ai_recon_api.schemas.common import Message
from ai_recon_api.services import catalog as catalog_svc

router = APIRouter(prefix="/profiles", tags=["profiles"])


class ProfileSummary(BaseModel):
    name: str
    source: str  # builtin | custom
    description: str | None = None


class ProfileDoc(BaseModel):
    name: str
    source: str
    doc: dict


class ProfileWriteIn(BaseModel):
    name: str
    yaml_doc: str
    description: str | None = None


@router.get("", response_model=list[ProfileSummary])
async def list_profiles(_: CurrentUser, db: DbSession) -> list[ProfileSummary]:
    out: list[ProfileSummary] = []
    for n in catalog_svc.list_builtin_profiles():
        try:
            doc = catalog_svc.get_builtin_profile(n)
            desc = doc.get("description")
        except Exception:
            desc = None
        out.append(ProfileSummary(name=n, source="builtin", description=desc))
    res = await db.execute(select(ProfileCustom))
    for row in res.scalars().all():
        out.append(ProfileSummary(name=row.name, source="custom", description=row.description))
    return out


@router.get("/{name}", response_model=ProfileDoc)
async def get_profile(name: str, _: CurrentUser, db: DbSession) -> ProfileDoc:
    try:
        doc = catalog_svc.get_builtin_profile(name)
        return ProfileDoc(name=name, source="builtin", doc=doc)
    except FileNotFoundError:
        pass
    res = await db.execute(select(ProfileCustom).where(ProfileCustom.name == name))
    row = res.scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"profile '{name}' not found")
    doc = yaml.safe_load(row.doc_yaml) or {}
    return ProfileDoc(name=name, source="custom", doc=doc)


@router.post("", response_model=ProfileDoc)
async def create_profile(payload: ProfileWriteIn, _: CurrentUser, db: DbSession) -> ProfileDoc:
    if payload.name in catalog_svc.list_builtin_profiles():
        raise HTTPException(status.HTTP_409_CONFLICT, "name reserved by built-in profile")
    try:
        doc = yaml.safe_load(payload.yaml_doc) or {}
    except yaml.YAMLError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"invalid yaml: {e}")
    res = await db.execute(select(ProfileCustom).where(ProfileCustom.name == payload.name))
    if res.scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "profile already exists")
    row = ProfileCustom(
        name=payload.name, doc_yaml=payload.yaml_doc, description=payload.description
    )
    db.add(row)
    await db.commit()
    return ProfileDoc(name=payload.name, source="custom", doc=doc)


@router.put("/{name}", response_model=ProfileDoc)
async def update_profile(
    name: str, payload: ProfileWriteIn, _: CurrentUser, db: DbSession
) -> ProfileDoc:
    if name in catalog_svc.list_builtin_profiles():
        raise HTTPException(status.HTTP_409_CONFLICT, "built-in profiles are read-only")
    res = await db.execute(select(ProfileCustom).where(ProfileCustom.name == name))
    row = res.scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "profile not found")
    try:
        doc = yaml.safe_load(payload.yaml_doc) or {}
    except yaml.YAMLError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"invalid yaml: {e}")
    row.doc_yaml = payload.yaml_doc
    row.description = payload.description
    await db.commit()
    return ProfileDoc(name=name, source="custom", doc=doc)


@router.delete("/{name}", response_model=Message)
async def delete_profile(name: str, _: CurrentUser, db: DbSession) -> Message:
    if name in catalog_svc.list_builtin_profiles():
        raise HTTPException(status.HTTP_409_CONFLICT, "built-in profiles cannot be deleted")
    res = await db.execute(select(ProfileCustom).where(ProfileCustom.name == name))
    row = res.scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "profile not found")
    await db.delete(row)
    await db.commit()
    return Message(detail="deleted")
