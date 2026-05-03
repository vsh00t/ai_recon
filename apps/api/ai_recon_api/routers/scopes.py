"""Scopes CRUD with JSON Schema validation."""

from __future__ import annotations

import json
import secrets

from fastapi import APIRouter, HTTPException, status
from jsonschema import Draft7Validator
from pydantic import BaseModel
from sqlalchemy import select

from ai_recon_api.db.models import Scope
from ai_recon_api.deps import CurrentUser, DbSession
from ai_recon_api.schemas.common import Message
from ai_recon_api.services import catalog as catalog_svc

router = APIRouter(prefix="/scopes", tags=["scopes"])


def _new_id() -> str:
    return secrets.token_hex(12)


def _validate(doc: dict) -> list[str]:
    try:
        schema = catalog_svc.get_schema("scope")
    except FileNotFoundError:
        return []
    validator = Draft7Validator(schema)
    return [
        f"{'/'.join(map(str, e.absolute_path)) or '/'}: {e.message}"
        for e in validator.iter_errors(doc)
    ]


class ScopeIn(BaseModel):
    name: str
    doc: dict


class ScopeOut(BaseModel):
    id: str
    name: str
    doc: dict


class ValidateOut(BaseModel):
    valid: bool
    errors: list[str]


@router.get("", response_model=list[ScopeOut])
async def list_scopes(_: CurrentUser, db: DbSession) -> list[ScopeOut]:
    res = await db.execute(select(Scope))
    out: list[ScopeOut] = []
    for row in res.scalars().all():
        out.append(ScopeOut(id=row.id, name=row.name, doc=json.loads(row.doc_json)))
    return out


@router.post("", response_model=ScopeOut)
async def create_scope(payload: ScopeIn, _: CurrentUser, db: DbSession) -> ScopeOut:
    errors = _validate(payload.doc)
    if errors:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, {"errors": errors})
    row = Scope(id=_new_id(), name=payload.name, doc_json=json.dumps(payload.doc))
    db.add(row)
    await db.commit()
    return ScopeOut(id=row.id, name=row.name, doc=payload.doc)


@router.get("/{scope_id}", response_model=ScopeOut)
async def get_scope(scope_id: str, _: CurrentUser, db: DbSession) -> ScopeOut:
    res = await db.execute(select(Scope).where(Scope.id == scope_id))
    row = res.scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scope not found")
    return ScopeOut(id=row.id, name=row.name, doc=json.loads(row.doc_json))


@router.put("/{scope_id}", response_model=ScopeOut)
async def update_scope(
    scope_id: str, payload: ScopeIn, _: CurrentUser, db: DbSession
) -> ScopeOut:
    errors = _validate(payload.doc)
    if errors:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, {"errors": errors})
    res = await db.execute(select(Scope).where(Scope.id == scope_id))
    row = res.scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scope not found")
    row.name = payload.name
    row.doc_json = json.dumps(payload.doc)
    await db.commit()
    return ScopeOut(id=row.id, name=row.name, doc=payload.doc)


@router.delete("/{scope_id}", response_model=Message)
async def delete_scope(scope_id: str, _: CurrentUser, db: DbSession) -> Message:
    res = await db.execute(select(Scope).where(Scope.id == scope_id))
    row = res.scalar_one_or_none()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scope not found")
    await db.delete(row)
    await db.commit()
    return Message(detail="deleted")


@router.post("/validate", response_model=ValidateOut)
async def validate_scope(payload: ScopeIn, _: CurrentUser) -> ValidateOut:
    errors = _validate(payload.doc)
    return ValidateOut(valid=not errors, errors=errors)
