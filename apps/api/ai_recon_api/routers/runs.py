"""Runs management endpoints."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import desc, select

from ai_recon_api.db.models import Finding, Run, RunEvent, Scope
from ai_recon_api.deps import CurrentUser, DbSession
from ai_recon_api.schemas.common import Message
from ai_recon_api.services import runner as runner_svc

router = APIRouter(prefix="/runs", tags=["runs"])


class RunSummary(BaseModel):
    id: str
    scope_id: str | None
    profile_name: str
    status: str
    intrusiveness: str
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None


class RunCreate(BaseModel):
    scope_id: str
    profile: str
    intrusiveness: str = "passive"
    options: dict[str, Any] = {}


class RunEventOut(BaseModel):
    seq: int | None = None
    ts: datetime
    type: str
    payload: dict[str, Any]


class FindingOut(BaseModel):
    id: str
    technique_id: str
    severity: str
    title: str
    doc: dict[str, Any]


def _to_summary(r: Run) -> RunSummary:
    return RunSummary(
        id=r.id,
        scope_id=r.scope_id,
        profile_name=r.profile_name,
        status=r.status,
        intrusiveness=r.intrusiveness,
        started_at=r.started_at,
        finished_at=r.finished_at,
        error_message=r.error_message,
    )


@router.get("", response_model=list[RunSummary])
async def list_runs(
    _: CurrentUser, db: DbSession, limit: int = 50, status_filter: str | None = None
) -> list[RunSummary]:
    stmt = select(Run).order_by(desc(Run.started_at)).limit(limit)
    if status_filter:
        stmt = stmt.where(Run.status == status_filter)
    res = await db.execute(stmt)
    return [_to_summary(r) for r in res.scalars().all()]


@router.post("", response_model=RunSummary)
async def create_run(payload: RunCreate, user: CurrentUser, db: DbSession) -> RunSummary:
    scope = await db.get(Scope, payload.scope_id)
    if not scope:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scope not found")

    run_id = runner_svc.new_run_id()
    run = Run(
        id=run_id,
        scope_id=payload.scope_id,
        profile_name=payload.profile,
        intrusiveness=payload.intrusiveness,
        triggered_by=user.id,
        options_json=json.dumps(payload.options),
        status="queued",
    )
    db.add(run)
    await db.commit()

    scope_doc = json.loads(scope.doc_json)
    await runner_svc.launch(run_id, scope_doc, payload.profile, payload.options)

    return _to_summary(run)


@router.get("/{run_id}", response_model=RunSummary)
async def get_run(run_id: str, _: CurrentUser, db: DbSession) -> RunSummary:
    run = await db.get(Run, run_id)
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    return _to_summary(run)


@router.post("/{run_id}/cancel", response_model=Message)
async def cancel_run(run_id: str, _: CurrentUser, db: DbSession) -> Message:
    run = await db.get(Run, run_id)
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    if not runner_svc.request_cancel(run_id):
        raise HTTPException(status.HTTP_409_CONFLICT, "run not active")
    return Message(detail="cancel requested")


@router.get("/{run_id}/events", response_model=list[RunEventOut])
async def list_events(
    run_id: str, _: CurrentUser, db: DbSession, since_id: int = 0, limit: int = 500
) -> list[RunEventOut]:
    stmt = (
        select(RunEvent)
        .where(RunEvent.run_id == run_id, RunEvent.id > since_id)
        .order_by(RunEvent.id)
        .limit(limit)
    )
    res = await db.execute(stmt)
    out: list[RunEventOut] = []
    for ev in res.scalars().all():
        out.append(
            RunEventOut(
                seq=ev.id,
                ts=ev.ts,
                type=ev.type,
                payload=json.loads(ev.payload_json),
            )
        )
    return out


@router.get("/{run_id}/findings", response_model=list[FindingOut])
async def list_findings(
    run_id: str,
    _: CurrentUser,
    db: DbSession,
    severity: str | None = None,
    technique: str | None = None,
) -> list[FindingOut]:
    stmt = select(Finding).where(Finding.run_id == run_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if technique:
        stmt = stmt.where(Finding.technique_id == technique)
    res = await db.execute(stmt)
    return [
        FindingOut(
            id=f.id,
            technique_id=f.technique_id,
            severity=f.severity,
            title=f.title,
            doc=json.loads(f.doc_json),
        )
        for f in res.scalars().all()
    ]
