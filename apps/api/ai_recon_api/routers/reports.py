"""Reports endpoints (summary + findings + render)."""

from __future__ import annotations

import json
from collections import Counter

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import select

from ai_recon_api.db.models import Finding, Run
from ai_recon_api.deps import CurrentUser, DbSession

router = APIRouter(prefix="/reports", tags=["reports"])


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ReportSummary(BaseModel):
    run_id: str
    profile: str
    status: str
    started_at: str | None
    finished_at: str | None
    severity: SeverityBreakdown
    findings_total: int


@router.get("/{run_id}", response_model=ReportSummary)
async def get_report(run_id: str, _: CurrentUser, db: DbSession) -> ReportSummary:
    run = await db.get(Run, run_id)
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    res = await db.execute(select(Finding.severity).where(Finding.run_id == run_id))
    sevs = Counter([row[0] for row in res.all()])
    return ReportSummary(
        run_id=run.id,
        profile=run.profile_name,
        status=run.status,
        started_at=run.started_at.isoformat() if run.started_at else None,
        finished_at=run.finished_at.isoformat() if run.finished_at else None,
        severity=SeverityBreakdown(
            critical=sevs.get("critical", 0),
            high=sevs.get("high", 0),
            medium=sevs.get("medium", 0),
            low=sevs.get("low", 0),
            info=sevs.get("info", 0),
        ),
        findings_total=sum(sevs.values()),
    )


@router.get("/{run_id}/render")
async def render(run_id: str, _: CurrentUser, db: DbSession, format: str = "json"):
    run = await db.get(Run, run_id)
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    res = await db.execute(select(Finding).where(Finding.run_id == run_id))
    findings = [
        {
            "id": f.id,
            "technique": f.technique_id,
            "severity": f.severity,
            "title": f.title,
            "doc": json.loads(f.doc_json),
        }
        for f in res.scalars().all()
    ]
    payload = {
        "run_id": run.id,
        "profile": run.profile_name,
        "status": run.status,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "findings": findings,
    }
    if format == "json":
        return payload
    if format == "md":
        lines = [f"# Report — run {run.id}", "", f"Profile: `{run.profile_name}`",
                 f"Status: `{run.status}`", "", f"## Findings ({len(findings)})", ""]
        for f in findings:
            lines.append(f"- **[{f['severity']}]** `{f['technique']}` — {f['title']}")
        return Response("\n".join(lines), media_type="text/markdown")
    raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown format '{format}'")
