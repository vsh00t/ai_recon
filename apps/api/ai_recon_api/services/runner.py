"""Background runner: bridges ai_recon to API persistence + event bus."""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ai_recon_api.db.models import Finding as DbFinding
from ai_recon_api.db.models import Run, RunEvent
from ai_recon_api.db.session import SessionLocal
from ai_recon_api.logging import get_logger
from ai_recon_api.services.eventbus import bus

logger = get_logger("runner")


_running: dict[str, asyncio.Task] = {}
_cancel_flags: dict[str, asyncio.Event] = {}


def is_running(run_id: str) -> bool:
    return run_id in _running and not _running[run_id].done()


def request_cancel(run_id: str) -> bool:
    flag = _cancel_flags.get(run_id)
    if flag is None:
        return False
    flag.set()
    return True


async def _persist_event(db: AsyncSession, run_id: str, evt: dict[str, Any]) -> None:
    payload = {k: v for k, v in evt.items() if k not in ("type",)}
    db.add(
        RunEvent(
            run_id=run_id,
            ts=datetime.now(timezone.utc),
            type=evt["type"],
            payload_json=json.dumps(payload),
        )
    )
    await db.commit()


async def _emit(db: AsyncSession, run_id: str, evt: dict[str, Any]) -> None:
    evt = {**evt, "ts": time.time()}
    await bus.publish(run_id, evt)
    try:
        await _persist_event(db, run_id, evt)
    except Exception as e:  # pragma: no cover
        logger.warning("event_persist_failed", run_id=run_id, error=str(e))


async def _run_inner(run_id: str, scope_doc: dict, profile_name: str, options: dict) -> None:
    cancel = _cancel_flags[run_id]
    async with SessionLocal() as db:
        run = await db.get(Run, run_id)
        if run is None:
            return
        run.status = "running"
        run.started_at = datetime.now(timezone.utc)
        await db.commit()

        await _emit(db, run_id, {"type": "run.started", "profile": profile_name})

        techniques: list[str] = options.get("techniques") or []
        if not techniques:
            try:
                from ai_recon_api.services import catalog as catalog_svc

                doc = catalog_svc.get_builtin_profile(profile_name)
                techs = doc.get("techniques") or {}
                if isinstance(techs, dict):
                    techniques = list(techs.get("enable") or [])
                elif isinstance(techs, list):
                    techniques = list(techs)
            except FileNotFoundError:
                techniques = []

        finding_count = 0
        try:
            for idx, tid in enumerate(techniques):
                if cancel.is_set():
                    await _emit(db, run_id, {"type": "run.canceled"})
                    run.status = "canceled"
                    run.finished_at = datetime.now(timezone.utc)
                    await db.commit()
                    return
                await _emit(
                    db,
                    run_id,
                    {
                        "type": "technique.started",
                        "id": tid,
                        "index": idx,
                        "total": len(techniques),
                    },
                )
                # NOTE: in this scaffold we don't execute live traffic — runner is wired
                # but technique execution against live targets requires a fully built
                # RunContext (HTTP client, scope guard, secrets, rate-limit). We emit a
                # synthetic completion so the UI streaming pipeline is exercised end-to-end.
                await asyncio.sleep(0.2)
                await _emit(
                    db,
                    run_id,
                    {
                        "type": "technique.completed",
                        "id": tid,
                        "duration_ms": 200,
                        "findings": 0,
                    },
                )
            run.status = "completed"
            run.finished_at = datetime.now(timezone.utc)
            await db.commit()
            await _emit(
                db,
                run_id,
                {"type": "run.completed", "findings": finding_count},
            )
        except Exception as e:  # pragma: no cover
            logger.exception("run_failed", run_id=run_id)
            run.status = "failed"
            run.error_message = str(e)
            run.finished_at = datetime.now(timezone.utc)
            await db.commit()
            await _emit(db, run_id, {"type": "run.failed", "error": str(e)})


async def launch(run_id: str, scope_doc: dict, profile_name: str, options: dict) -> None:
    flag = asyncio.Event()
    _cancel_flags[run_id] = flag
    task = asyncio.create_task(
        _run_inner(run_id, scope_doc, profile_name, options), name=f"run:{run_id}"
    )
    _running[run_id] = task

    def _cleanup(_: asyncio.Task) -> None:
        _running.pop(run_id, None)
        _cancel_flags.pop(run_id, None)

    task.add_done_callback(_cleanup)


def new_run_id() -> str:
    return secrets.token_hex(12)


def new_finding_id() -> str:
    return secrets.token_hex(12)


# Re-exports kept for symmetry with planned schema (Finding ORM persistence helper).
__all__ = [
    "launch",
    "is_running",
    "request_cancel",
    "new_run_id",
    "new_finding_id",
    "DbFinding",
]
