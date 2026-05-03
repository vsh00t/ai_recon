"""WebSocket endpoint for live run events."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from ai_recon_api.auth.security import decode_access_token
from ai_recon_api.services.eventbus import bus
from ai_recon_api.settings import get_settings

router = APIRouter()


def _authenticate(ws: WebSocket) -> bool:
    settings = get_settings()
    token = ws.cookies.get(settings.cookie_name) or ws.query_params.get("token")
    if not token:
        return False
    return decode_access_token(token) is not None


@router.websocket("/ws/runs/{run_id}")
async def run_events(websocket: WebSocket, run_id: str, since: int = 0) -> None:
    if not _authenticate(websocket):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    channel = await bus.channel(run_id)

    # replay buffered events first
    for evt in channel.replay_since(since):
        await websocket.send_json(evt)

    queue = channel.subscribe()
    try:
        while True:
            try:
                evt = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_json(evt)
            except asyncio.TimeoutError:
                # heartbeat to keep connection alive
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        channel.unsubscribe(queue)
