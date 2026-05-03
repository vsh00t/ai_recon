"use client";

import type { RunEvent } from "./api";

export interface RunWsHandlers {
  onEvent: (ev: RunEvent) => void;
  onOpen?: () => void;
  onClose?: (code: number) => void;
  onError?: (e: Event) => void;
}

export function connectRunStream(runId: string, since: number, h: RunWsHandlers) {
  let closed = false;
  let ws: WebSocket | null = null;
  let retry = 0;
  let lastSeq = since;

  function open() {
    if (closed) return;
    const proto = typeof window !== "undefined" && window.location.protocol === "https:" ? "wss" : "ws";
    const host = typeof window !== "undefined" ? window.location.host : "";
    const url = `${proto}://${host}/ws/runs/${runId}?since=${lastSeq}`;
    ws = new WebSocket(url);
    ws.onopen = () => { retry = 0; h.onOpen?.(); };
    ws.onmessage = (m) => {
      try {
        const ev = JSON.parse(m.data) as RunEvent;
        if (ev.type === "ping") return;
        if (typeof ev.seq === "number") lastSeq = ev.seq;
        h.onEvent(ev);
      } catch {}
    };
    ws.onerror = (e) => h.onError?.(e);
    ws.onclose = (e) => {
      h.onClose?.(e.code);
      if (closed) return;
      const wait = Math.min(15_000, 500 * 2 ** retry++);
      setTimeout(open, wait);
    };
  }

  open();
  return () => { closed = true; ws?.close(); };
}
