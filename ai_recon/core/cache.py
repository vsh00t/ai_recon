"""SQLite-backed HTTP and prompt response cache."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any


class ResponseCache:
    """Persistent cache keyed by (method, url, body_sha256).

    Allows ``--replay`` to reconstruct a run without touching the network.
    """

    def __init__(self, cache_dir: Path, run_id: str) -> None:
        self._path = cache_dir / run_id / "cache.db"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._init()

    def _init(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS responses (
                key       TEXT PRIMARY KEY,
                status    INTEGER,
                headers   TEXT,
                body      BLOB,
                cached_at REAL
            )
            """
        )
        self._conn.commit()

    @staticmethod
    def _make_key(method: str, url: str, body: bytes | None) -> str:
        body_hash = hashlib.sha256(body or b"").hexdigest()
        raw = f"{method.upper()}:{url}:{body_hash}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(
        self, method: str, url: str, body: bytes | None = None
    ) -> dict[str, Any] | None:
        key = self._make_key(method, url, body)
        row = self._conn.execute(
            "SELECT status, headers, body FROM responses WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        return {
            "status": row[0],
            "headers": json.loads(row[1]),
            "body": row[2],
        }

    def set(
        self,
        method: str,
        url: str,
        body: bytes | None,
        status: int,
        headers: dict[str, str],
        response_body: bytes,
    ) -> None:
        key = self._make_key(method, url, body)
        self._conn.execute(
            """
            INSERT OR REPLACE INTO responses (key, status, headers, body, cached_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (key, status, json.dumps(headers), response_body, time.time()),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
