"""SQLite persistence for ingested telemetry."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import Lock

from app.config import get_settings
from app.models.schemas import NormalizedEvent

_lock = Lock()


def db_path() -> Path:
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    return settings.data_dir / "lateralx.db"


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path()), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _lock:
        conn = connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    host TEXT,
                    user TEXT,
                    event_code INTEGER,
                    source_file TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ingest_batches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_file TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.commit()
        finally:
            conn.close()


def save_events(events: list[NormalizedEvent], source_file: str = "") -> int:
    if not events:
        return 0
    init_db()
    inserted = 0
    with _lock:
        conn = connect()
        try:
            for ev in events:
                try:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO events
                        (event_id, payload, timestamp, host, user, event_code, source_file)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            ev.event_id,
                            ev.model_dump_json(),
                            ev.timestamp.isoformat(),
                            ev.host,
                            ev.user,
                            ev.event_code,
                            source_file,
                        ),
                    )
                    inserted += 1
                except sqlite3.Error:
                    continue
            if source_file:
                from datetime import datetime, timezone

                conn.execute(
                    """
                    INSERT INTO ingest_batches (source_file, event_count, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (source_file, inserted, datetime.now(timezone.utc).isoformat()),
                )
            conn.commit()
        finally:
            conn.close()
    return inserted


def load_events() -> list[NormalizedEvent]:
    init_db()
    with _lock:
        conn = connect()
        try:
            rows = conn.execute(
                "SELECT payload FROM events ORDER BY timestamp ASC"
            ).fetchall()
        finally:
            conn.close()
    events: list[NormalizedEvent] = []
    for row in rows:
        try:
            events.append(NormalizedEvent.model_validate_json(row["payload"]))
        except Exception:
            try:
                events.append(NormalizedEvent.model_validate(json.loads(row["payload"])))
            except Exception:
                continue
    return events


def clear_events() -> int:
    init_db()
    with _lock:
        conn = connect()
        try:
            cur = conn.execute("SELECT COUNT(*) AS c FROM events")
            count = int(cur.fetchone()["c"])
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM ingest_batches")
            conn.commit()
            return count
        finally:
            conn.close()


def event_count() -> int:
    init_db()
    with _lock:
        conn = connect()
        try:
            return int(conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"])
        finally:
            conn.close()


def list_batches(limit: int = 50) -> list[dict]:
    init_db()
    with _lock:
        conn = connect()
        try:
            rows = conn.execute(
                """
                SELECT id, source_file, event_count, created_at
                FROM ingest_batches
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
