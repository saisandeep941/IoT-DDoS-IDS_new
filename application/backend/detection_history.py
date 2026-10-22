"""Small, bounded SQLite persistence for recent detection records."""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from threading import Lock


class DetectionHistoryStore:
    def __init__(self, path: str | Path | None = None, limit: int = 500):
        self.path = Path(path or os.getenv(
            "SENTINEL_HISTORY_DB",
            Path(__file__).resolve().parents[1] / "data" / "detection_history.sqlite3",
        ))
        self.limit = int(limit)
        self._lock = Lock()
        self.initialize()

    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def initialize(self):
        with self._lock, self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS detections ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, record_json TEXT NOT NULL)"
            )
            connection.execute(
                "DELETE FROM detections WHERE id NOT IN "
                "(SELECT id FROM detections ORDER BY id DESC LIMIT ?)",
                (self.limit,),
            )

    def latest(self):
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT id, record_json FROM detections ORDER BY id DESC LIMIT ?",
                (self.limit,),
            ).fetchall()
        records = []
        for row in rows:
            record = json.loads(row["record_json"])
            record["id"] = row["id"]
            records.append(record)
        return records

    def append(self, record):
        payload = dict(record)
        payload.pop("id", None)
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO detections(record_json) VALUES (?)",
                (json.dumps(payload, ensure_ascii=False, separators=(",", ":")),),
            )
            record_id = int(cursor.lastrowid)
            connection.execute(
                "DELETE FROM detections WHERE id NOT IN "
                "(SELECT id FROM detections ORDER BY id DESC LIMIT ?)",
                (self.limit,),
            )
        return {**payload, "id": record_id}

    def remove_replay(self, replay_id):
        if replay_id is None:
            return
        with self._lock, self._connect() as connection:
            rows = connection.execute("SELECT id, record_json FROM detections").fetchall()
            remove = [row["id"] for row in rows if json.loads(row["record_json"]).get("replay_session_id") == replay_id]
            connection.executemany("DELETE FROM detections WHERE id=?", ((item,) for item in remove))
