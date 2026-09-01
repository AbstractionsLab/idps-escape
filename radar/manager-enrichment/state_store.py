"""
Central, shared per-user state store.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections import deque
from pathlib import Path

DEFAULT_DB_PATH = "/var/ossec/etc/radar/user_state.sqlite3"

class UserState:
    __slots__ = ("last_ts", "last_lat", "last_lon", "last_country", "asn_hist", "asn_set")

    def __init__(self):
        self.last_ts = None
        self.last_lat = None
        self.last_lon = None
        self.last_country = None
        self.asn_hist = deque()   # deque of (asn: str, ts: int)
        self.asn_set = set()


class UserStateStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS user_state (
                            username     TEXT PRIMARY KEY,
                            last_ts      REAL,
                            last_lat     REAL,
                            last_lon     REAL,
                            last_country TEXT,
                            asn_history  TEXT NOT NULL DEFAULT '[]'
                        )
                        """
                    )
            finally:
                conn.close()
            self._ensure_group_writable()

    def _ensure_group_writable(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            path = self.db_path + suffix
            try:
                if os.path.exists(path):
                    os.chmod(path, 0o660)
            except OSError:
                pass

    def get(self, username: str) -> UserState:
        """Returns a fresh UserState() if the user has no record yet."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT last_ts, last_lat, last_lon, last_country, asn_history "
                    "FROM user_state WHERE username = ?",
                    (username,),
                ).fetchone()
            finally:
                conn.close()

        us = UserState()
        if row is None:
            return us

        last_ts, last_lat, last_lon, last_country, asn_history_json = row
        us.last_ts = last_ts
        us.last_lat = last_lat
        us.last_lon = last_lon
        us.last_country = last_country
        pairs = json.loads(asn_history_json) if asn_history_json else []
        us.asn_hist = deque((asn, ts) for asn, ts in pairs)
        us.asn_set = {asn for asn, _ in us.asn_hist}
        return us

    def save(self, username: str, us: UserState) -> None:
        asn_history_json = json.dumps(list(us.asn_hist))
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO user_state
                            (username, last_ts, last_lat, last_lon, last_country, asn_history)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(username) DO UPDATE SET
                            last_ts      = excluded.last_ts,
                            last_lat     = excluded.last_lat,
                            last_lon     = excluded.last_lon,
                            last_country = excluded.last_country,
                            asn_history  = excluded.asn_history
                        """,
                        (username, us.last_ts, us.last_lat, us.last_lon, us.last_country, asn_history_json),
                    )
            finally:
                conn.close()