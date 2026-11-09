"""Storage of used and revoked token identifiers.

Only random token ids and timestamps are stored, so a leak of this database
reveals nothing about the people who presented the tokens.
"""
from __future__ import annotations

import sqlite3
import threading


class TokenStore:
    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS used (token_id TEXT PRIMARY KEY, used_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS revoked (token_id TEXT PRIMARY KEY);
            """
        )

    def mark_used(self, token_id: str, now: int) -> bool:
        """Atomically mark a token as used. Returns False if it was used before."""
        with self._lock:
            try:
                self._db.execute("INSERT INTO used VALUES (?, ?)", (token_id, now))
                self._db.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def revoke(self, token_id: str) -> None:
        with self._lock:
            self._db.execute("INSERT OR IGNORE INTO revoked VALUES (?)", (token_id,))
            self._db.commit()

    def is_revoked(self, token_id: str) -> bool:
        cur = self._db.execute("SELECT 1 FROM revoked WHERE token_id = ?", (token_id,))
        return cur.fetchone() is not None

    def purge_used_before(self, timestamp: int) -> int:
        """Delete records of tokens that are expired anyway (data minimisation)."""
        with self._lock:
            cur = self._db.execute("DELETE FROM used WHERE used_at < ?", (timestamp,))
            self._db.commit()
            return cur.rowcount
