"""SQLite access: schema bootstrap and per-request connections.

The standard library driver is used directly; every statement elsewhere in the
package is parameterized, so no SQL is ever built from user input.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from maldetect import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name     TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_name      TEXT NOT NULL,
    source        TEXT NOT NULL CHECK (source IN ('manual', 'apk')),
    verdict       TEXT NOT NULL CHECK (verdict IN ('malicious', 'benign')),
    probability   REAL NOT NULL,
    risk_level    TEXT NOT NULL,
    threshold     REAL NOT NULL,
    model_name    TEXT NOT NULL,
    features      TEXT NOT NULL,
    contributions TEXT NOT NULL,
    apk           TEXT,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans(user_id, created_at DESC, id DESC);
"""

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def to_iso(moment: datetime) -> str:
    """Format a datetime as second-precision ISO-8601 UTC.

    The fixed-width format sorts lexicographically, which lets SQLite order and
    range-filter timestamps stored as plain text.
    """
    return moment.astimezone(timezone.utc).strftime(TIMESTAMP_FORMAT)


def utcnow_iso() -> str:
    return to_iso(datetime.now(timezone.utc))


def connect(path: Path | None = None) -> sqlite3.Connection:
    """Open a connection with row access by name and foreign keys enforced."""
    db_file = Path(path) if path is not None else config.db_path()
    db_file.parent.mkdir(parents=True, exist_ok=True)
    # A request's dependency and endpoint may run on different worker threads,
    # but never concurrently, so sharing the connection across them is safe.
    conn = sqlite3.connect(db_file, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(path: Path | None = None) -> None:
    """Create the schema if needed and switch the database to WAL mode."""
    with closing(connect(path)) as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
        conn.commit()


def get_db() -> Iterator[sqlite3.Connection]:
    """FastAPI dependency: one short-lived connection per request."""
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()
