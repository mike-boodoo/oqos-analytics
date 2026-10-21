"""
The connector's view of the harvest store, decoupled from oqos-analytics.

When this package runs inside the oqos-analytics repo, it reuses that
repo's `analytics` module, so there is one schema and one code path and
the connector writes to the very DB the verifier and dashboard read.

When it is vendored into a standalone repo (the OQOS connector) where
`analytics` is not importable, it falls back to an identical built-in
SQLite store. Either way the sightings schema and the aggregates are the
same, so downstream tools (export, explorer) are unaffected.

Config: with the host present, the DB path is analytics.DB_PATH;
standalone, it is $OQOS_DB_PATH (default ./harvest.db).
"""
from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

try:  # reuse the host repo's canonical store when available
    import analytics as _host
except Exception:  # standalone: no oqos-analytics on the path
    _host = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS sightings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    remote_addr TEXT,
    method TEXT,
    path TEXT,
    authority TEXT,
    verified INTEGER NOT NULL,
    reason TEXT,
    keyid TEXT,
    alg TEXT,
    tag TEXT,
    created INTEGER,
    expires INTEGER,
    signature_agent TEXT,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_keyid ON sightings(keyid);
CREATE INDEX IF NOT EXISTS idx_ts ON sightings(ts);
"""

_DB_PATH = os.environ.get("OQOS_DB_PATH", "harvest.db")

EXPORT_COLUMNS = (
    "ts", "remote_addr", "path", "authority", "verified", "reason",
    "keyid", "alg", "tag", "created", "expires", "signature_agent", "user_agent",
)

using_host = _host is not None


def db_path() -> str:
    return str(_host.DB_PATH) if _host is not None else _DB_PATH


def set_db_path(path: str | None):
    global _DB_PATH
    if path is None:
        return
    if _host is not None:
        _host.DB_PATH = path
    _DB_PATH = str(path)


@contextmanager
def _conn():
    p = db_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p)
    try:
        yield c
    finally:
        c.commit()
        c.close()


def init_db():
    if _host is not None:
        return _host.init_db()
    with _conn() as c:
        c.executescript(SCHEMA)


def record_sighting(remote_addr, method, path, authority, verified, reason,
                    sig_fields=None, signature_agent=None, user_agent=None, ts=None):
    if _host is not None:
        return _host.record_sighting(
            remote_addr=remote_addr, method=method, path=path, authority=authority,
            verified=verified, reason=reason, sig_fields=sig_fields,
            signature_agent=signature_agent, user_agent=user_agent, ts=ts)
    sig_fields = sig_fields or {}
    with _conn() as c:
        c.execute(
            """INSERT INTO sightings
               (ts, remote_addr, method, path, authority, verified, reason,
                keyid, alg, tag, created, expires, signature_agent, user_agent)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (time.time() if ts is None else ts, remote_addr, method, path, authority,
             int(verified), reason, sig_fields.get("keyid"), sig_fields.get("alg"),
             sig_fields.get("tag"), sig_fields.get("created"), sig_fields.get("expires"),
             signature_agent, user_agent),
        )


def total_sightings() -> int:
    if _host is not None:
        return _host.total_sightings()
    with _conn() as c:
        return c.execute("SELECT COUNT(*) FROM sightings").fetchone()[0]


def unique_agents() -> int:
    if _host is not None:
        return _host.unique_agents()
    with _conn() as c:
        return c.execute(
            "SELECT COUNT(DISTINCT keyid) FROM sightings WHERE verified = 1 "
            "AND keyid IS NOT NULL"
        ).fetchone()[0]


def export_rows(limit: int | None = None) -> list[dict]:
    init_db()
    c = sqlite3.connect(db_path())
    c.row_factory = sqlite3.Row
    q = f"SELECT {','.join(EXPORT_COLUMNS)} FROM sightings ORDER BY ts"
    if limit:
        q += f" LIMIT {int(limit)}"
    rows = []
    try:
        for r in c.execute(q):
            d = dict(r)
            d["verified"] = bool(d["verified"])
            rows.append(d)
    finally:
        c.close()
    return rows
