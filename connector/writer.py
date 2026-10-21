"""
Idempotent writer: take normalized rows and record them in the same
`sightings` store analytics.py reads, skipping anything already ingested.

Dedup and cursors live in two small side tables in the same DB
(`ingest_seen`, `ingest_cursor`) so the sightings schema is untouched and
analytics.py keeps working as-is. The actual sighting insert goes through
analytics.record_sighting(), passing the log's own ts, so one code path
owns the schema.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from . import correlate, store
from .normalize import normalize, sig_fields_of
from .sources import Source

_SIDE_SCHEMA = """
CREATE TABLE IF NOT EXISTS ingest_seen (
    fingerprint TEXT PRIMARY KEY,
    source TEXT,
    ts REAL
);
CREATE TABLE IF NOT EXISTS ingest_cursor (
    source TEXT PRIMARY KEY,
    cursor TEXT,
    updated REAL
);
""" + correlate.CORRELATIONS_SCHEMA


class IngestWriter:
    def __init__(self, db_path: str | None = None, trusted_signers=None):
        # None -> resolve analytics.DB_PATH lazily at each call, so tests
        # that monkeypatch it (and the CLI's --db) are both honoured.
        self._db_path = db_path
        # keyids trusted as third-party anchors: a correlation id seen on an
        # exchange signed by one of these is marked 'attested' (see correlate).
        self.trusted_signers = set(trusted_signers or ())

    @property
    def db_path(self) -> str:
        return str(self._db_path if self._db_path is not None else store.db_path())

    def _side_conn(self) -> sqlite3.Connection:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(self.db_path)
        c.executescript(_SIDE_SCHEMA)
        return c

    def init(self):
        # ensure both the sightings schema and our side tables exist
        if self._db_path is not None:
            store.set_db_path(self.db_path)
        store.init_db()
        self._side_conn().close()

    def _seen(self, c, fp: str) -> bool:
        return c.execute(
            "SELECT 1 FROM ingest_seen WHERE fingerprint = ?", (fp,)
        ).fetchone() is not None

    def write_row(self, row: dict, c: sqlite3.Connection) -> bool:
        """Insert one normalized row unless its fingerprint was seen. Returns
        True if inserted, False if skipped as a duplicate."""
        fp = row["fingerprint"]
        if self._seen(c, fp):
            return False
        store.record_sighting(
            remote_addr=row["remote_addr"], method=row["method"], path=row["path"],
            authority=row["authority"], verified=row["verified"], reason=row["reason"],
            sig_fields=sig_fields_of(row), signature_agent=row["signature_agent"],
            user_agent=row["user_agent"], ts=row["ts"],
        )
        c.execute(
            "INSERT INTO ingest_seen (fingerprint, source, ts) VALUES (?,?,?)",
            (fp, row.get("_source"), row["ts"]),
        )
        if row.get("_correlation_id"):
            correlate.record(c, fp, row["_correlation_id"], row, self.trusted_signers)
        c.commit()
        return True

    def ingest(self, source: Source, source_name: str | None = None) -> dict:
        """Run a source to completion. Returns {read, inserted, skipped}."""
        self.init()
        if self._db_path is not None:
            store.set_db_path(self.db_path)
        read = inserted = skipped = 0
        latest_ts = None
        c = self._side_conn()
        try:
            for rec in source.records():
                read += 1
                row = normalize(rec)
                if self.write_row(row, c):
                    inserted += 1
                    latest_ts = row["ts"] if latest_ts is None else max(latest_ts, row["ts"])
                else:
                    skipped += 1
            if latest_ts is not None:
                name = source_name or getattr(getattr(source, "field_map", None), "source", "unknown")
                c.execute(
                    "INSERT INTO ingest_cursor (source, cursor, updated) VALUES (?,?,?) "
                    "ON CONFLICT(source) DO UPDATE SET cursor=excluded.cursor, updated=excluded.updated",
                    (name, str(latest_ts), time.time()),
                )
                c.commit()
        finally:
            c.close()
        return {"read": read, "inserted": inserted, "skipped": skipped}

    def status(self) -> dict:
        self.init()
        if self._db_path is not None:
            store.set_db_path(self.db_path)
        c = self._side_conn()
        try:
            cursors = {
                row[0]: {"cursor": row[1], "updated": row[2]}
                for row in c.execute("SELECT source, cursor, updated FROM ingest_cursor")
            }
            ingested = c.execute("SELECT COUNT(*) FROM ingest_seen").fetchone()[0]
        finally:
            c.close()
        return {
            "db_path": self.db_path,
            "ingested_rows": ingested,
            "total_sightings": store.total_sightings(),
            "attributable_agents": store.unique_agents(),
            "cursors": cursors,
        }
