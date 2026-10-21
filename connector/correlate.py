"""
Correlation capture + reconciliation (co-agency via a third-party anchor).

Two isolated agents never coordinate, but when both interact with the same
third-party service that service may reuse one identifier across both
exchanges (a transaction id, a webhook correlation hash, a request-bound
response). If each agent's connector stamps that identifier onto its
sighting, an observer can *join* the two otherwise-unrelated streams on the
shared value -- this is a correlation-id join (as in distributed tracing),
not coordination the developers wrote.

Trust discipline (the point): a shared id value that only the agents wrote
is a *claim* -- anyone who saw the id could stamp it. So each correlation
row carries whether the exchange was signed by a trusted third-party anchor
(`attested`). A join is only safe to act on automatically when some row for
that id is attested; the mere shared value is a candidate link, nothing more.

Lives in a side table in the same DB (schema untouched), like ingest_seen.
"""
from __future__ import annotations

import sqlite3

from . import store

CORRELATIONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS correlations (
    fingerprint TEXT PRIMARY KEY,   -- one row per sighting; dedups re-ingest
    corr_id TEXT NOT NULL,
    keyid TEXT,                     -- signer of this exchange (agent or anchor)
    verified INTEGER NOT NULL,
    attested INTEGER NOT NULL,      -- verified AND signed by a trusted anchor
    authority TEXT,
    path TEXT,
    ts REAL,
    source TEXT
);
CREATE INDEX IF NOT EXISTS idx_corr_id ON correlations(corr_id);
"""


def record(c: sqlite3.Connection, fingerprint: str, corr_id: str, row: dict,
           trusted_signers: set | None) -> None:
    """Write one correlation row for a sighting that carried a correlation id.
    Called on the writer's side connection, inside the same ingest pass."""
    trusted_signers = trusted_signers or set()
    keyid = row.get("keyid")
    verified = 1 if row.get("verified") else 0
    attested = 1 if (row.get("verified") and keyid and keyid in trusted_signers) else 0
    c.execute(
        """INSERT OR IGNORE INTO correlations
           (fingerprint, corr_id, keyid, verified, attested, authority, path, ts, source)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (fingerprint, corr_id, keyid, verified, attested,
         row.get("authority"), row.get("path"), row.get("ts"), row.get("_source")),
    )


def _rows_for(c, corr_id):
    return c.execute(
        "SELECT corr_id, keyid, verified, attested, authority, path, ts, source "
        "FROM correlations WHERE corr_id = ? ORDER BY ts", (corr_id,)
    ).fetchall()


def reconcile(corr_id: str, db_path: str | None = None) -> dict:
    """
    Everything sharing one correlation id, grouped by participant (keyid).
    `attested` is true only if some row for this id was signed by a trusted
    anchor -- i.e. the join is vouched for, not merely observed.
    """
    store.set_db_path(db_path)
    store.init_db()
    c = sqlite3.connect(store.db_path())
    try:
        c.executescript(CORRELATIONS_SCHEMA)
        rows = _rows_for(c, corr_id)
    finally:
        c.close()

    parts = {}
    attested_by = set()
    for (_cid, keyid, verified, attested, authority, path, ts, source) in rows:
        key = keyid or "(unsigned)"
        p = parts.setdefault(key, {"keyid": keyid, "authorities": set(), "paths": set(),
                                   "first_seen": ts, "last_seen": ts, "verified": False,
                                   "attested": False, "rows": 0})
        p["rows"] += 1
        if authority:
            p["authorities"].add(authority)
        if path:
            p["paths"].add(path)
        if ts is not None:
            p["first_seen"] = ts if p["first_seen"] is None else min(p["first_seen"], ts)
            p["last_seen"] = ts if p["last_seen"] is None else max(p["last_seen"], ts)
        p["verified"] = p["verified"] or bool(verified)
        if attested:
            p["attested"] = True
            if keyid:
                attested_by.add(keyid)

    participants = []
    for p in parts.values():
        participants.append({**p, "authorities": sorted(p["authorities"]),
                             "paths": sorted(p["paths"])})
    participants.sort(key=lambda x: x["rows"], reverse=True)
    return {
        "corr_id": corr_id,
        "rows": len(rows),
        "participant_count": len(parts),
        "co_agency": len(parts) > 1,
        "attested": len(attested_by) > 0,
        "attested_by": sorted(attested_by),
        "participants": participants,
    }


def list_correlations(db_path: str | None = None, min_participants: int = 1,
                      attested_only: bool = False) -> list[dict]:
    """
    One summary per correlation id. min_participants=2 surfaces only the
    co-agency cases (an id seen by more than one participant).
    """
    store.set_db_path(db_path)
    store.init_db()
    c = sqlite3.connect(store.db_path())
    try:
        c.executescript(CORRELATIONS_SCHEMA)
        rows = c.execute(
            """SELECT corr_id,
                      COUNT(*) AS n_rows,
                      COUNT(DISTINCT keyid) AS n_participants,
                      MAX(attested) AS any_attested
               FROM correlations
               GROUP BY corr_id
               ORDER BY n_participants DESC, n_rows DESC"""
        ).fetchall()
    finally:
        c.close()
    out = []
    for corr_id, n_rows, n_participants, any_attested in rows:
        if n_participants < min_participants:
            continue
        if attested_only and not any_attested:
            continue
        out.append({"corr_id": corr_id, "rows": n_rows,
                    "participant_count": n_participants,
                    "co_agency": n_participants > 1,
                    "attested": bool(any_attested)})
    return out
