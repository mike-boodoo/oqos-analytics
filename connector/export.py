"""
Export the harvest store as the JSON shape the agent explorer and the
dashboard consume: one object per sighting, `verified` as a bool. Shared
by the CLI (`export-json`), the MCP server (`export_snapshot`), and the
explorer build helper, so there is one definition of the wire format.
"""
from __future__ import annotations

import json
import sqlite3

import analytics

EXPORT_COLUMNS = (
    "ts", "remote_addr", "path", "authority", "verified", "reason",
    "keyid", "alg", "tag", "created", "expires", "signature_agent", "user_agent",
)


def export_sightings(db_path: str | None = None, limit: int | None = None) -> list[dict]:
    if db_path:
        analytics.DB_PATH = db_path
    analytics.init_db()
    c = sqlite3.connect(str(analytics.DB_PATH))
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


def write_export(path: str, db_path: str | None = None) -> int:
    rows = export_sightings(db_path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(rows, indent=2))
    return len(rows)
