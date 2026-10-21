"""
Export the harvest store as the JSON shape the agent explorer and the
dashboard consume: one object per sighting, `verified` as a bool. Shared
by the CLI (`export-json`), the MCP server (`export_snapshot`), and the
explorer build helper, so there is one definition of the wire format.
"""
from __future__ import annotations

import json

from . import store

EXPORT_COLUMNS = store.EXPORT_COLUMNS


def export_sightings(db_path: str | None = None, limit: int | None = None) -> list[dict]:
    store.set_db_path(db_path)
    return store.export_rows(limit=limit)


def write_export(path: str, db_path: str | None = None) -> int:
    rows = export_sightings(db_path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(rows, indent=2))
    return len(rows)
