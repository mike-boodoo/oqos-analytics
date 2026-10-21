"""
oqos-analytics ingest connector.

Turns real request logs from an external source (a CDN like Cloudflare,
raw web-server access logs, or any JSON feed) into rows in the same
`sightings` store the live verifier writes to -- so analytics.py,
dashboard.py and the agent explorer all work unchanged on real
field data instead of only on demo.py's local run.

Two layers:
  - a `Source` adapter fetches raw records (sources.py)
  - `normalize()` maps each record onto the sightings schema (normalize.py)
  - `IngestWriter` writes them idempotently (writer.py)

Delivered both as a CLI (`python -m connector ...`) and as a stdlib MCP
server (connector/mcp_server.py).

Honest caveat: when ingesting a CDN's logs you are recording the
*upstream's* verification verdict, not re-running the ed25519 check
yourself (logs rarely carry enough to re-verify). Those rows are marked
with a reason like "verified (cloudflare)" so they are never mistaken
for locally verified traffic -- the trust shift to an intermediary is
exactly hypotheses H1/H6.
"""
from .normalize import normalize, RawRecord, CANON_COLUMNS
from .sources import (
    Source,
    FieldMap,
    JsonRecordSource,
    CombinedLogSource,
    CloudflareSource,
)
from .writer import IngestWriter

__all__ = [
    "normalize", "RawRecord", "CANON_COLUMNS",
    "Source", "FieldMap", "JsonRecordSource", "CombinedLogSource",
    "CloudflareSource", "IngestWriter",
]
