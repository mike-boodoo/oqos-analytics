"""
Build/serve helper for the agent explorer.

The explorer page (agent-explorer.html) fetches `harvest.json` from its
own directory -- the connector's export-json output. This helper
regenerates that file from the harvest store and, with --serve, runs a
static server over the explorer directory so the fetch resolves (opening
the HTML over file:// blocks the fetch; the page then shows its embedded
fallback snapshot instead).

  # refresh explorer/harvest.json from the default harvest DB
  python explorer/build.py

  # use a specific DB and then serve the explorer at :8080
  python explorer/build.py --db data/harvest.db --serve --port 8080

Typical loop: ingest real logs with the connector, then run this.
  python -m connector ingest --source cloudflare --path cf-logpush.jsonl
  python explorer/build.py --serve
"""
from __future__ import annotations

import argparse
import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Make the repo root importable whether run as a script or a module.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from connector.export import write_export  # noqa: E402

EXPLORER_DIR = Path(__file__).resolve().parent
HARVEST_JSON = EXPLORER_DIR / "harvest.json"


def build(db_path: str | None) -> int:
    n = write_export(str(HARVEST_JSON), db_path=db_path)
    print(f"wrote {n} sightings -> {HARVEST_JSON}")
    return n


def serve(port: int):
    handler = partial(SimpleHTTPRequestHandler, directory=str(EXPLORER_DIR))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    url = f"http://127.0.0.1:{port}/agent-explorer.html"
    print(f"serving explorer at {url}  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping explorer server...")
    finally:
        httpd.server_close()


def main(argv=None):
    p = argparse.ArgumentParser(description="Build (and optionally serve) the agent explorer.")
    p.add_argument("--db", help="harvest DB path (default: analytics.DB_PATH)")
    p.add_argument("--serve", action="store_true", help="serve the explorer directory after building")
    p.add_argument("--port", type=int, default=8080, help="port for --serve (default 8080)")
    args = p.parse_args(argv)
    build(args.db)
    if args.serve:
        serve(args.port)


if __name__ == "__main__":
    main(sys.argv[1:])
