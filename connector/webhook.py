"""
Webhook receiver: a dependency-light HTTP endpoint that ingests pushed
batches of request-log records into the harvest store.

Point an edge/CDN/pipeline that can POST JSON at it (Logpush to an HTTP
destination, a log-shipper, your own forwarder). Each POST body may be a
JSON array, JSON-lines, or a single object; records are mapped through a
FieldMap, written idempotently (duplicate POSTs are de-duplicated by the
same fingerprint the rest of the connector uses), and the response is the
{read, inserted, skipped} summary.

  python -m connector serve-webhook --port 8900 --path /ingest \
      --token "$SHARED_SECRET" --map ts=time,remote_addr=ip,host=authority

Honest caveat unchanged: if the records carry an upstream verdict
(e.g. a `verified` field) it is recorded as-is (reason "verified
(<source>)"); the connector does not re-run ed25519 on pushed rows.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .sources import FieldMap, StreamSource, _iter_json
from .writer import IngestWriter


def ingest_body(raw: bytes, field_map: FieldMap, writer: IngestWriter,
                source_name: str = "webhook") -> dict:
    """Parse one POST body and ingest it. Returns {read, inserted, skipped}."""
    objs = list(_iter_json(raw.decode("utf-8")))
    src = StreamSource(objs, field_map=field_map)
    return writer.ingest(src, source_name=source_name)


def make_handler(field_map: FieldMap, token: str | None, writer: IngestWriter, path: str):
    class WebhookHandler(BaseHTTPRequestHandler):
        def _json(self, code: int, obj: dict):
            payload = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if self.path == "/health":
                self._json(200, {"status": "ok"})
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self):
            if self.path != path:
                self._json(404, {"error": "not found"})
                return
            if token and self.headers.get("Authorization") != f"Bearer {token}":
                self._json(401, {"error": "unauthorized"})
                return
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else b""
            try:
                result = ingest_body(body, field_map, writer)
            except Exception as e:  # malformed body -> 400, never crash the server
                self._json(400, {"error": f"bad request: {e}"})
                return
            self._json(200, result)

        def log_message(self, *args):
            pass  # quiet; analytics is the real log

    return WebhookHandler


def run_webhook(host: str = "127.0.0.1", port: int = 8900, *,
                field_map: FieldMap | None = None, token: str | None = None,
                db_path: str | None = None, path: str = "/ingest"):
    writer = IngestWriter(db_path=db_path)
    writer.init()
    fm = field_map or FieldMap(source="webhook")
    httpd = ThreadingHTTPServer((host, port), make_handler(fm, token, writer, path))
    print(f"webhook listening on http://{host}:{port}{path}  (POST JSON; Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping webhook...")
    finally:
        httpd.server_close()
