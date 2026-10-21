"""
A minimal, dependency-light MCP server over stdio for the ingest
connector -- same core as the CLI, exposed as tools an MCP client (Claude)
can call. It speaks JSON-RPC 2.0 on stdin/stdout using only the standard
library, matching the repo's "no vendor, dependency-light" shape rather
than pulling in an SDK.

Tools:
  - ingest_logs(source, path?/url?/token?/authority?/field_map?, db?)
  - connector_status(db?)
  - preview_normalize(record)            -- normalize one raw record, no write
  - export_snapshot(limit?, db?)         -- sightings as explorer JSON

Run:  python -m connector.mcp_server
"""
from __future__ import annotations

import json
import sys

import analytics
from .export import export_sightings
from .normalize import normalize, RawRecord
from .sources import FieldMap, JsonRecordSource, CombinedLogSource, CloudflareSource
from .writer import IngestWriter

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "ingest_logs",
        "description": "Ingest request logs from a source (access-log, cloudflare, generic) "
                       "into the harvest store, idempotently. Returns {read, inserted, skipped}.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {"type": "string", "enum": ["access-log", "cloudflare", "generic"]},
                "path": {"type": "string", "description": "input file path"},
                "url": {"type": "string", "description": "cloudflare: NDJSON URL"},
                "token": {"type": "string", "description": "cloudflare: bearer token for url"},
                "authority": {"type": "string", "description": "access-log: Host to attribute"},
                "field_map": {"type": "object", "description": "generic: field overrides"},
                "db": {"type": "string", "description": "harvest DB path"},
            },
            "required": ["source"],
        },
    },
    {
        "name": "connector_status",
        "description": "Ingest state: DB path, rows ingested, total sightings, per-source cursors.",
        "inputSchema": {"type": "object", "properties": {"db": {"type": "string"}}},
    },
    {
        "name": "preview_normalize",
        "description": "Normalize one raw record (no write) to show the sightings row it becomes.",
        "inputSchema": {
            "type": "object",
            "properties": {"record": {"type": "object"}},
            "required": ["record"],
        },
    },
    {
        "name": "export_snapshot",
        "description": "Return recorded sightings as the JSON the agent explorer/dashboard consume.",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer"}, "db": {"type": "string"}},
        },
    },
]


def _apply_db(args):
    if args.get("db"):
        analytics.DB_PATH = args["db"]


def _tool_ingest(args):
    _apply_db(args)
    src = args["source"]
    if src == "access-log":
        path = args.get("path", "")
        source = (JsonRecordSource(path=path, field_map=FieldMap.nginx_json())
                  if path.endswith((".json", ".jsonl", ".ndjson"))
                  else CombinedLogSource(path=path, authority=args.get("authority")))
    elif src == "cloudflare":
        source = CloudflareSource(path=args.get("path"), url=args.get("url"), token=args.get("token"))
    elif src == "generic":
        fm = FieldMap(source="generic")
        for k, v in (args.get("field_map") or {}).items():
            if hasattr(fm, k):
                setattr(fm, k, v)
        source = JsonRecordSource(path=args.get("path"), field_map=fm)
    else:
        raise ValueError(f"unknown source: {src}")
    return {"source": src, **IngestWriter(db_path=args.get("db")).ingest(source, source_name=src)}


def _tool_status(args):
    _apply_db(args)
    return IngestWriter(db_path=args.get("db")).status()


def _tool_preview(args):
    rec = args["record"]
    raw = RawRecord(
        ts=rec.get("ts", 0), remote_addr=rec.get("remote_addr"),
        method=rec.get("method", "GET"), path=rec.get("path", "/"),
        authority=rec.get("authority"), user_agent=rec.get("user_agent"),
        signature_input=rec.get("signature_input"), signature=rec.get("signature"),
        signature_agent=rec.get("signature_agent"), verified=rec.get("verified"),
        reason=rec.get("reason"), source=rec.get("source", "preview"),
    )
    row = normalize(raw)
    return {k: v for k, v in row.items() if not k.startswith("_")}


def _tool_export(args):
    _apply_db(args)
    return {"sightings": export_sightings(db_path=args.get("db"), limit=args.get("limit"))}


HANDLERS = {
    "ingest_logs": _tool_ingest,
    "connector_status": _tool_status,
    "preview_normalize": _tool_preview,
    "export_snapshot": _tool_export,
}


def handle(req: dict) -> dict | None:
    """Dispatch one JSON-RPC request; return a response (None for a notification)."""
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        return _ok(rid, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "oqos-ingest", "version": "0.1.0"},
        })
    if method == "notifications/initialized" or rid is None:
        return None
    if method == "tools/list":
        return _ok(rid, {"tools": TOOLS})
    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        fn = HANDLERS.get(name)
        if fn is None:
            return _err(rid, -32601, f"unknown tool: {name}")
        try:
            result = fn(args)
        except Exception as e:  # tool errors are reported, not fatal
            return _ok(rid, {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True})
        return _ok(rid, {"content": [{"type": "text", "text": json.dumps(result, default=str, indent=2)}]})
    return _err(rid, -32601, f"unknown method: {method}")


def _ok(rid, result):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _err(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def serve(stdin=None, stdout=None):
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(req)
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()


if __name__ == "__main__":
    serve()
