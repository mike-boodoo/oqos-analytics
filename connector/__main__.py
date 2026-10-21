"""
CLI for the ingest connector.

  python -m connector ingest --source access-log   --path access.log
  python -m connector ingest --source cloudflare    --path cf-logpush.json
  python -m connector ingest --source cloudflare    --url https://… --token $CF_TOKEN
  python -m connector ingest --source generic        --path feed.jsonl \
         --map ts=time,remote_addr=ip,host=authority,signature_input=sig_input
  python -m connector status
  python -m connector export-json --out snapshot.json

Use --db to point at a specific harvest DB (defaults to analytics.DB_PATH,
the same file the verifier and dashboard use).
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import fields as _dc_fields

import analytics
from .export import export_sightings, write_export
from .sources import FieldMap, JsonRecordSource, CombinedLogSource, CloudflareSource
from .writer import IngestWriter


def _apply_db(db):
    if db:
        analytics.DB_PATH = db


def _field_map_from_arg(arg: str | None, base: FieldMap) -> FieldMap:
    """Override FieldMap entries from 'key=value,key=value'."""
    if not arg:
        return base
    valid = {f.name for f in _dc_fields(FieldMap)}
    for pair in arg.split(","):
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        k, v = k.strip(), v.strip()
        if k in valid:
            setattr(base, k, v)
    return base


def _build_source(args):
    if args.source == "access-log":
        if args.path and args.path.endswith((".json", ".jsonl", ".ndjson")):
            return JsonRecordSource(path=args.path, field_map=FieldMap.nginx_json())
        return CombinedLogSource(path=args.path, authority=args.authority)
    if args.source == "cloudflare":
        return CloudflareSource(path=args.path, url=args.url, token=args.token)
    if args.source == "generic":
        fm = _field_map_from_arg(args.map, FieldMap(source="generic"))
        return JsonRecordSource(path=args.path, field_map=fm)
    raise SystemExit(f"unknown source: {args.source}")


def cmd_ingest(args):
    _apply_db(args.db)
    writer = IngestWriter(db_path=args.db)
    result = writer.ingest(_build_source(args), source_name=args.source)
    print(json.dumps({"source": args.source, **result}, indent=2))


def cmd_status(args):
    _apply_db(args.db)
    print(json.dumps(IngestWriter(db_path=args.db).status(), indent=2, default=str))


def cmd_export(args):
    """Dump sightings as the JSON the agent explorer / dashboard consume."""
    _apply_db(args.db)
    if args.out:
        n = write_export(args.out, db_path=args.db)
        print(f"wrote {n} sightings -> {args.out}")
    else:
        print(json.dumps(export_sightings(db_path=args.db), indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="connector", description="Ingest real request logs into the harvest store.")
    p.add_argument("--db", help="harvest DB path (default: analytics.DB_PATH)")
    sub = p.add_subparsers(dest="cmd", required=True)

    ing = sub.add_parser("ingest", help="ingest from a source")
    ing.add_argument("--source", required=True, choices=["access-log", "cloudflare", "generic"])
    ing.add_argument("--path", help="input file (JSON / JSON-lines / combined log)")
    ing.add_argument("--url", help="cloudflare: fetch newline-delimited JSON from this URL")
    ing.add_argument("--token", help="cloudflare: bearer token for --url")
    ing.add_argument("--authority", help="access-log: Host to attribute (combined logs omit it)")
    ing.add_argument("--map", help="generic: field overrides, e.g. ts=time,remote_addr=ip")
    ing.set_defaults(func=cmd_ingest)

    st = sub.add_parser("status", help="show ingest state")
    st.set_defaults(func=cmd_status)

    ex = sub.add_parser("export-json", help="dump sightings as explorer/dashboard JSON")
    ex.add_argument("--out", help="write here (default: stdout)")
    ex.set_defaults(func=cmd_export)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main(sys.argv[1:])
