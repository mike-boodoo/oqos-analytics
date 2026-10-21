"""
Tests for the ingest connector: normalization onto the sightings schema,
the three source adapters, idempotent writes, real-timestamp preservation,
and the stdlib MCP server's JSON-RPC surface.
"""
import io
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import analytics
from connector.normalize import normalize, RawRecord
from connector.sources import (
    FieldMap, JsonRecordSource, CombinedLogSource, CloudflareSource, StreamSource, to_epoch,
)
from connector.writer import IngestWriter
from connector.export import export_sightings
from connector.webhook import ingest_body, run_webhook
from connector import mcp_server


# ---- a real, signed Signature-Input (shape the verifier emits) -----------
SIG_INPUT = ('sig1=("@authority");alg="ed25519";keyid="REALKEYID_abc123";'
             'created=1792590051;expires=1792590111;nonce="n1";tag="web-bot-auth"')
SIG = "sig1=:QUJDRA:"


def test_normalize_signed_record_parses_sig_params():
    rec = RawRecord(ts=1792590051, remote_addr="203.0.113.5", path="/whoami",
                    authority="shop.example", user_agent="acme/1.0",
                    signature_input=SIG_INPUT, signature=SIG,
                    signature_agent="https://acme.example", verified=True,
                    source="cloudflare")
    row = normalize(rec)
    assert row["keyid"] == "REALKEYID_abc123"
    assert row["alg"] == "ed25519" and row["tag"] == "web-bot-auth"
    assert row["created"] == 1792590051 and row["expires"] == 1792590111
    assert row["verified"] is True
    assert row["reason"] == "verified (cloudflare)"  # upstream verdict named


def test_normalize_unsigned_and_malformed_are_safe():
    assert normalize(RawRecord(ts=1, path="/"))["reason"] == "unsigned"
    # malformed Signature-Input must not crash and yields no keyid
    bad = normalize(RawRecord(ts=1, signature_input="garbage", signature="x"))
    assert bad["keyid"] is None
    # signed but no upstream verdict -> recorded as not locally verified
    sd = normalize(RawRecord(ts=1, signature_input=SIG_INPUT, signature=SIG))
    assert sd["verified"] is False and "no upstream verdict" in sd["reason"]


def test_to_epoch_handles_many_formats():
    assert to_epoch(1792590051) == 1792590051.0
    assert to_epoch(1792590051000) == 1792590051.0            # millis
    assert to_epoch(1792590051000000000) == 1792590051.0      # nanos
    assert abs(to_epoch("2026-10-21T09:00:51Z") - 1792573251.0) < 1


def test_cloudflare_source_maps_nested_headers(isolated_store):
    records = [{
        "EdgeStartTimestamp": 1792590051000000000,
        "ClientIP": "198.51.100.9", "ClientRequestMethod": "GET",
        "ClientRequestPath": "/whoami", "ClientRequestHost": "shop.example",
        "ClientRequestUserAgent": "acme/1.0", "VerifiedBot": True,
        "RequestHeaders": {"signature-input": SIG_INPUT, "signature": SIG,
                           "signature-agent": "https://acme.example"},
    }]
    rows = [normalize(r) for r in CloudflareSource(data=records).records()]
    assert len(rows) == 1
    r = rows[0]
    assert r["keyid"] == "REALKEYID_abc123"
    assert r["authority"] == "shop.example"
    assert r["verified"] is True and r["remote_addr"] == "198.51.100.9"


def test_generic_json_source_with_field_overrides():
    data = json.dumps([{"time": "2026-10-21T09:00:51Z", "ip": "10.1.2.3",
                        "uri": "/x", "host": "h.example",
                        "sig_input": SIG_INPUT, "sig": SIG}])
    fm = FieldMap(ts="time", remote_addr="ip", path="uri", authority="host",
                  signature_input="sig_input", signature="sig", source="generic")
    rows = [normalize(r) for r in JsonRecordSource(data, field_map=fm).records()]
    assert rows[0]["keyid"] == "REALKEYID_abc123" and rows[0]["remote_addr"] == "10.1.2.3"


def test_combined_access_log_parses_basic_facts():
    line = ('203.0.113.7 - - [21/Oct/2026:09:00:51 +0000] '
            '"GET /products HTTP/1.1" 200 512 "-" "genericcrawler/1.0"')
    rows = [normalize(r) for r in CombinedLogSource(line, authority="shop.example").records()]
    assert len(rows) == 1
    assert rows[0]["path"] == "/products" and rows[0]["keyid"] is None
    assert rows[0]["reason"] == "unsigned"  # combined logs carry no headers


def test_ingest_is_idempotent_and_feeds_analytics(isolated_store):
    records = [{
        "EdgeStartTimestamp": 1792590051, "ClientIP": "198.51.100.9",
        "ClientRequestMethod": "GET", "ClientRequestPath": "/whoami",
        "ClientRequestHost": "shop.example", "ClientRequestUserAgent": "acme/1.0",
        "VerifiedBot": True,
        "RequestHeaders": {"signature-input": SIG_INPUT, "signature": SIG},
    }]
    w = IngestWriter()  # uses analytics.DB_PATH from isolated_store
    first = w.ingest(CloudflareSource(data=records), source_name="cloudflare")
    second = w.ingest(CloudflareSource(data=records), source_name="cloudflare")
    assert first == {"read": 1, "inserted": 1, "skipped": 0}
    assert second == {"read": 1, "inserted": 0, "skipped": 1}
    # the row reached the real analytics store, attributed because verified
    assert analytics.unique_agents() == 1
    assert analytics.total_sightings() == 1


def test_ingest_preserves_log_timestamp_not_ingest_time(isolated_store):
    old_ts = 1792590051.0
    records = [{"EdgeStartTimestamp": old_ts, "ClientIP": "1.1.1.1",
                "ClientRequestMethod": "GET", "ClientRequestPath": "/whoami",
                "ClientRequestHost": "shop.example", "VerifiedBot": True,
                "RequestHeaders": {"signature-input": SIG_INPUT, "signature": SIG}}]
    IngestWriter().ingest(CloudflareSource(data=records), source_name="cloudflare")
    import sqlite3
    c = sqlite3.connect(str(analytics.DB_PATH))
    stored = c.execute("SELECT ts FROM sightings").fetchone()[0]
    c.close()
    assert abs(stored - old_ts) < 1  # the event's own time, not time.time()


def test_export_sightings_shape_matches_explorer(isolated_store):
    records = [{"EdgeStartTimestamp": 1792590051, "ClientIP": "1.1.1.1",
                "ClientRequestMethod": "GET", "ClientRequestPath": "/whoami",
                "ClientRequestHost": "shop.example", "VerifiedBot": True,
                "RequestHeaders": {"signature-input": SIG_INPUT, "signature": SIG}}]
    IngestWriter().ingest(CloudflareSource(data=records), source_name="cloudflare")
    rows = export_sightings()
    assert len(rows) == 1
    r = rows[0]
    assert r["verified"] is True and isinstance(r["verified"], bool)
    assert r["keyid"] == "REALKEYID_abc123" and r["authority"] == "shop.example"
    # exactly the columns the explorer / dashboard read
    assert set(r) == {"ts", "remote_addr", "path", "authority", "verified", "reason",
                      "keyid", "alg", "tag", "created", "expires", "signature_agent", "user_agent"}


# ---- streaming + webhook -------------------------------------------------
def _generic_record(ts=1792590051):
    return {"ts": ts, "remote_addr": "203.0.113.5", "method": "GET", "path": "/whoami",
            "host": "shop.example", "user_agent": "acme/1.0",
            "signature_input": SIG_INPUT, "signature": SIG,
            "signature_agent": "https://acme.example", "verified": True}


def test_stream_source_from_generator_maps_records():
    def gen():
        yield _generic_record(1792590051)
        yield None                      # gaps in a stream are skipped
        yield _generic_record(1792590060)
    rows = [normalize(r) for r in StreamSource(gen(), field_map=FieldMap()).records()]
    assert len(rows) == 2 and all(r["keyid"] == "REALKEYID_abc123" for r in rows)


def test_stream_source_ingests_and_is_idempotent(isolated_store):
    batch = [_generic_record(1792590051), _generic_record(1792590060)]
    w = IngestWriter()
    fm = FieldMap(source="stream", verified="verified")  # map the verdict field
    first = w.ingest(StreamSource(list(batch), field_map=fm), source_name="stream")
    second = w.ingest(StreamSource(list(batch), field_map=fm), source_name="stream")
    assert first["inserted"] == 2 and second["inserted"] == 0 and second["skipped"] == 2
    assert analytics.unique_agents() == 1


def test_webhook_ingest_body_parses_array_and_ndjson(isolated_store):
    w = IngestWriter()
    fm = FieldMap(verified="verified")
    arr = json.dumps([_generic_record(1792590051), _generic_record(1792590060)]).encode()
    assert ingest_body(arr, fm, w, source_name="webhook")["inserted"] == 2
    ndjson = (json.dumps(_generic_record(1792590070)) + "\n").encode()
    assert ingest_body(ndjson, fm, w)["inserted"] == 1
    assert analytics.total_sightings() == 3


def test_webhook_server_round_trip_with_token(isolated_store):
    import threading, urllib.request, urllib.error
    from connector.webhook import make_handler
    from http.server import ThreadingHTTPServer
    db = str(analytics.DB_PATH)
    port = 8911
    w = IngestWriter(db_path=db); w.init()
    httpd = ThreadingHTTPServer(("127.0.0.1", port),
                                make_handler(FieldMap(source="webhook", verified="verified"), "s3cret", w, "/ingest"))
    t = threading.Thread(target=httpd.serve_forever, daemon=True); t.start()
    try:
        body = json.dumps([_generic_record(1792590051)]).encode()
        # missing token -> 401
        req = urllib.request.Request(f"http://127.0.0.1:{port}/ingest", data=body, method="POST")
        try:
            urllib.request.urlopen(req); assert False, "expected 401"
        except urllib.error.HTTPError as e:
            assert e.code == 401
        # with token -> 200 and one insert
        req = urllib.request.Request(f"http://127.0.0.1:{port}/ingest", data=body,
                                     method="POST", headers={"Authorization": "Bearer s3cret"})
        resp = json.loads(urllib.request.urlopen(req).read())
        assert resp["inserted"] == 1
    finally:
        httpd.shutdown(); httpd.server_close()
    assert analytics.unique_agents() == 1


# ---- MCP server surface --------------------------------------------------
def _rpc(obj, monkeypatch=None):
    out = io.StringIO()
    mcp_server.serve(stdin=io.StringIO(json.dumps(obj) + "\n"), stdout=out)
    out.seek(0)
    line = out.read().strip()
    return json.loads(line) if line else None


def test_mcp_initialize_and_list():
    init = _rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert init["result"]["serverInfo"]["name"] == "oqos-ingest"
    lst = _rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in lst["result"]["tools"]}
    assert {"ingest_logs", "connector_status", "preview_normalize", "export_snapshot"} <= names


def test_mcp_preview_normalize_tool():
    resp = _rpc({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                 "params": {"name": "preview_normalize",
                            "arguments": {"record": {"ts": 1792590051,
                                "signature_input": SIG_INPUT, "signature": SIG,
                                "verified": True, "source": "cloudflare"}}}})
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["keyid"] == "REALKEYID_abc123"
    assert "_signature" not in payload  # internal helpers stripped
