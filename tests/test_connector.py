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
    FieldMap, JsonRecordSource, CombinedLogSource, CloudflareSource, to_epoch,
)
from connector.writer import IngestWriter
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
