"""
Source adapters: each yields RawRecord objects from one kind of log.

Three concrete sources cover the cases asked for:
  - JsonRecordSource  -- any JSON feed (JSON array, JSON-lines, or an
    in-memory list); a FieldMap says which keys hold which facts. This
    one backs both "raw access logs" (structured/JSON logging) and the
    "generic HTTP/webhook feed".
  - CombinedLogSource -- classic Apache/nginx "combined" text logs, for
    the basic HTTP facts. Combined logs don't carry request headers, so
    those rows come through unsigned -- which is itself the real-world
    point: you only capture signatures if your log format records them.
  - CloudflareSource  -- Cloudflare Logpush/Logs records (from a file, an
    HTTP(S) URL, or an in-memory list), pre-wired with a Cloudflare
    FieldMap and its verified-bot verdict.

Every adapter is just a mapping onto RawRecord; the normalizer and writer
don't care which one produced the record.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Iterator, Protocol

from .normalize import RawRecord


class Source(Protocol):
    def records(self) -> Iterator[RawRecord]: ...


# --------------------------------------------------------------------------
# timestamp coercion -- logs express time a dozen ways
# --------------------------------------------------------------------------
def to_epoch(v) -> float:
    """Best-effort: epoch seconds/millis/nanos, or an ISO-8601 string."""
    if v is None:
        return 0.0
    if isinstance(v, (int, float)):
        x = float(v)
        if x > 1e18:      # nanoseconds
            return x / 1e9
        if x > 1e14:      # microseconds
            return x / 1e6
        if x > 1e11:      # milliseconds
            return x / 1e3
        return x          # seconds
    s = str(v).strip()
    if s.isdigit():
        return to_epoch(int(s))
    try:
        iso = s.replace("Z", "+00:00")
        return datetime.fromisoformat(iso).timestamp()
    except ValueError:
        # Apache "10/Oct/2026:13:55:36 +0000"
        try:
            return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").timestamp()
        except ValueError:
            return 0.0


def _dig(obj: dict, dotted: str):
    """Fetch a possibly-nested key like 'RequestHeaders.signature-input'."""
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict):
            # headers are commonly lower-cased; try as-given then lower
            cur = cur.get(part, cur.get(part.lower()))
        else:
            return None
    return cur


# --------------------------------------------------------------------------
# field mapping for JSON feeds
# --------------------------------------------------------------------------
@dataclass
class FieldMap:
    """
    Which keys in a JSON record hold which facts. Values are dotted paths,
    so nested header maps work (e.g. "RequestHeaders.signature-input").
    """
    ts: str = "ts"
    remote_addr: str = "remote_addr"
    method: str = "method"
    path: str = "path"
    authority: str = "host"
    user_agent: str = "user_agent"
    signature_input: str = "signature_input"
    signature: str = "signature"
    signature_agent: str = "signature_agent"
    verified: str | None = None       # key holding an upstream bool verdict
    reason: str | None = None
    source: str = "json"

    def record(self, obj: dict) -> RawRecord:
        verdict = _dig(obj, self.verified) if self.verified else None
        if isinstance(verdict, str):
            verdict = verdict.strip().lower() in ("1", "true", "yes", "verified", "ok")
        return RawRecord(
            ts=to_epoch(_dig(obj, self.ts)),
            remote_addr=_dig(obj, self.remote_addr),
            method=_dig(obj, self.method) or "GET",
            path=_dig(obj, self.path) or "/",
            authority=_dig(obj, self.authority),
            user_agent=_dig(obj, self.user_agent),
            signature_input=_dig(obj, self.signature_input),
            signature=_dig(obj, self.signature),
            signature_agent=_dig(obj, self.signature_agent),
            verified=verdict,
            reason=_dig(obj, self.reason) if self.reason else None,
            source=self.source,
            extra=obj,
        )

    @staticmethod
    def nginx_json() -> "FieldMap":
        """A structured nginx/Apache JSON log that captured the headers."""
        return FieldMap(
            ts="time", remote_addr="remote_addr", method="method", path="uri",
            authority="host", user_agent="http_user_agent",
            signature_input="http_signature_input", signature="http_signature",
            signature_agent="http_signature_agent", source="access-log",
        )

    @staticmethod
    def cloudflare() -> "FieldMap":
        """
        Cloudflare HTTP-requests Logpush dataset. Exact field availability
        depends on the account's Logpush config; request headers must be
        added to the dataset for the signature fields to arrive. Override
        any path if your dataset differs.
        """
        return FieldMap(
            ts="EdgeStartTimestamp",
            remote_addr="ClientIP",
            method="ClientRequestMethod",
            path="ClientRequestPath",
            authority="ClientRequestHost",
            user_agent="ClientRequestUserAgent",
            signature_input="RequestHeaders.signature-input",
            signature="RequestHeaders.signature",
            signature_agent="RequestHeaders.signature-agent",
            verified="VerifiedBot",
            source="cloudflare",
        )


def _iter_json(data: str) -> Iterator[dict]:
    """Accept a JSON array, JSON-lines, or a single JSON object."""
    text = data.strip()
    if not text:
        return
    if text[0] == "[":
        for obj in json.loads(text):
            yield obj
        return
    # try one object, else treat as JSON-lines
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            yield from obj
        else:
            yield obj
        return
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if line:
                yield json.loads(line)


class JsonRecordSource:
    """Records from a JSON array / JSON-lines string, file path, or list."""

    def __init__(self, data: Iterable | str | None = None, *, path: str | None = None,
                 field_map: FieldMap | None = None):
        self.field_map = field_map or FieldMap()
        self._objs: Iterable[dict]
        if path is not None:
            with open(path, "r", encoding="utf-8") as f:
                self._objs = list(_iter_json(f.read()))
        elif isinstance(data, str):
            self._objs = list(_iter_json(data))
        else:
            self._objs = list(data or [])

    def records(self) -> Iterator[RawRecord]:
        for obj in self._objs:
            yield self.field_map.record(obj)


# --------------------------------------------------------------------------
# classic combined access log
# --------------------------------------------------------------------------
_COMBINED = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) \S+ '
    r'"[^"]*" "(?P<ua>[^"]*)"'
)


class CombinedLogSource:
    """
    Apache/nginx 'combined' text logs. These carry only basic HTTP facts
    (no request headers), so every row is unsigned -- the honest result:
    to harvest signatures your log format must be extended to record the
    Signature* headers (use JsonRecordSource for that).
    """

    def __init__(self, data: str | None = None, *, path: str | None = None,
                 authority: str | None = None):
        if path is not None:
            with open(path, "r", encoding="utf-8") as f:
                self._text = f.read()
        else:
            self._text = data or ""
        self._authority = authority

    def records(self) -> Iterator[RawRecord]:
        for line in self._text.splitlines():
            m = _COMBINED.match(line.strip())
            if not m:
                continue
            yield RawRecord(
                ts=to_epoch(m.group("time")),
                remote_addr=m.group("ip"),
                method=m.group("method"),
                path=m.group("path"),
                authority=self._authority,
                user_agent=m.group("ua") or None,
                source="access-log",
            )


# --------------------------------------------------------------------------
# Cloudflare
# --------------------------------------------------------------------------
class CloudflareSource:
    """
    Cloudflare Logpush/Logs records. Supply them one of three ways:
      - data=<list|json str>  : records you already have in hand
      - path=<file>           : a Logpush dump (JSON array or JSON-lines)
      - url=<https URL>        : fetch newline-delimited JSON (Logpush to an
                                 HTTP/R2 destination, or a presigned link);
                                 token -> 'Authorization: Bearer <token>'.
    For the GraphQL Analytics API, fetch into JSON yourself and feed it via
    data=/path= with FieldMap.cloudflare().
    """

    def __init__(self, data=None, *, path: str | None = None, url: str | None = None,
                 token: str | None = None, field_map: FieldMap | None = None):
        self.field_map = field_map or FieldMap.cloudflare()
        self._data = data
        self._path = path
        self._url = url
        self._token = token

    def _fetch_url(self) -> str:
        import requests  # local import: module import stays network-free
        headers = {"Authorization": f"Bearer {self._token}"} if self._token else {}
        resp = requests.get(self._url, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.text

    def records(self) -> Iterator[RawRecord]:
        if self._url is not None:
            objs = list(_iter_json(self._fetch_url()))
        elif self._path is not None:
            with open(self._path, "r", encoding="utf-8") as f:
                objs = list(_iter_json(f.read()))
        elif isinstance(self._data, str):
            objs = list(_iter_json(self._data))
        else:
            objs = list(self._data or [])
        for obj in objs:
            yield self.field_map.record(obj)


class StreamSource:
    """
    A streaming source: maps an *iterable of raw JSON dicts* through a
    FieldMap. The iterable can be a list, a generator, or a callable that
    returns one -- so a Kafka/Kinesis/Pub-Sub consumer poll loop, or a
    `tail -f` / `kafkacat` pipe decoded to dicts, is wired in by writing a
    short generator that yields records; this adapter maps them and the
    writer ingests them as they arrive.

        def poll():                       # your consumer
            while True:
                for msg in consumer.poll():
                    yield json.loads(msg.value)
        IngestWriter().ingest(StreamSource(poll, field_map=FieldMap.cloudflare()))

    Records are consumed lazily, so an unbounded stream ingests row by row
    rather than being buffered first.
    """

    def __init__(self, records_iterable, *, field_map: FieldMap | None = None):
        self.field_map = field_map or FieldMap(source="stream")
        self._it = records_iterable

    def records(self) -> Iterator[RawRecord]:
        src = self._it() if callable(self._it) else self._it
        for obj in src:
            if obj is None:
                continue
            yield self.field_map.record(obj)
