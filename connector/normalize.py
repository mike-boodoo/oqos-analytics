"""
Normalize one raw log record into a `sightings` row.

The sightings schema (analytics.py) is the contract every source has to
meet. A source adapter produces a `RawRecord` -- the HTTP-level facts it
could pull from its logs -- and `normalize()` turns that into the exact
column set analytics.record_sighting() expects, parsing the signature
parameters out of the raw `Signature-Input` header with the SAME parser
the verifier uses, so the connector can never disagree with it.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# Parse signature params identically to live verification. sigparse reuses
# the verifier's own parser when oqos-analytics is present, else a vendored
# copy -- so this package is portable to a standalone repo.
from .sigparse import parse_sig_input as _parse_sig_input

CANON_COLUMNS = (
    "ts", "remote_addr", "method", "path", "authority", "verified", "reason",
    "keyid", "alg", "tag", "created", "expires", "signature_agent", "user_agent",
)


@dataclass
class RawRecord:
    """HTTP-level facts a source pulls from one log line."""
    ts: float
    remote_addr: str | None = None
    method: str = "GET"
    path: str = "/"
    authority: str | None = None          # Host / :authority
    user_agent: str | None = None
    signature_input: str | None = None     # raw Signature-Input header
    signature: str | None = None           # raw Signature header
    signature_agent: str | None = None     # raw Signature-Agent header
    # The upstream's verdict, when the source already decided one (a CDN).
    # None means "the source expressed no verdict" and we infer from the
    # presence of a signature instead.
    verified: bool | None = None
    reason: str | None = None
    source: str = "unknown"
    extra: dict = field(default_factory=dict)


def _to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _sig_body(signature: str | None) -> str | None:
    """The base64 body of a `sig1=:<b64>:` Signature header, else None."""
    if not signature:
        return None
    parts = str(signature).split(":")
    return parts[1] if len(parts) >= 2 and parts[1] else None


def fingerprint(row: dict) -> str:
    """
    Stable id for one sighting, so re-ingesting the same batch doesn't
    double-count. Built from the facts that make an event unique: source,
    time, address, the signed identity, and the signature bytes (falling
    back to method+path for unsigned rows).
    """
    sig = _sig_body(row.get("_signature")) or f"{row['method']}:{row['path']}"
    basis = "|".join(str(x) for x in (
        row.get("_source"), row["ts"], row.get("remote_addr"),
        row.get("keyid"), sig,
    ))
    return hashlib.sha256(basis.encode()).hexdigest()


def normalize(rec: RawRecord) -> dict:
    """
    RawRecord -> a dict of sightings columns plus a `fingerprint` key and
    a couple of leading-underscore helpers used only for dedup.

    Verdict logic:
      - source gave a verdict  -> trust it; reason names the source.
      - signature present, no verdict -> recorded as not-locally-verified
        ("signed (no upstream verdict)"), because we did not run the crypto.
      - no signature at all     -> "unsigned".
    """
    fields = _parse_sig_input(rec.signature_input) if rec.signature_input else None
    fields = fields or {}
    has_sig = bool(rec.signature_input)

    if rec.verified is None:
        verified = False
        reason = rec.reason or ("signed (no upstream verdict)" if has_sig else "unsigned")
    else:
        verified = bool(rec.verified)
        reason = rec.reason or (
            f"verified ({rec.source})" if verified else f"rejected ({rec.source})"
        )

    row = {
        "ts": float(rec.ts),
        "remote_addr": rec.remote_addr,
        "method": rec.method or "GET",
        "path": rec.path or "/",
        "authority": rec.authority,
        "verified": verified,
        "reason": reason,
        "keyid": fields.get("keyid"),
        "alg": fields.get("alg"),
        "tag": fields.get("tag"),
        "created": _to_int(fields.get("created")),
        "expires": _to_int(fields.get("expires")),
        "signature_agent": rec.signature_agent,
        "user_agent": rec.user_agent,
        # helpers for fingerprint(), stripped before DB insert
        "_signature": rec.signature,
        "_source": rec.source,
    }
    row["fingerprint"] = fingerprint(row)
    return row


def sig_fields_of(row: dict) -> dict:
    """The subset analytics.record_sighting() wants as `sig_fields`."""
    return {k: row[k] for k in ("keyid", "alg", "tag", "created", "expires")}
