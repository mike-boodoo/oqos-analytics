"""
Verifier + harvester. Every incoming request gets recorded as a
sighting regardless of outcome -- that's the harvestable surface:

  - always available: remote_addr, method, path, Host (authority), User-Agent
  - available only if the request is signed: keyid, alg, tag, created/
    expires timestamps, Signature-Agent (claimed directory origin)
  - derived: verified (bool) + reason (why, if it failed)

/whoami stays gated (403 unless verified) to demonstrate access control;
every other path is left open but still logged, to show that harvesting
doesn't require gating -- you learn about agents just by being visited.
"""
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature

from config import (
    AGENT_KEY_PATH,
    MAX_SIGNATURE_LIFETIME,
    CLOCK_SKEW,
    EXPECTED_AUTHORITY,
)
from keys import b64url_decode, load_private_key
from directory import build_directory_body, sign_directory, DIRECTORY_PATH
from registry import load_registry
import analytics

# Loaded lazily on first use, not at import time -- importing this
# module (e.g. to test verify_request()) should not require a signing
# key to already exist on disk. Only the directory-serving code path
# actually needs DIR_PRIV.
_DIR_PRIV = None
KNOWN_KEYS = {}  # keyid -> Ed25519PublicKey, refreshed from the registry
_seen_nonces = set()  # (keyid, sig_b64) -> replay guard


def _get_dir_priv():
    global _DIR_PRIV
    if _DIR_PRIV is None:
        _DIR_PRIV = load_private_key(str(AGENT_KEY_PATH))
    return _DIR_PRIV


def refresh_known_keys():
    global KNOWN_KEYS
    KNOWN_KEYS = load_registry()


def resolve_authority(headers: dict) -> str:
    """
    The authority this verifier checks signatures against. If a
    deployment pins EXPECTED_AUTHORITY, use it; otherwise fall back to
    the client-supplied Host header (legacy demo behaviour). Trusting
    Host lets a signature captured by site A be replayed to site B with
    a spoofed Host, so a real deployment should always pin it. See H6.
    """
    return EXPECTED_AUTHORITY or headers.get("Host", "")


def _parse_sig_input(sig_input: str):
    """Parse a Signature-Input value. Returns a dict, or None if the
    header is malformed -- callers must fail closed rather than crash,
    so that a hostile client can't dodge logging with a broken header
    (the real server records every parsed outcome). See H4."""
    try:
        _, params = sig_input.split("=", 1)
        parts = params.split(";")
        fields = {"covered": parts[0]}
        for p in parts[1:]:
            k, v = p.split("=", 1)
            fields[k] = v.strip('"')
        return fields
    except (ValueError, AttributeError):
        return None


def _extract_sig(signature: str):
    """Pull the base64url body out of a `sig1=:<b64>:` Signature header.
    Returns None on a malformed header instead of raising. See H4."""
    try:
        parts = signature.split(":")
        if len(parts) < 2 or not parts[1]:
            return None
        return parts[1]
    except AttributeError:
        return None


def verify_request(headers: dict, authority: str, now: int,
                   max_lifetime: int = None, clock_skew: int = None) -> tuple:
    """Returns (verified: bool, reason: str, sig_fields: dict).

    Fails soft on every malformed input (never raises), so the caller
    always has an outcome to log. Enforces a lifetime policy and rejects
    future-dated signatures, not just already-expired ones."""
    max_lifetime = MAX_SIGNATURE_LIFETIME if max_lifetime is None else max_lifetime
    clock_skew = CLOCK_SKEW if clock_skew is None else clock_skew

    sig_input = headers.get("Signature-Input")
    signature = headers.get("Signature")
    if not sig_input or not signature:
        return False, "unsigned", {}

    fields = _parse_sig_input(sig_input)
    if fields is None:
        return False, "malformed Signature-Input", {}

    keyid = fields.get("keyid")
    try:
        created = int(fields["created"])
        expires = int(fields["expires"])
    except (KeyError, ValueError, TypeError):
        return False, "malformed signature timestamps", fields

    sig_b64 = _extract_sig(signature)
    if sig_b64 is None:
        return False, "malformed Signature header", fields

    # Lifetime policy -- enforced BEFORE the crypto check so an
    # attacker-chosen, decades-long or future-dated window is rejected
    # even when the signature itself is cryptographically valid. See H5.
    if created > now + clock_skew:
        return False, "signature not yet valid", fields
    if expires - created > max_lifetime:
        return False, "signature lifetime exceeds policy", fields
    if now > expires:
        return False, "signature expired", fields
    # Replay key is the actual signature value. Because @authority-only
    # signing (see signer.py) makes two identical-second requests collide
    # without a nonce, the signer embeds one -- so distinct legitimate
    # signings are distinct here, and only a genuine resend of the same
    # signed bytes trips this.
    if (keyid, sig_b64) in _seen_nonces:
        return False, "replay: signature already used", fields
    if keyid not in KNOWN_KEYS:
        return False, "unknown keyid (not in registry)", fields

    try:
        sig_bytes = b64url_decode(sig_b64)
    except Exception:
        return False, "malformed signature encoding", fields

    signature_base = (
        f'"@authority": {authority}\n'
        f'"@signature-params": {sig_input.split("=", 1)[1]}'
    ).encode()

    try:
        KNOWN_KEYS[keyid].verify(sig_bytes, signature_base)
    except InvalidSignature:
        return False, "invalid signature", fields

    _seen_nonces.add((keyid, sig_b64))
    return True, "verified", fields


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # quiet; analytics.py is the real log now

    def do_GET(self):
        path = urlparse(self.path).path
        headers = dict(self.headers)
        authority = resolve_authority(headers)
        now = int(time.time())

        if path == DIRECTORY_PATH:
            body = build_directory_body([_get_dir_priv().public_key()])
            resp_headers = sign_directory(_get_dir_priv(), body)
            self.send_response(200)
            for k, v in resp_headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
            analytics.record_sighting(
                remote_addr=self.client_address[0], method="GET", path=path,
                authority=authority, verified=True, reason="directory fetch",
                signature_agent=headers.get("Signature-Agent"),
                user_agent=headers.get("User-Agent"),
            )
            return

        verified, reason, fields = verify_request(headers, authority, now)

        analytics.record_sighting(
            remote_addr=self.client_address[0],
            method="GET",
            path=path,
            authority=authority,
            verified=verified,
            reason=reason,
            sig_fields=fields,
            signature_agent=headers.get("Signature-Agent"),
            user_agent=headers.get("User-Agent"),
        )

        if path == "/whoami":
            if not verified:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(f"403 Forbidden: {reason}".encode())
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"200 OK: {reason} (keyid {fields.get('keyid', '')[:12]}...)".encode())
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"200 OK (unrestricted route, sighting logged)")


def run(port=8088):
    global EXPECTED_AUTHORITY
    analytics.init_db()
    refresh_known_keys()
    # Pin the authority to this server's own host:port unless the
    # deployment already configured one, so signatures are checked
    # against where the request actually landed rather than a
    # client-controlled Host header. See H6.
    if EXPECTED_AUTHORITY is None:
        EXPECTED_AUTHORITY = f"localhost:{port}"
    print(f"verifier+harvester listening on http://localhost:{port}")
    print(f"  pinned authority: {EXPECTED_AUTHORITY}")
    print(f"  directory:   http://localhost:{port}{DIRECTORY_PATH}")
    print(f"  gated route: http://localhost:{port}/whoami")
    print(f"  known agents in registry: {len(KNOWN_KEYS)}")
    HTTPServer(("localhost", port), Handler).serve_forever()


if __name__ == "__main__":
    run()