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
        _DIR_PRIV = load_private_key("/home/claude/webbotauth/agent")
    return _DIR_PRIV


def refresh_known_keys():
    global KNOWN_KEYS
    KNOWN_KEYS = load_registry()


def _parse_sig_input(sig_input: str) -> dict:
    _, params = sig_input.split("=", 1)
    parts = params.split(";")
    fields = {"covered": parts[0]}
    for p in parts[1:]:
        k, v = p.split("=", 1)
        fields[k] = v.strip('"')
    return fields


def verify_request(headers: dict, authority: str, now: int) -> tuple:
    """Returns (verified: bool, reason: str, sig_fields: dict)."""
    sig_input = headers.get("Signature-Input")
    signature = headers.get("Signature")
    if not sig_input or not signature:
        return False, "unsigned", {}

    fields = _parse_sig_input(sig_input)
    keyid = fields.get("keyid")
    created = int(fields.get("created", 0))
    expires = int(fields.get("expires", 0))

    sig_b64 = signature.split(":")[1]

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

    sig_bytes = b64url_decode(sig_b64)

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
        authority = headers.get("Host", "")
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
    analytics.init_db()
    refresh_known_keys()
    print(f"verifier+harvester listening on http://localhost:{port}")
    print(f"  directory:   http://localhost:{port}{DIRECTORY_PATH}")
    print(f"  gated route: http://localhost:{port}/whoami")
    print(f"  known agents in registry: {len(KNOWN_KEYS)}")
    HTTPServer(("localhost", port), Handler).serve_forever()


if __name__ == "__main__":
    run()