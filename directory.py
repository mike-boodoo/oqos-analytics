"""
The bot directory: served at /.well-known/http-message-signatures-directory.

This is what a verifier fetches to get an agent's public key. In real
Web Bot Auth the directory response is itself signed; we do the same
here with a directory-signing key, kept separate from per-request keys.
"""
import json
import time
from keys import (
    generate_keypair,
    keyid_for,
    public_key_to_jwk,
    b64url,
    load_private_key,
)

DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
CONTENT_TYPE = "application/http-message-signatures-directory+json"


def build_directory_body(public_keys: list) -> bytes:
    body = {"keys": [public_key_to_jwk(pk) for pk in public_keys]}
    return json.dumps(body).encode()


def sign_directory(private_key, body: bytes) -> dict:
    """
    Produce Signature-Input / Signature headers for the directory
    response itself, tagged 'http-message-signatures-directory' per
    the draft spec, covering the @authority derived component.
    """
    created = int(time.time())
    expires = created + 300
    keyid = keyid_for(private_key.public_key())
    sig_input = (
        f'sig1=("@authority");alg="ed25519";keyid="{keyid}";'
        f'created={created};expires={expires};'
        f'tag="http-message-signatures-directory"'
    )
    signature_base = sig_input.encode() + b"\n" + body
    sig = private_key.sign(signature_base)
    return {
        "Content-Type": CONTENT_TYPE,
        "Signature-Input": sig_input,
        "Signature": f"sig1=:{b64url(sig)}:",
    }


if __name__ == "__main__":
    priv = load_private_key("/home/claude/webbotauth/agent")
    body = build_directory_body([priv.public_key()])
    headers = sign_directory(priv, body)
    print(headers["Content-Type"])
    print(headers["Signature-Input"])
    print(body.decode())