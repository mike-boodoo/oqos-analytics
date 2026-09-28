"""
Agent identity: one ed25519 keypair per agent.

This is the same primitive Cloudflare's Web Bot Auth relies on (RFC 9421
signatures, ed25519 keys) and the same one used for provenance signing —
generate once, keep the private key secret, publish the public key in a
signed key directory (see directory.py).
"""
import base64
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from config import AGENT_KEY_PATH


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def generate_keypair():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def keyid_for(public_key: Ed25519PublicKey) -> str:
    """Deterministic key ID: base64url of the raw public key bytes."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64url(raw)


def public_key_to_jwk(public_key: Ed25519PublicKey) -> dict:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64url(raw),
        "kid": keyid_for(public_key),
    }


def save_keypair(private_key: Ed25519PrivateKey, path_prefix: str):
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(f"{path_prefix}.priv", "wb") as f:
        f.write(priv_bytes)
    with open(f"{path_prefix}.pub.json", "w") as f:
        json.dump(public_key_to_jwk(private_key.public_key()), f, indent=2)


def load_private_key(path_prefix: str) -> Ed25519PrivateKey:
    with open(f"{path_prefix}.priv", "rb") as f:
        return Ed25519PrivateKey.from_private_bytes(f.read())


if __name__ == "__main__":
    priv, pub = generate_keypair()
    save_keypair(priv, str(AGENT_KEY_PATH))
    print(f"Generated agent keypair -> {AGENT_KEY_PATH}.priv / {AGENT_KEY_PATH}.pub.json")
    print(json.dumps(public_key_to_jwk(pub), indent=2))