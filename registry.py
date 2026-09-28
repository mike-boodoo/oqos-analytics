"""
A registry is just a directory of published public keys — standing in
for "fetch each agent's own /.well-known directory" without needing
real network hosts for the demo. Swap load_registry() for actual HTTP
fetches per Signature-Agent origin to go from simulated to real.
"""
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from config import REGISTRY_DIR
from keys import b64url_decode, public_key_to_jwk

REGISTRY_DIR = str(REGISTRY_DIR)


def register_agent(name: str, public_key: Ed25519PublicKey):
    os.makedirs(REGISTRY_DIR, exist_ok=True)
    with open(f"{REGISTRY_DIR}/{name}.pub.json", "w") as f:
        json.dump(public_key_to_jwk(public_key), f, indent=2)


def load_registry() -> dict:
    """Returns {keyid: Ed25519PublicKey} for every registered agent."""
    keys = {}
    if not os.path.isdir(REGISTRY_DIR):
        return keys
    for fname in os.listdir(REGISTRY_DIR):
        if not fname.endswith(".pub.json"):
            continue
        with open(f"{REGISTRY_DIR}/{fname}") as f:
            jwk = json.load(f)
        raw = b64url_decode(jwk["x"])
        keys[jwk["kid"]] = Ed25519PublicKey.from_public_bytes(raw)
    return keys