"""
Sign an outgoing HTTP request the way Web Bot Auth signs agent traffic:
sign the target @authority (domain) with the agent's private key, and
tell the verifier where to fetch the public key via Signature-Agent.

Note on scope: real Web Bot Auth deliberately covers only @authority --
the signature says "this keyholder is talking to this domain," not
"this keyholder sent this exact request." That's coarse by design (one
signature authorizes many requests until it expires), but it also means
two different requests signed in the same wall-clock second, with no
other distinguishing input, produce byte-identical signatures -- so a
legitimate second call and a replay of the first become indistinguishable.
We add an explicit per-signing nonce below purely so THIS DEMO can tell
"agent signed twice" apart from "attacker resent the same signature" --
real Web Bot Auth accepts that ambiguity and relies on short expiry instead.
"""
import os
import time
from urllib.parse import urlparse
from keys import keyid_for, b64url, load_private_key


def sign_request(private_key, method: str, url: str, signature_agent: str) -> dict:
    """
    Returns the headers to attach to an outgoing request.
    signature_agent: base URL where the verifier can fetch this agent's
    key directory, e.g. "https://your-agent.example"
    """
    authority = urlparse(url).netloc
    created = int(time.time())
    expires = created + 60
    keyid = keyid_for(private_key.public_key())
    nonce = b64url(os.urandom(12))

    sig_input = (
        f'sig1=("@authority");alg="ed25519";keyid="{keyid}";'
        f'created={created};expires={expires};'
        f'nonce="{nonce}";tag="web-bot-auth"'
    )
    # Signature base: the covered components string, then the value of
    # each covered component. Only @authority is covered (matching real
    # Web Bot Auth scope); the nonce inside @signature-params is what
    # makes each individual signing operation unique.
    signature_base = (
        f'"@authority": {authority}\n'
        f'"@signature-params": {sig_input.split("=", 1)[1]}'
    ).encode()

    sig = private_key.sign(signature_base)

    return {
        "Signature-Input": sig_input,
        "Signature": f"sig1=:{b64url(sig)}:",
        "Signature-Agent": signature_agent,
    }


if __name__ == "__main__":
    priv = load_private_key("/home/claude/webbotauth/agent")
    headers = sign_request(
        priv,
        method="GET",
        url="http://localhost:8088/whoami",
        signature_agent="http://localhost:8088",
    )
    for k, v in headers.items():
        print(f"{k}: {v}")