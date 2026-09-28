"""
Tests for the signing/verification protocol itself (signer.py +
verifier.verify_request). These run against verify_request() directly,
no HTTP server involved -- we're testing the crypto/logic, not the
transport.
"""
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from signer import sign_request
import verifier
from conftest import make_agent


def test_valid_signature_verifies(clean_verifier_state):
    """Baseline: a freshly signed request from a registered agent passes."""
    name, priv, pub = make_agent("alice")
    verifier.refresh_known_keys()

    headers = sign_request(priv, "GET", "http://example.test/whoami",
                            signature_agent="http://example.test/alice")
    ok, reason, fields = verifier.verify_request(headers, "example.test", int(time.time()))

    assert ok is True
    assert reason == "verified"
    assert fields["tag"] == "web-bot-auth"


def test_unsigned_request_is_not_verified(clean_verifier_state):
    """No Signature-Input/Signature headers at all -> 'unsigned', not an error."""
    ok, reason, fields = verifier.verify_request({}, "example.test", int(time.time()))
    assert ok is False
    assert reason == "unsigned"
    assert fields == {}


def test_unknown_key_is_rejected(clean_verifier_state):
    """
    A signature that's structurally valid but signed by a key never
    registered anywhere -- e.g. an agent that never published its
    directory, or a forged keyid. Must fail closed.
    """
    name, priv, pub = make_agent("bob")
    # deliberately do NOT refresh_known_keys() -- simulates the registry
    # not having this agent on file yet
    headers = sign_request(priv, "GET", "http://example.test/whoami",
                            signature_agent="http://example.test/bob")
    ok, reason, fields = verifier.verify_request(headers, "example.test", int(time.time()))
    assert ok is False
    assert "unknown keyid" in reason


def test_expired_signature_is_rejected(clean_verifier_state):
    """A signature whose 'expires' timestamp is already in the past fails,
    even if the cryptographic signature itself is perfectly valid."""
    name, priv, pub = make_agent("carol")
    verifier.refresh_known_keys()

    headers = sign_request(priv, "GET", "http://example.test/whoami",
                            signature_agent="http://example.test/carol")
    # verify as if 5 minutes have passed since signing (well past the 60s window)
    future = int(time.time()) + 300
    ok, reason, fields = verifier.verify_request(headers, "example.test", future)
    assert ok is False
    assert reason == "signature expired"


def test_tampered_signature_is_rejected(clean_verifier_state):
    """Flipping a bit in the signature must not verify against the
    original message -- sanity check that we're not accidentally
    accepting anything that merely LOOKS like a signature."""
    name, priv, pub = make_agent("dave")
    verifier.refresh_known_keys()

    headers = sign_request(priv, "GET", "http://example.test/whoami",
                            signature_agent="http://example.test/dave")
    sig_prefix, sig_b64 = headers["Signature"].split(":", 1)
    corrupted = "A" + sig_b64[1:] if sig_b64[0] != "A" else "B" + sig_b64[1:]
    headers["Signature"] = f"{sig_prefix}:{corrupted}"

    ok, reason, fields = verifier.verify_request(headers, "example.test", int(time.time()))
    assert ok is False
    assert reason == "invalid signature"


def test_genuine_replay_is_rejected(clean_verifier_state):
    """The exact same signed request, sent twice, is a real replay:
    second presentation must fail."""
    name, priv, pub = make_agent("eve")
    verifier.refresh_known_keys()

    headers = sign_request(priv, "GET", "http://example.test/whoami",
                            signature_agent="http://example.test/eve")
    now = int(time.time())

    ok1, reason1, _ = verifier.verify_request(headers, "example.test", now)
    ok2, reason2, _ = verifier.verify_request(headers, "example.test", now)  # same headers again

    assert ok1 is True
    assert ok2 is False
    assert "replay" in reason2


def test_two_legitimate_signings_in_same_second_are_not_confused_for_replay(clean_verifier_state):
    """
    Regression test for the exact bug the demo surfaced: signing only
    @authority means the signed message is IDENTICAL for two different
    requests issued in the same wall-clock second, unless something else
    makes each signing unique. signer.py adds a per-signing nonce for
    this reason -- this test locks that behavior in so a future change
    can't silently reintroduce the false-positive replay flag.
    """
    name, priv, pub = make_agent("frank")
    verifier.refresh_known_keys()
    now = int(time.time())

    headers_1 = sign_request(priv, "GET", "http://example.test/whoami",
                              signature_agent="http://example.test/frank")
    headers_2 = sign_request(priv, "GET", "http://example.test/products",
                              signature_agent="http://example.test/frank")

    # same agent, same second, two DIFFERENT signing operations
    assert headers_1["Signature"] != headers_2["Signature"], (
        "if these ever match, the nonce isn't doing its job and the "
        "collision bug from the original demo run is back"
    )

    ok1, reason1, _ = verifier.verify_request(headers_1, "example.test", now)
    ok2, reason2, _ = verifier.verify_request(headers_2, "example.test", now)
    assert ok1 is True and reason1 == "verified"
    assert ok2 is True and reason2 == "verified"