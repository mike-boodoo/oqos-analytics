"""
One test per exposure hypothesis surfaced while analysing this repo as a
Web Bot Auth (RFC 9421 HTTP Message Signatures) harvester.

Each hypothesis is written as an assertion of the *desired, hardened*
behaviour, so it fails against the unpatched code and passes once the
corresponding fix lands. The patches live in config.py, analytics.py,
verifier.py, signer.py and dashboard.py.

Grouping:
  - H4/H5/H6/H9 + XSS are concrete bugs in this demo -> the test asserts
    the fixed behaviour directly.
  - H1/H2/H3/H8 are properties of the protocol profile; the fix is a
    detection/attribution primitive, so the test asserts that primitive
    now exists and behaves honestly.
  - H7 + steering are agent-side; the fix is a mitigation knob on the
    signer, so the test asserts the knob exists and works.
"""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import analytics
import verifier
from signer import sign_request
from keys import generate_keypair, keyid_for, b64url
from conftest import make_agent


# --------------------------------------------------------------------------
# H1 -- a claimed identity is recorded before any trust exists, but must
# NOT be attributed to the agent until at least one request verifies.
# --------------------------------------------------------------------------
def test_H1_claimed_but_unverified_identity_is_logged_but_not_attributed(
    isolated_store, clean_verifier_state
):
    rogue, _ = generate_keypair()  # never registered anywhere
    headers = sign_request(rogue, "GET", "http://site.test/x",
                           signature_agent="http://rogue.example")
    ok, reason, fields = verifier.verify_request(headers, "site.test", int(time.time()))
    analytics.record_sighting(
        "9.9.9.9", "GET", "/x", "site.test", ok, reason, fields,
        headers.get("Signature-Agent"), "python-requests/2.x",
    )

    assert ok is False and "unknown keyid" in reason
    kid = fields["keyid"]
    # honestly logged as a *claim*...
    assert analytics.claimed_unverified_identities().get(kid) == 1
    # ...but never presented as a real agent.
    assert analytics.unique_agents() == 0
    assert all(row["keyid"] != kid for row in analytics.per_agent_summary())


# --------------------------------------------------------------------------
# H2 -- the same key signing for unrelated sites is trivially linkable;
# the harvester should be able to surface that reuse.
# --------------------------------------------------------------------------
def test_H2_cross_site_key_reuse_is_detectable(isolated_store):
    for site in ("shop.test", "bank.test", "health.test"):
        analytics.record_sighting(
            "1.1.1.1", "GET", "/", site, True, "verified",
            {"keyid": "alice"}, "http://alice.example", "alice-bot/1.0",
        )
    assert analytics.authorities_per_keyid()["alice"] == 3


# --------------------------------------------------------------------------
# H3 -- anyone can forge a victim's (public) keyid on an unverified
# request; those rows must never pollute the victim's attributed history.
# --------------------------------------------------------------------------
def test_H3_victim_keyid_cannot_be_framed_via_unverified_rows(isolated_store):
    victim = "VICTIM_PUBLIC_KEYID"
    for _ in range(3):
        analytics.record_sighting(
            "6.6.6.6", "GET", "/admin/export", "shop.test", False,
            "invalid signature", {"keyid": victim, "tag": "x"},
            "http://evil.example", "TotallyLegitBot",
        )
    assert analytics.unique_agents() == 0
    assert all(row["keyid"] != victim for row in analytics.per_agent_summary())
    # still visible as an unattributed claim, not silently dropped
    assert analytics.claimed_unverified_identities().get(victim) == 3


# --------------------------------------------------------------------------
# H4 -- malformed signature headers must not crash the verifier (which
# would skip logging in the real server). verify_request must fail soft.
# --------------------------------------------------------------------------
def test_H4_malformed_headers_fail_soft_and_do_not_raise(clean_verifier_state):
    bad_headers = [
        {"Signature-Input": "garbage", "Signature": "x"},
        {"Signature-Input": 'sig1=("@authority");keyid="k";created=abc;expires=1',
         "Signature": "sig1=:AA:"},
        {"Signature-Input": 'sig1=("@authority");keyid="k";created=1;expires=99999999999',
         "Signature": "nocolons"},
    ]
    now = int(time.time())
    for h in bad_headers:
        ok, reason, _ = verifier.verify_request(h, "x.test", now)  # must not raise
        assert ok is False
        assert "malformed" in reason or "lifetime" in reason


# --------------------------------------------------------------------------
# H5 -- the verifier must bound signature lifetime and reject
# future-dated signatures, not only already-expired ones.
# --------------------------------------------------------------------------
def test_H5_overlong_and_future_signatures_are_rejected(clean_verifier_state):
    _, priv, pub = make_agent("tris")
    verifier.refresh_known_keys()
    now = int(time.time())
    kid = keyid_for(pub)

    def craft(created, expires):
        si = (f'sig1=("@authority");alg="ed25519";keyid="{kid}";'
              f'created={created};expires={expires};nonce="n";tag="web-bot-auth"')
        base = (f'"@authority": shop.test\n'
                f'"@signature-params": {si.split("=", 1)[1]}').encode()
        return {"Signature-Input": si, "Signature": f"sig1=:{b64url(priv.sign(base))}:"}

    ok, reason, _ = verifier.verify_request(craft(now, now + 10 ** 7), "shop.test", now)
    assert ok is False and "lifetime" in reason

    ok, reason, _ = verifier.verify_request(
        craft(now + 10 ** 6, now + 10 ** 6 + 30), "shop.test", now)
    assert ok is False and "not yet valid" in reason


# --------------------------------------------------------------------------
# H6 -- the verifier must not derive its own authority from the
# client-supplied Host header, or a captured signature replays cross-site.
# --------------------------------------------------------------------------
def test_H6_verifier_does_not_trust_client_host(clean_verifier_state, monkeypatch):
    _, priv, _ = make_agent("mallory")
    verifier.refresh_known_keys()
    # agent, lured to the attacker's site, signs for the attacker authority
    headers = sign_request(priv, "GET", "http://attacker.test/x",
                           signature_agent="http://mallory.example")
    headers["Host"] = "attacker.test"  # attacker replays, spoofing Host

    monkeypatch.setattr(verifier, "EXPECTED_AUTHORITY", "realbank.test")
    authority = verifier.resolve_authority(headers)
    assert authority == "realbank.test"  # NOT the client-controlled Host

    ok, reason, _ = verifier.verify_request(headers, authority, int(time.time()))
    assert ok is False and reason == "invalid signature"


# --------------------------------------------------------------------------
# H7 -- a hard-coded 60s lifetime is a library fingerprint; the signer
# must let the lifetime be tuned (so it can be jittered/normalised).
# --------------------------------------------------------------------------
def test_H7_signature_lifetime_is_tunable(clean_verifier_state):
    priv, _ = generate_keypair()
    headers = sign_request(priv, "GET", "http://s.test/", signature_agent="http://x",
                           lifetime=30)
    fields = verifier._parse_sig_input(headers["Signature-Input"])
    assert int(fields["expires"]) - int(fields["created"]) == 30


# --------------------------------------------------------------------------
# H8 -- a one-operator fleet across many keyids/IPs is invisible to the
# IP-concentration check but visible by Signature-Agent.
# --------------------------------------------------------------------------
def test_H8_operator_fleet_detectable_by_signature_agent(isolated_store):
    for i in range(10):
        analytics.record_sighting(
            f"10.0.{i}.1", "GET", "/", "shop.test", True, "verified",
            {"keyid": f"fleet-{i}"}, "http://fleet-operator.example", "bot",
        )
    # IP view: looks like 10 unrelated agents, one each
    assert max(analytics.distinct_keyids_per_remote_addr().values()) == 1
    # operator view: one actor behind all 10
    assert analytics.distinct_keyids_per_signature_agent()["http://fleet-operator.example"] == 10


# --------------------------------------------------------------------------
# H9 -- unauthenticated directory fetches must not inflate the headline
# verification rate.
# --------------------------------------------------------------------------
def test_H9_directory_fetches_do_not_inflate_verification_rate(isolated_store):
    analytics.record_sighting("1.1.1.1", "GET", "/whoami", "s", True, "verified", {"keyid": "a"})
    analytics.record_sighting("1.1.1.1", "GET", "/whoami", "s", False, "unsigned", {})
    for _ in range(20):
        analytics.record_sighting(
            "5.5.5.5", "GET", verifier.DIRECTORY_PATH, "s", True, "directory fetch")
    # 1 verified out of 2 real authentication attempts; housekeeping excluded
    assert analytics.verification_rate() == 0.5


# --------------------------------------------------------------------------
# Steering -- an agent should be able to refuse to sign for an authority
# it was never configured to talk to (the redirect/link lure).
# --------------------------------------------------------------------------
def test_steering_signer_refuses_non_allowlisted_authority():
    priv, _ = generate_keypair()
    with pytest.raises(ValueError):
        sign_request(priv, "GET", "http://evil.test/x", signature_agent="http://x",
                     allowed_authorities={"shop.test"})
    headers = sign_request(priv, "GET", "http://shop.test/x", signature_agent="http://x",
                           allowed_authorities={"shop.test"})
    assert "Signature" in headers


# --------------------------------------------------------------------------
# XSS -- the dashboard must escape attacker-controlled fields (tag,
# paths) instead of injecting them raw via innerHTML.
# --------------------------------------------------------------------------
def test_xss_dashboard_escapes_user_controlled_fields():
    import dashboard
    page = dashboard.HTML_PAGE
    assert "function esc" in page or "const esc" in page
    for raw in ("${row.tags}", "${row.paths_hit}", "${tag}"):
        assert raw not in page, f"unescaped interpolation still present: {raw}"
    for safe in ("esc(row.tags)", "esc(row.paths_hit)", "esc(tag)"):
        assert safe in page, f"expected escaped interpolation missing: {safe}"
