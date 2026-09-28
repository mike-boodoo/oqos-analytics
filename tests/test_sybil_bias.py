"""
The earlier argument named two weak links: Sybil inflation (identity is
free, so N can be gamed) and sample bias (only agents that choose to
sign show up individuated). These tests make both failures concrete:
each one demonstrates the vulnerability actually occurring against the
current code, so 'this is a risk' is backed by a reproducible case
rather than left as a paragraph of prose.
"""
import sys
sys.path.insert(0, "/home/claude/webbotauth")

import analytics
from keys import generate_keypair
from registry import register_agent


def test_sybil_inflation_is_currently_uncosted(isolated_store):
    """
    An attacker generates 50 ed25519 keypairs (near-zero cost) all from
    one source and signs one request with each. unique_agents() reports
    50 -- indistinguishable, by that metric alone, from 50 real distinct
    agents. This is the concrete version of 'identity is free': the test
    demonstrates the inflation succeeds today, it does not (yet) assert
    any defense, because none exists yet in verifier.py/analytics.py.
    """
    attacker_addr = "10.0.0.1"
    for i in range(50):
        priv, pub = generate_keypair()
        keyid = f"sybil-{i}"
        analytics.record_sighting(
            remote_addr=attacker_addr, method="GET", path="/whoami",
            authority="example.test", verified=True, reason="verified",
            sig_fields={"keyid": keyid, "tag": "web-bot-auth"},
        )

    # this is the vulnerability, stated as a passing assertion: naive N
    # counting is fooled by cheap keygen.
    assert analytics.unique_agents() == 50

    # but the concentration is fully visible if you look for it -- one
    # address behind all 50 identities. This is the building block a
    # real mitigation (rate-limit per address, require proof-of-work or
    # stake per new keyid, decay trust for low-diversity sources) would
    # be built on. The test asserts the SIGNAL exists, not that anything
    # currently acts on it.
    concentration = analytics.distinct_keyids_per_remote_addr()
    assert concentration[attacker_addr] == 50
    assert len(concentration) == 1, (
        "all 50 'agents' trace back to a single address -- a real "
        "population of 50 distinct agents would show up spread across "
        "many addresses instead"
    )


def test_naive_n_is_not_trustworthy_without_a_concentration_check(isolated_store):
    """
    Mixed scenario: 5 genuinely distinct agents (different addresses)
    plus one Sybil burst of 20 from a single address. unique_agents()
    reports 25 as if population had grown 5x, but the concentration
    check reveals 20 of those 25 are one actor -- this is the check that
    would need to run BEFORE trusting N in the confidence-curve math
    from test_confidence_curve.py, since that math assumes N independent
    observations, and a Sybil burst violates independence entirely.
    """
    for i in range(5):
        analytics.record_sighting(
            remote_addr=f"192.168.0.{i}", method="GET", path="/whoami",
            authority="example.test", verified=True, reason="verified",
            sig_fields={"keyid": f"real-agent-{i}", "tag": "web-bot-auth"},
        )
    for i in range(20):
        analytics.record_sighting(
            remote_addr="10.0.0.1", method="GET", path="/whoami",
            authority="example.test", verified=True, reason="verified",
            sig_fields={"keyid": f"sybil-{i}", "tag": "web-bot-auth"},
        )

    assert analytics.unique_agents() == 25  # naive count: looks like healthy growth

    concentration = analytics.distinct_keyids_per_remote_addr()
    worst_offender_addr, worst_offender_count = max(concentration.items(), key=lambda kv: kv[1])
    share_from_one_address = worst_offender_count / analytics.unique_agents()

    assert share_from_one_address == 20 / 25  # 80% of "population" is one address
    assert share_from_one_address > 0.5, (
        "more than half of the apparent population traces to a single "
        "address -- N=25 should NOT be fed into the confidence-curve math "
        "as if it were 25 independent samples"
    )


def test_sample_bias_from_self_selected_signing(isolated_store):
    """
    Ground truth: 100 agents attempt a task, and the TRUE success rate
    across all of them is 50%. But only agents that succeed bother to
    sign and report (a plausible real-world pattern -- failures often go
    unreported, or fail before ever completing a signed exchange).
    verification_rate(), computed only from what got recorded, will
    read far higher than the true 50% -- because the sample that shows
    up at all is not representative of the population it's implicitly
    being used to describe. This is survivorship bias, concretely.
    """
    true_successes = 50
    true_failures = 50

    # only successes get signed and recorded (the biased, realistic case)
    for i in range(true_successes):
        analytics.record_sighting(
            remote_addr=f"172.16.0.{i}", method="GET", path="/whoami",
            authority="example.test", verified=True, reason="verified",
            sig_fields={"keyid": f"agent-{i}", "tag": "web-bot-auth"},
        )
    # the 50 failures never show up as attributable sightings at all --
    # they simply don't appear in the store, which is the point: this
    # is not a --verified=False row, it's an ABSENT row.

    observed_rate = analytics.verification_rate()

    assert observed_rate == 1.0, (
        "with only successes recorded, the observed rate reads as a "
        "perfect 100%"
    )
    true_rate = true_successes / (true_successes + true_failures)
    assert observed_rate != true_rate and abs(observed_rate - true_rate) == 0.5, (
        "the gap between observed (1.0) and true (0.5) rate IS the bias "
        "-- no query against this schema alone can recover the true rate "
        "once non-signing failures go unrecorded; that has to be fixed "
        "upstream (e.g. logging failed attempts too, not just successes), "
        "not queried around after the fact"
    )