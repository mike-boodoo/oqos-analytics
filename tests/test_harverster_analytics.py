"""
Tests for analytics.py -- these check that the aggregates the earlier
data-moat argument leans on (unique_agents, per_agent_summary,
tag_distribution, verification_rate) actually count what they claim to,
under conditions we control exactly (we know the ground truth because
we constructed the sightings ourselves).
"""
import sys
sys.path.insert(0, "/home/claude/webbotauth")

import analytics


def _sighting(keyid, verified, tag="web-bot-auth", remote_addr="1.2.3.4", path="/whoami"):
    analytics.record_sighting(
        remote_addr=remote_addr, method="GET", path=path, authority="example.test",
        verified=verified, reason="verified" if verified else "unsigned",
        sig_fields={"keyid": keyid, "alg": "ed25519", "tag": tag} if keyid else {},
        signature_agent=f"http://example.test/{keyid}" if keyid else None,
        user_agent="test-agent/1.0",
    )


def test_unique_agents_counts_distinct_keyids_only(isolated_store):
    _sighting("alice", True)
    _sighting("alice", True)   # same agent again -> still 1 unique
    _sighting("bob", True)
    _sighting(None, False)      # unsigned -> not attributable, not counted here

    assert analytics.unique_agents() == 2
    assert analytics.total_sightings() == 4
    assert analytics.unsigned_count() == 1


def test_verification_rate_matches_known_ground_truth(isolated_store):
    for _ in range(7):
        _sighting("alice", True)
    for _ in range(3):
        _sighting("alice", False, tag=None)

    rate = analytics.verification_rate()
    assert rate == 0.7  # 7 verified out of 10 total, by construction


def test_per_agent_summary_reports_correct_counts_per_agent(isolated_store):
    _sighting("alice", True, path="/whoami")
    _sighting("alice", True, path="/products")
    _sighting("alice", False, path="/whoami")
    _sighting("bob", True, path="/whoami")

    summary = {row["keyid"]: row for row in analytics.per_agent_summary()}

    assert summary["alice"]["n_requests"] == 3
    assert summary["alice"]["n_verified"] == 2
    assert summary["bob"]["n_requests"] == 1
    assert summary["bob"]["n_verified"] == 1


def test_tag_distribution_buckets_unsigned_separately(isolated_store):
    _sighting("alice", True, tag="web-bot-auth")
    _sighting("bob", True, tag="web-bot-auth")
    _sighting(None, False, tag=None)
    _sighting(None, False, tag=None)

    dist = analytics.tag_distribution()
    assert dist["web-bot-auth"] == 2
    assert dist["(unsigned/none)"] == 2


def test_replay_attempts_counts_only_reason_starting_with_replay(isolated_store):
    analytics.record_sighting(
        remote_addr="1.2.3.4", method="GET", path="/whoami", authority="example.test",
        verified=False, reason="replay: signature already used",
        sig_fields={"keyid": "eve"},
    )
    analytics.record_sighting(
        remote_addr="1.2.3.4", method="GET", path="/whoami", authority="example.test",
        verified=False, reason="signature expired",
        sig_fields={"keyid": "eve"},
    )
    assert analytics.replay_attempts() == 1