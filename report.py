"""
Prints a summary of everything harvested so far. Run any time after the
verifier has seen traffic: `python3 report.py`
"""
import time
import analytics


def _fmt_ts(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "-"


def main():
    analytics.init_db()

    print("=== Harvest report ===\n")
    print(f"Total sightings recorded : {analytics.total_sightings()}")
    print(f"Unique attributable agents: {analytics.unique_agents()}")
    print(f"Unsigned/unattributable requests: {analytics.unsigned_count()}")
    print(f"Overall verification rate: {analytics.verification_rate():.0%}")
    print(f"Replay attempts detected : {analytics.replay_attempts()}")

    print("\n--- Tag distribution (declared request purpose) ---")
    for tag, count in analytics.tag_distribution().items():
        print(f"  {tag:30s} {count}")

    print("\n--- Per-agent summary ---")
    for row in analytics.per_agent_summary():
        print(f"\nagent {row['keyid'][:16]}...")
        print(f"  requests       : {row['n_requests']} ({row['n_verified']} verified)")
        print(f"  first/last seen: {_fmt_ts(row['first_seen'])} -> {_fmt_ts(row['last_seen'])}")
        print(f"  tags used      : {row['tags']}")
        print(f"  paths hit      : {row['paths_hit']}")
        print(f"  signature-agent: {row['signature_agents']}")
        print(f"  user-agent     : {row['user_agents']}")


if __name__ == "__main__":
    main()