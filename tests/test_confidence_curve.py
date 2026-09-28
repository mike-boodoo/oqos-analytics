"""
Validates the actual quantitative claim from the data-moat argument:
that the uncertainty on a per-tag verification rate narrows as
sqrt(p(1-p)/N) -- i.e. that accumulating more agent sightings genuinely
buys you a tighter, more sellable estimate, and isn't just a story.

Method: for several sample sizes N, run many independent simulated
"harvests" of N sightings each from a KNOWN true success rate, measure
the empirical spread of the estimate across those harvests, and check
it against the closed-form standard error. This is a backtest of the
statistical claim, not just an assertion of it.

Performance note: analytics.record_sighting() commits once per call,
which is correct for real traffic (one request at a time) but far too
slow for a Monte Carlo test inserting hundreds of thousands of rows --
the first version of this test took >5 minutes and had to be rewritten
to bulk-insert directly against the same schema/table analytics.py
uses, committing once per simulated harvest instead of once per row.
"""
import math
import random
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import analytics


TRUE_P = 0.7           # ground-truth success rate we're simulating
N_TRIALS = 60          # independent simulated harvests per sample size
SAMPLE_SIZES = [50, 500, 5000]


def _bulk_simulate_harvest(db_path: str, n_sightings: int, true_p: float, seed: int) -> float:
    """
    Same table, same columns as analytics.py's schema -- just inserted
    in one transaction instead of one commit per row, purely for speed.
    Returns the observed verification_rate() read back through the real
    analytics.py query, so we're still testing the actual aggregate.
    """
    rng = random.Random(seed)
    analytics.DB_PATH = db_path
    analytics.init_db()

    rows = []
    now = 0.0
    for i in range(n_sightings):
        verified = rng.random() < true_p
        rows.append((
            now, "0.0.0.0", "GET", "/whoami", "sim.test", int(verified),
            "verified" if verified else "unsigned",
            f"agent-{i}" if verified else None,
            "ed25519" if verified else None,
            "web-bot-auth" if verified else None,
            None, None, None, None,
        ))

    conn = sqlite3.connect(db_path)
    conn.executemany(
        """INSERT INTO sightings
           (ts, remote_addr, method, path, authority, verified, reason,
            keyid, alg, tag, created, expires, signature_agent, user_agent)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        rows,
    )
    conn.commit()
    conn.close()

    return analytics.verification_rate()  # real query, real code path


def test_estimate_spread_narrows_like_sqrt_n(tmp_path):
    """
    For each sample size N, the empirical standard deviation of the
    estimated rate across N_TRIALS independent harvests should land
    close to the theoretical standard error sqrt(p(1-p)/N). We allow a
    generous tolerance (Monte Carlo noise on only 60 trials is real) but
    the RATIO between sample sizes is the load-bearing check: going from
    N=50 to N=5000 (100x) should tighten the spread by roughly
    sqrt(100)=10x, which is the entire basis for the 'descriptive only'
    -> 'sellable w/ SLA' -> 'tight enough to price' regime claim.
    """
    observed_std_by_n = {}

    for n in SAMPLE_SIZES:
        estimates = []
        for trial in range(N_TRIALS):
            db_path = str(tmp_path / f"sim_{n}_{trial}.db")
            rate = _bulk_simulate_harvest(db_path, n, TRUE_P, seed=trial * 7919 + n)
            estimates.append(rate)

        mean_estimate = sum(estimates) / len(estimates)
        variance = sum((e - mean_estimate) ** 2 for e in estimates) / len(estimates)
        observed_std = math.sqrt(variance)
        observed_std_by_n[n] = observed_std

        theoretical_se = math.sqrt(TRUE_P * (1 - TRUE_P) / n)

        assert abs(mean_estimate - TRUE_P) < 0.05, (
            f"N={n}: mean estimate {mean_estimate:.3f} strayed too far from "
            f"true rate {TRUE_P} -- something is biased, not just noisy"
        )

        assert 0.5 * theoretical_se < observed_std < 2.0 * theoretical_se, (
            f"N={n}: observed std {observed_std:.4f} is not within 2x of "
            f"theoretical SE {theoretical_se:.4f} -- the sqrt(N) claim "
            f"doesn't hold up against simulated data at this N"
        )

    ratio = observed_std_by_n[50] / observed_std_by_n[5000]
    assert 5 < ratio < 20, (
        f"expected roughly a 10x tightening in estimate spread from N=50 "
        f"to N=5000, observed {ratio:.1f}x -- this is the number the "
        f"'accumulate enough agents -> sellable signal' argument rests on"
    )