"""
Analytics layer: every request that hits the verifier gets recorded as
a "sighting" — whatever metadata the protocol and HTTP transport
actually expose, whether or not the request verifies. This is the
harvesting surface: whatever an agent reveals about itself in the act
of connecting, both signed (attributable) and unsigned (anonymous).

Backed by SQLite so it survives restarts and is queryable directly
with `sqlite3 harvest.db` if you want to poke at it by hand.
"""
import sqlite3
import time
from contextlib import contextmanager

DB_PATH = "/home/claude/webbotauth/harvest.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS sightings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    remote_addr TEXT,
    method TEXT,
    path TEXT,
    authority TEXT,
    verified INTEGER NOT NULL,
    reason TEXT,
    keyid TEXT,
    alg TEXT,
    tag TEXT,
    created INTEGER,
    expires INTEGER,
    signature_agent TEXT,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_keyid ON sightings(keyid);
CREATE INDEX IF NOT EXISTS idx_ts ON sightings(ts);
"""


@contextmanager
def _conn():
    c = sqlite3.connect(DB_PATH)
    try:
        yield c
    finally:
        c.commit()
        c.close()


def init_db():
    with _conn() as c:
        c.executescript(SCHEMA)


def record_sighting(
    remote_addr: str,
    method: str,
    path: str,
    authority: str,
    verified: bool,
    reason: str,
    sig_fields: dict | None = None,
    signature_agent: str | None = None,
    user_agent: str | None = None,
):
    """
    sig_fields: the parsed Signature-Input fields (keyid, alg, tag,
    created, expires) when present — this is the "metadata that could
    be harvested from any agent it sees," on top of raw HTTP metadata
    (remote_addr, user_agent) that's present regardless of signing.
    """
    sig_fields = sig_fields or {}
    with _conn() as c:
        c.execute(
            """INSERT INTO sightings
               (ts, remote_addr, method, path, authority, verified, reason,
                keyid, alg, tag, created, expires, signature_agent, user_agent)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                time.time(),
                remote_addr,
                method,
                path,
                authority,
                int(verified),
                reason,
                sig_fields.get("keyid"),
                sig_fields.get("alg"),
                sig_fields.get("tag"),
                sig_fields.get("created"),
                sig_fields.get("expires"),
                signature_agent,
                user_agent,
            ),
        )


# ---- aggregate queries -----------------------------------------------

def total_sightings() -> int:
    with _conn() as c:
        return c.execute("SELECT COUNT(*) FROM sightings").fetchone()[0]


def unique_agents() -> int:
    """Distinct attributable agents seen (non-null keyid only —
    unsigned traffic can't be individuated, only counted in aggregate)."""
    with _conn() as c:
        return c.execute(
            "SELECT COUNT(DISTINCT keyid) FROM sightings WHERE keyid IS NOT NULL"
        ).fetchone()[0]


def unsigned_count() -> int:
    with _conn() as c:
        return c.execute(
            "SELECT COUNT(*) FROM sightings WHERE keyid IS NULL"
        ).fetchone()[0]


def per_agent_summary() -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            """SELECT keyid,
                      COUNT(*) as n_requests,
                      SUM(verified) as n_verified,
                      MIN(ts) as first_seen,
                      MAX(ts) as last_seen,
                      GROUP_CONCAT(DISTINCT tag) as tags,
                      GROUP_CONCAT(DISTINCT user_agent) as user_agents,
                      GROUP_CONCAT(DISTINCT signature_agent) as signature_agents,
                      GROUP_CONCAT(DISTINCT path) as paths_hit
               FROM sightings
               WHERE keyid IS NOT NULL
               GROUP BY keyid
               ORDER BY n_requests DESC"""
        ).fetchall()
    cols = ["keyid", "n_requests", "n_verified", "first_seen", "last_seen",
            "tags", "user_agents", "signature_agents", "paths_hit"]
    return [dict(zip(cols, r)) for r in rows]


def tag_distribution() -> dict:
    with _conn() as c:
        rows = c.execute(
            """SELECT COALESCE(tag, '(unsigned/none)'), COUNT(*)
               FROM sightings GROUP BY tag ORDER BY 2 DESC"""
        ).fetchall()
    return dict(rows)


def verification_rate() -> float:
    with _conn() as c:
        total, verified = c.execute(
            "SELECT COUNT(*), SUM(verified) FROM sightings"
        ).fetchone()
    return (verified or 0) / total if total else 0.0


def replay_attempts() -> int:
    with _conn() as c:
        return c.execute(
            "SELECT COUNT(*) FROM sightings WHERE reason LIKE 'replay%'"
        ).fetchone()[0]


def distinct_keyids_per_remote_addr() -> dict:
    """
    How many distinct signed identities have come from each source
    address. A single remote_addr producing many distinct keyids is the
    cheap-keygen Sybil pattern: identity is free (ed25519 keypairs cost
    nothing to generate), so 'unique_agents()' alone can't be trusted as
    a population size until this is checked and found flat.
    """
    with _conn() as c:
        rows = c.execute(
            """SELECT remote_addr, COUNT(DISTINCT keyid) as n_keyids
               FROM sightings
               WHERE keyid IS NOT NULL
               GROUP BY remote_addr
               ORDER BY n_keyids DESC"""
        ).fetchall()
    return dict(rows)