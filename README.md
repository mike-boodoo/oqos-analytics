# Web Bot Auth, self-hosted

A minimal, dependency-light implementation of the same protocols using (RFC 9421 HTTP Message Signatures + ed25519), running
entirely on your own machine — no CDN, no vendor, no account.

## Run it

```bash
pip install cryptography requests
python3 demo.py
```

Expected output: an unsigned request to `/whoami` gets `403`, a signed
request gets `200`, and replaying the exact same signed request gets
`403` again (replay protection).

## Run the tests

```bash
pip install pytest
python3 -m pytest tests/ -v
```

16 tests, whole suite runs in ~2 seconds. Covers three layers:

- **`tests/test_protocol.py`** — signing/verification correctness:
  valid signatures pass, unsigned/unknown-key/expired/tampered all fail
  closed, genuine replay is rejected, and a regression test locks in the
  fix for the same-second signature-collision bug the original demo run
  surfaced (two legitimate signings landing in the same wall-clock
  second must NOT be confused for a replay).
- **`tests/test_harvester_analytics.py`** — the aggregate queries
  (`unique_agents`, `verification_rate`, `per_agent_summary`,
  `tag_distribution`, `replay_attempts`) return exactly what a
  hand-constructed set of sightings implies, checked against known
  ground truth.
- **`tests/test_confidence_curve.py`** — a Monte Carlo backtest of the
  `sqrt(N)` confidence-narrowing claim: simulates many independent
  harvests at N=50/500/5000 from a known true rate and checks the
  observed estimate spread actually tightens ~10x from N=50 to N=5000,
  the number the "descriptive only → sellable → tight enough to price"
  argument rests on.
- **`tests/test_sybil_and_bias.py`** — makes the two named risks
  concrete and checkable: cheap-keygen Sybil inflation currently
  fools `unique_agents()` (with `distinct_keyids_per_remote_addr()` as
  the detection signal a real mitigation would build on), and
  self-selected signing produces a `verification_rate()` that's
  provably wrong once non-signing failures go unrecorded.

## Files

- `keys.py` — generates an agent's ed25519 identity (keypair), exports the
  public half as a JWK. Same primitive as Cloudflare's per-agent signing key.
- `directory.py` — builds and signs the key directory document served at
  `/.well-known/http-message-signatures-directory`.
- `registry.py` — a directory of registered agents' public keys, standing
  in for "fetch each agent's own `.well-known` over the network."
- `signer.py` — signs an outgoing request: `Signature-Input`, `Signature`,
  `Signature-Agent` headers, covering `@authority` plus a per-signing
  nonce (see the note in the file on why the nonce matters).
- `verifier.py` — the receiving side + harvester. Serves the signed
  directory; gates `/whoami` on a valid signature (checks expiry, known
  key, replay); logs **every** request — signed or not — to `analytics.py`.
- `analytics.py` — SQLite-backed store of every sighting, with aggregate
  queries: unique agents, per-agent request history, tag distribution,
  verification rate, replay attempts, and `distinct_keyids_per_remote_addr()`
  — the concentration check that flags cheap-keygen Sybil inflation
  before it gets fed into a confidence estimate as if it were real N.
- `report.py` — prints a harvest report from whatever `analytics.py` has
  recorded so far.
- `demo.py` — generates a small population of agents (alice/bob/carol),
  sends a realistic mix of signed, repeated, replayed, and anonymous
  traffic, then prints the harvest report.
- `tests/` — pytest suite covering protocol correctness, harvester
  arithmetic, the statistical confidence-curve claim, and the two named
  risks (Sybil inflation, self-selection bias) as reproducible cases.

## What gets harvested, and from whom

Every request produces a "sighting" row, whether or not it's signed:

| Always available (any HTTP request) | Only if the request is signed |
|---|---|
| remote address | `keyid` (stable per-agent identity) |
| method + path | `alg`, `tag` (declared purpose) |
| `Host` (authority) | `created` / `expires` (signature timestamps) |
| `User-Agent` | `Signature-Agent` (claimed directory origin) |

Unsigned traffic is still counted (`unsigned_count()`), just not
individuable — this mirrors the real asymmetry: signing is what turns an
anonymous hit into a trackable agent identity across visits.

## A design nuance the demo surfaces on its own

Web Bot Auth (by design) signs only `@authority` — the domain, not the
specific request. That makes a signature a coarse, reusable credential:
one signature authorizes *any* request to that domain until it expires,
not just the one it was first attached to. Building the harvester
exposed this directly — two legitimate signed requests issued in the
same wall-clock second, with nothing else distinguishing them, produced
byte-identical signatures, so a genuine second call and a replayed first
call were cryptographically indistinguishable. `signer.py` adds an
explicit nonce inside the signed parameters purely so *this demo* can
tell the two apart; real Web Bot Auth accepts that ambiguity and relies
on a short expiry window instead of per-request uniqueness.

## Extending this toward the full design

- **Co-indexing**: swap `registry.py`'s flat directory for a lookup
  against your own agent-graph vector DB, keyed by `kid`.
- **Taxonomy**: branch on the `tag=` field per request type (search /
  agent-action / training), mirroring Cloudflare's three-way split.
- **Monetization**: gate a route behind an HTTP 402 challenge before
  verification (x402-style) instead of flat allow/deny.
- **Multi-hop trust**: have the verifier sign a receipt back to the
  agent, so a third party can later verify the exchange happened — the
  provenance-chain building block.

Nothing here has been audited or hardened for production use — it's a
correctness demo of the protocol shape and a working harvesting
pipeline, not a security-reviewed library.