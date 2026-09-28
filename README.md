# Agentic Field Dashboard

A minimal, dependency-light implementation of the same protocols using (RFC 9421 HTTP Message Signatures + ed25519), running
entirely on your own machine — no CDN, no vendor, no account.

## Quick start

```bash
cd /workspaces/oqos-analytics
python -m pip install -r requirements.txt
python app.py
```

Open the dashboard at http://127.0.0.1:8000. It serves a simple live UI for the analytics data and exposes:

- `/` — dashboard page
- `/api/health` — status check
- `/api/summary` — JSON summary for the dashboard

## Demo / protocol flow

```bash
cd /workspaces/oqos-analytics
python demo.py
```

This runs the verifier, emits signed and unsigned traffic, and prints the harvest report from the analytics layer.

## Run the tests

```bash
cd /workspaces/oqos-analytics
python -m pytest -q
```

The repo currently includes 10 passing tests covering protocol correctness and the analytics/statistical claims.

- **`tests/testprotocol.py`** — signing/verification correctness: valid signatures pass, unsigned/unknown-key/expired/tampered all fail, replay attempts are rejected, and same-second legitimate signings are not mistaken for replay.
- **`tests/test_harverster_analytics.py`** — aggregate queries such as `unique_agents()`, `verification_rate()`, `per_agent_summary()`, `tag_distribution()`, and `replay_attempts()` match known ground truth.
- **`tests/test_confidence_curve.py`** — statistical backtest showing the standard error narrows with $\sqrt{N}$ as expected.
- **`tests/test_sybil_bias.py`** — reproduces Sybil inflation and self-selection bias scenarios in a controlled way.
- **`tests/test_repo_config.py`** — ensures the repo is portable and not tied to `/home/claude` paths.

## Files

- `config.py` — repo-local runtime configuration for the app root, data directory, registry, and agent key storage. This removes the previous hardcoded `/home/claude` assumption.
- `keys.py` — generates an agent's ed25519 identity (keypair), exports the public half as a JWK, and handles key storage.
- `directory.py` — builds and signs the key directory document served at `/.well-known/http-message-signatures-directory`.
- `registry.py` — a directory of registered agents' public keys, standing in for "fetch each agent's own `.well-known` over the network."
- `signer.py` — signs an outgoing request: `Signature-Input`, `Signature`, and `Signature-Agent` headers, covering `@authority` plus a per-signing nonce.
- `verifier.py` — the receiving side + harvester. Serves the signed directory, gates `/whoami` on a valid signature, and logs every request to `analytics.py`.
- `analytics.py` — SQLite-backed store of every sighting, with aggregate queries for unique agents, per-agent histories, tag distribution, verification rate, replay attempts, and `distinct_keyids_per_remote_addr()`.
- `report.py` — prints a harvest report from the recorded data.
- `dashboard.py` — lightweight web UI and JSON summary API for the harvested analytics.
- `app.py` — application entry point for the dashboard.
- `demo.py` — generates a small population of agents (alice/bob/carol), sends mixed signed/unsigned/replayed traffic, and prints the harvest report.
- `tests/` — pytest suite covering protocol correctness, analytics arithmetic, the statistical confidence-curve claim, Sybil inflation, and portability.

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

## Notes

- The project is now repo-local and portable: no checkout-specific absolute paths are required.
- The dashboard is a working UI layer on top of the analytics store and is intended to serve live observability for the harvest pipeline.
- Nothing here has been audited or hardened for production use — it's a correctness demo of the protocol shape and a working harvesting pipeline, not a security-reviewed library.