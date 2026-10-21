# OQOS Analytics dashboard 

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

The repo currently includes 21 passing tests covering protocol correctness, the analytics/statistical claims, and a set of exposure hypotheses with their hardening fixes.

- **`tests/testprotocol.py`** — signing/verification correctness: valid signatures pass, unsigned/unknown-key/expired/tampered all fail, replay attempts are rejected, and same-second legitimate signings are not mistaken for replay.
- **`tests/test_harverster_analytics.py`** — aggregate queries such as `unique_agents()`, `verification_rate()`, `per_agent_summary()`, `tag_distribution()`, and `replay_attempts()` match known ground truth.
- **`tests/test_confidence_curve.py`** — statistical backtest showing the standard error narrows with $\sqrt{N}$ as expected.
- **`tests/test_sybil_bias.py`** — reproduces Sybil inflation and self-selection bias scenarios in a controlled way.
- **`tests/test_repo_config.py`** — ensures the repo is portable and not tied to `/home/claude` paths.
- **`tests/test_exposure_hypotheses.py`** — one test per exposure hypothesis surfaced by treating this as a Web Bot Auth harvester (see below). Each asserts the hardened behaviour, so it would fail against the pre-hardening code.

## Exposure hypotheses and the hardening

Analysing the repo as a harvester surfaced a set of hypotheses about how
RFC 9421 / Web Bot Auth exposes agents, and where this demo's verifier
was weaker than the protocol requires. `tests/test_exposure_hypotheses.py`
turns each into a concrete test; the fixes live across `config.py`,
`analytics.py`, `verifier.py`, `signer.py`, and `dashboard.py`.

| Hypothesis | Problem | Fix |
|---|---|---|
| **H1** record-before-trust | A claimed `keyid` was logged *and attributed* before any verification. | Attribution now requires ≥1 verified sighting; unverified claims go to `analytics.claimed_unverified_identities()`. |
| **H2** cross-site linkability | The same key is reused across every site; nothing surfaced it. | `analytics.authorities_per_keyid()` flags a key seen on >1 authority. |
| **H3** framing | Anyone could forge a victim's public `keyid` on a (rejected) request and pollute its history. | Rejected rows are no longer attributed; they stay visible only as unattributed claims. |
| **H4** log evasion | Malformed signature headers crashed `verify_request` before the request was logged. | Parsing fails soft (never raises); every outcome is loggable. |
| **H5** unbounded lifetime | A decades-long or future-dated signature verified. | `verifier` enforces `MAX_SIGNATURE_LIFETIME` and rejects future `created` (`config.py`). |
| **H6** cross-site replay | The verifier trusted the client-supplied `Host` as its authority. | `resolve_authority()` pins `EXPECTED_AUTHORITY`; the server pins its own host:port. |
| **H7** fingerprinting | A hard-coded 60s lifetime fingerprints the signer. | `sign_request(lifetime=...)` makes it tunable/jitterable. |
| **H8** operator clustering | A one-operator fleet across many keys/IPs looked like a healthy spread. | `analytics.distinct_keyids_per_signature_agent()` collapses it to one actor. |
| **H9** rate inflation | Unauthenticated directory fetches counted as verified. | `verification_rate()` excludes directory housekeeping. |
| **Steering** | An agent re-signs for whatever URL it is lured to via redirect/link. | `sign_request(allowed_authorities=...)` refuses off-list authorities. |
| **XSS** | The dashboard injected harvested `tag`/`paths` via `innerHTML` unescaped. | `dashboard.py` HTML-escapes every interpolated field. |

These are properties of this demo verifier and of the protocol profile,
not of RFC 9421 itself; H1/H2/H7/H8 are inherent to a stable, shared,
public key identity and are *surfaced* here rather than eliminated.

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
- `connector/` — ingest connector: pulls real request logs (Cloudflare, raw access logs, or any JSON feed) into the `sightings` store. CLI (`python -m connector`), a stdlib MCP server (`connector/mcp_server.py`), and a shared `export.py` for the explorer/dashboard JSON shape.
- `explorer/` — `agent-explorer.html`, a standalone UI fed by the connector's `export-json` output, plus `build.py` to regenerate `harvest.json` and serve the page.
- `tests/` — pytest suite covering protocol correctness, analytics arithmetic, the statistical confidence-curve claim, Sybil inflation, portability, the exposure hypotheses, and the ingest connector.

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

## Ingesting real traffic (the connector)

`demo.py` only produces local, loopback traffic. To run the same
analytics over **real** agent sightings, the `connector/` package ingests
request logs from an external source into the same `sightings` store, so
`analytics.py`, `dashboard.py`, and the agent explorer all work unchanged.

Three sources, one normalizer, idempotent writes:

```bash
# a CDN's logs (Cloudflare Logpush/Logs: file, URL, or in-memory)
python -m connector ingest --source cloudflare --path cf-logpush.jsonl
python -m connector ingest --source cloudflare --url https://… --token "$CF_TOKEN"

# raw web-server access logs (JSON logging, or classic combined text)
python -m connector ingest --source access-log --path access.log --authority shop.example

# any JSON feed, with a field map
python -m connector ingest --source generic --path feed.jsonl \
  --map ts=time,remote_addr=ip,host=authority,signature_input=sig_input

python -m connector status                     # rows ingested, per-source cursors
python -m connector export-json --out snap.json  # sightings as explorer/dashboard JSON
```

Streaming and push are supported too, for live feeds rather than files:

```bash
# a live NDJSON pipe (Kafka/Kinesis consumer, tail -f, kafkacat, …)
kafkacat -C -t requests | python -m connector ingest --source stream --map verified=verified

# an HTTP endpoint that ingests pushed batches (Logpush to HTTP, a shipper)
python -m connector serve-webhook --port 8900 --token "$SECRET" --map ts=time,remote_addr=ip
# then POST a JSON array / NDJSON / object to http://host:8900/ingest
```

A Kafka/Kinesis/Pub-Sub consumer is wired in by writing a short generator
that yields record dicts and handing it to `StreamSource`; the writer
ingests lazily as records arrive. Pushed/streamed rows are de-duplicated
by the same fingerprint as file ingests.

The same core is exposed as a dependency-light MCP server
(`python -m connector.mcp_server`) with tools `ingest_logs`,
`connector_status`, `preview_normalize`, and `export_snapshot`.

### Co-agency: reconciling isolated agents on a third-party id

Two agents built by different developers never coordinate, but when both
interact with the same third-party service that service may reuse one
identifier (a transaction id, a webhook hash) across both exchanges. Point
the connector at that id and it can *join* the two otherwise-unrelated
streams on the shared value — a correlation-id join, not coordination.

```bash
# capture a correlation id (a JSON field or header path) while ingesting
python -m connector ingest --source generic --path devA.ndjson \
  --map verified=verified --correlation tx_id
# mark links vouched by a trusted anchor as "attested"
python -m connector ingest --source cloudflare --url "$URL" --token "$T" \
  --correlation RequestHeaders.content-digest --trusted-signers third-party-root

python -m connector reconcile --id 99823        # who shares this id, attested?
python -m connector correlations --min-participants 2   # the co-agency cases
```

Trust discipline: a shared id that only the agents wrote is a *claim* —
anyone who saw it could stamp it (hypothesis H3). A correlation is only
`attested` when some exchange carrying it was signed by a `--trusted-signers`
anchor. Treat merely-observed links as candidates, not facts; drive
automated reconciliation off attested ones. (Full `Content-Digest` / `;req`
checkpoint verification is the planned next slice.)

### Running as a service

`ingest` is a single pass; `poll` is the daemon form — it re-fetches a
source on an interval and relies on the idempotent fingerprint to skip
rows it has already seen:

```bash
python -m connector poll --source cloudflare --url "$URL" --token "$CF_TOKEN" --interval 300
```

`serve-webhook` is the push form (an HTTP endpoint). Both run under the
packaged console script (`pip install .` → `oqos-connector …`) or the
container image (`connector/Dockerfile`), with the DB path set by
`OQOS_DB_PATH`.

### Portability (standalone / the OQOS connector repo)

The `connector/` package is self-contained. It talks to the harvest store
only through `connector/store.py` and parses signatures only through
`connector/sigparse.py`; both reuse oqos-analytics (`analytics`,
`verifier`) when importable and fall back to a vendored, identical SQLite
store and parser when it isn't. So the package can be lifted into its own
repo unchanged — `pyproject.toml` builds exactly `connector` as
`oqos-connector`. Only the live data source has to be supplied; the code
needs nothing else from this repo.

### The agent explorer

`explorer/agent-explorer.html` is a standalone, single-file UI for
browsing what was harvested: per-agent drill-down, a random-agent pick,
and pivots across operators, source addresses, sites, cross-site key
reuse, operator clusters, and unverified "claims". It reads
`explorer/harvest.json` — the connector's `export-json` output — and
falls back to an embedded snapshot if that file isn't present.

```bash
# regenerate explorer/harvest.json from the store, then serve the page
python explorer/build.py --serve          # http://127.0.0.1:8080/agent-explorer.html
```

Refresh loop: ingest real logs with the connector, re-run
`python explorer/build.py`, reload the page.

Signature parameters are parsed with the verifier's own parser, and the
log's real timestamp is preserved (not the ingest time). One honest
caveat: ingesting a CDN's logs records the **upstream's** verification
verdict (logs rarely carry enough to re-run ed25519), so those rows read
`verified (cloudflare)` — the trust shift to an intermediary is exactly
hypotheses H1/H6.

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