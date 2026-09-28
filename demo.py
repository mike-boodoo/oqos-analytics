"""
Full loop, no Cloudflare involved -- now with a small population of
agents so the harvester has something to count:

1. Generate identities for three agents (alice, bob, carol)
2. Register them all in the shared registry
3. Start the verifier/harvester
4. Send a realistic mix of traffic: signed requests to different
   paths, an unsigned crawl, and a replay attempt
5. Print the harvest report
"""
import os
import time
import threading
import shutil

import requests

from config import AGENT_KEY_PATH, DATA_DIR, REGISTRY_DIR
from keys import generate_keypair, save_keypair, load_private_key, keyid_for
from registry import register_agent

# clean slate for a repeatable demo run
for f in (DATA_DIR / "harvest.db",):
    if f.exists():
        f.unlink()
if REGISTRY_DIR.exists():
    shutil.rmtree(REGISTRY_DIR, ignore_errors=True)

PORT = 8088
BASE = f"http://localhost:{PORT}"
AGENTS = ["alice", "bob", "carol"]

# verifier.py loads the repo-local agent key at import time, so every
# identity -- including the verifier's own -- has to exist on disk before
# `import verifier` runs below.
print("== 1. generating identities + a directory-signing key ==")
priv_keys = {}
for name in AGENTS:
    _priv, _pub = generate_keypair()
    save_keypair(_priv, str(DATA_DIR / name))
    register_agent(name, _pub)
    priv_keys[name] = _priv
    print(f"  {name}: keyid {keyid_for(_pub)[:16]}...")

_dir_priv, _dir_pub = generate_keypair()
save_keypair(_dir_priv, str(AGENT_KEY_PATH))

import verifier
from signer import sign_request


def main():
    print("\n== 2. starting verifier/harvester ==")
    t = threading.Thread(target=verifier.run, kwargs={"port": PORT}, daemon=True)
    t.start()
    time.sleep(0.5)

    print("\n== 3. simulated traffic ==")

    # alice: well-behaved, hits /whoami and a couple of other routes
    for path, ua in [("/whoami", "alice-bot/1.0"), ("/products", "alice-bot/1.0")]:
        h = sign_request(priv_keys["alice"], "GET", f"{BASE}{path}", signature_agent=f"{BASE}/alice")
        h["User-Agent"] = ua
        r = requests.get(f"{BASE}{path}", headers=h)
        print(f"  alice   GET {path:12s} -> {r.status_code}")

    # bob: signs, hits /whoami twice back-to-back (two distinct legit
    # signatures in the same second -- should NOT be flagged as replay)
    for _ in range(2):
        h = sign_request(priv_keys["bob"], "GET", f"{BASE}/whoami", signature_agent=f"{BASE}/bob")
        h["User-Agent"] = "bobcrawler/2.1"
        r = requests.get(f"{BASE}/whoami", headers=h)
        print(f"  bob     GET /whoami      -> {r.status_code}")

    # carol: signs once, then the SAME request is replayed by an attacker
    h = sign_request(priv_keys["carol"], "GET", f"{BASE}/whoami", signature_agent=f"{BASE}/carol")
    h["User-Agent"] = "carolagent/0.9"
    r = requests.get(f"{BASE}/whoami", headers=h)
    print(f"  carol   GET /whoami      -> {r.status_code}")
    r = requests.get(f"{BASE}/whoami", headers=h)  # replay
    print(f"  replay  GET /whoami      -> {r.status_code}")

    # anonymous/unsigned crawler traffic, unattributable but still logged
    for path in ["/", "/products", "/whoami"]:
        r = requests.get(f"{BASE}{path}", headers={"User-Agent": "genericcrawler/1.0"})
        print(f"  anon    GET {path:12s} -> {r.status_code}")

    print("\n== 4. harvest report ==\n")
    import report
    report.main()


if __name__ == "__main__":
    main()