from pathlib import Path
import os

APP_ROOT = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("OQOS_ROOT", APP_ROOT)).resolve()
DATA_DIR = Path(os.environ.get("OQOS_DATA_DIR", ROOT / "data")).resolve()
REGISTRY_DIR = Path(os.environ.get("OQOS_REGISTRY_DIR", ROOT / "registry")).resolve()
AGENT_KEY_PATH = Path(os.environ.get("OQOS_AGENT_KEY_PATH", ROOT / "agent")).resolve()
DB_PATH = Path(os.environ.get("OQOS_DB_PATH", DATA_DIR / "harvest.db")).resolve()

# --- verification policy -------------------------------------------------
# Web Bot Auth leans on *short* signature lifetimes as its only mitigation
# against a leaked/replayed signature, but the protocol lets the signer
# pick created/expires freely. These knobs let the verifier enforce an
# actual policy instead of accepting a decades-long, future-dated credential.
MAX_SIGNATURE_LIFETIME = int(os.environ.get("OQOS_MAX_SIG_LIFETIME", "300"))
CLOCK_SKEW = int(os.environ.get("OQOS_CLOCK_SKEW", "5"))

# The authority the verifier signs/checks against. Deriving this from the
# client-supplied Host header lets a captured signature be replayed to a
# different site, so a deployment should pin it. None => fall back to Host
# (legacy demo behaviour); the server sets it to its own host:port in run().
EXPECTED_AUTHORITY = os.environ.get("OQOS_EXPECTED_AUTHORITY") or None

for directory in (DATA_DIR, REGISTRY_DIR):
    directory.mkdir(parents=True, exist_ok=True)
