from pathlib import Path
import os

APP_ROOT = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("OQOS_ROOT", APP_ROOT)).resolve()
DATA_DIR = Path(os.environ.get("OQOS_DATA_DIR", ROOT / "data")).resolve()
REGISTRY_DIR = Path(os.environ.get("OQOS_REGISTRY_DIR", ROOT / "registry")).resolve()
AGENT_KEY_PATH = Path(os.environ.get("OQOS_AGENT_KEY_PATH", ROOT / "agent")).resolve()
DB_PATH = Path(os.environ.get("OQOS_DB_PATH", DATA_DIR / "harvest.db")).resolve()

for directory in (DATA_DIR, REGISTRY_DIR):
    directory.mkdir(parents=True, exist_ok=True)
