"""
Shared fixtures. Every test gets its own SQLite file and registry
directory (via tmp_path), and verifier.py's in-memory replay guard is
reset between tests -- otherwise a nonce collision from one test's
fixtures could bleed into the next test and produce a spurious replay
failure that has nothing to do with what that test is actually checking.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import analytics
import registry
import verifier
from keys import generate_keypair


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    """Point analytics + registry at a scratch directory for this test only."""
    monkeypatch.setattr(analytics, "DB_PATH", str(tmp_path / "harvest.db"))
    monkeypatch.setattr(registry, "REGISTRY_DIR", str(tmp_path / "registry"))
    analytics.init_db()
    yield tmp_path


@pytest.fixture
def clean_verifier_state(isolated_store):
    """
    verifier.py keeps KNOWN_KEYS and _seen_nonces as module-level state
    (that's what makes replay detection work across requests in the real
    server). For tests that call verify_request() directly, reset both
    so one test's signed requests can't be mistaken for another's.
    """
    verifier._seen_nonces.clear()
    verifier.refresh_known_keys()
    yield
    verifier._seen_nonces.clear()


def make_agent(name: str):
    """Generate + register one agent identity, return (name, priv, pub)."""
    priv, pub = generate_keypair()
    registry.register_agent(name, pub)
    return name, priv, pub