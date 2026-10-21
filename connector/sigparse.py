"""
Signature-Input parsing, decoupled from oqos-analytics.

Reuses the verifier's own parser when the host repo is importable (so the
connector can never disagree with live verification), and falls back to an
identical vendored copy when vendored into a standalone repo.
"""
from __future__ import annotations

try:
    from verifier import _parse_sig_input as parse_sig_input  # noqa: F401
except Exception:
    def parse_sig_input(sig_input):
        """Parse a Signature-Input value; return a dict, or None if malformed
        (callers fail closed rather than crash). Mirrors verifier._parse_sig_input."""
        try:
            _, params = sig_input.split("=", 1)
            parts = params.split(";")
            fields = {"covered": parts[0]}
            for p in parts[1:]:
                k, v = p.split("=", 1)
                fields[k] = v.strip('"')
            return fields
        except (ValueError, AttributeError):
            return None
