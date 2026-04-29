"""Pytest configuration and fixtures for Satochip hardware tests.

These tests require a physical Satochip card and compatible smart card reader.
Run with: pytest electrum/plugins/satochip/tests/ -v --tb=short

To skip hardware tests when no reader is present:
  pytest electrum/plugins/satochip/tests/ -v --ignore=electrum/plugins/satochip/tests/hardware
"""

import sys
import os

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def pytest_configure(config):
    config.addinivalue_line("markers", "visual_lifecycle: visual lifecycle test with screenshots")
    config.addinivalue_line("markers", "requires_card: requires a physical Satochip card")
    config.addinivalue_line("markers", "destructive_card: permanently modifies card state")
    config.addinivalue_line("markers", "ui_workflow: real Qt UI automation test (button clicks, text entry)")
    config.addinivalue_line("markers", "bdd: BDD/Gherkin test")


def reader_available():
    """Check if a smart card reader is connected."""
    try:
        from smartcard.System import readers

        return len(readers()) > 0
    except Exception:
        return False


def satochip_card_present():
    """Check if a Satochip card is in the reader."""
    if not reader_available():
        return False
    try:
        from smartcard.System import readers

        rs = readers()
        for r in rs:
            try:
                conn = r.createConnection()
                conn.connect()
                atr = bytes(conn.getATR())
                conn.disconnect()
                if atr[0:2] == bytes([0x3B, 0xD5]):
                    return True
            except Exception:
                continue
    except Exception:
        pass
    return False


skip_without_reader = pytest.mark.skipif(
    not reader_available(),
    reason="No smart card reader connected",
)

skip_without_card = pytest.mark.skipif(
    not satochip_card_present(),
    reason="No Satochip card detected in reader",
)
