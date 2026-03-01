"""
Pytest configuration and fixtures for Satochip integration tests.

This module provides:
- Custom markers: @pytest.mark.integration, @pytest.mark.manual, @pytest.mark.requires_card
- Fixtures for card connection detection and management
- Skip conditions when remote card is unavailable
"""

import os
import subprocess
import pytest
from unittest.mock import MagicMock, patch

# =============================================================================
# Markers
# =============================================================================

def pytest_configure(config):
    """Register custom pytest markers and load pcsc_remote_patch for macOS."""
    config.addinivalue_line(
        "markers",
        "integration: integration test requiring real Satochip hardware over remote pcscd"
    )
    config.addinivalue_line(
        "markers",
        "manual: manual test requiring user interaction (e.g., 2FA app)"
    )
    config.addinivalue_line(
        "markers",
        "requires_card: test requires physical Satochip card; skipped if unavailable"
    )
    config.addinivalue_line(
        "markers",
        "destructive_card: intentionally modifies or blocks card state; disabled by default"
    )
    config.addinivalue_line(
        "markers",
        "user_story: end-to-end user story test; only runs with --run-user-stories"
    )
    
    # Load pcsc_remote_patch for macOS if remote socket is configured
    # This must happen before any pyscard/pysatochip imports
    socket_path = os.environ.get("PCSCLITE_CSOCK_NAME")
    if not socket_path:
        for candidate in ("/tmp/pcscd-remote.comm", "/tmp/pcscd-smoke.comm", "/run/pcscd/pcscd.comm"):
            if os.path.exists(candidate):
                os.environ["PCSCLITE_CSOCK_NAME"] = candidate
                break
    
    if os.environ.get("PCSCLITE_CSOCK_NAME") and os.path.exists(os.environ["PCSCLITE_CSOCK_NAME"]):
        try:
            import sys
            from pathlib import Path
            _utils_path = Path(__file__).parent.parent.parent.parent.parent / "Satochip-Utils"
            if str(_utils_path) not in sys.path:
                sys.path.insert(0, str(_utils_path))
            import pcsc_remote_patch  # noqa: F401
        except ImportError:
            pass  # Patch not available, continue without it



def pytest_addoption(parser):
    parser.addoption(
        "--allow-destructive-card-tests",
        action="store_true",
        default=False,
        help="run tests marked destructive_card (can block/reset test card)",
    )
    parser.addoption(
        "--run-user-stories",
        action="store_true",
        default=False,
        help="run end-to-end user story tests (requires real Satochip hardware)",
    )


# =============================================================================
# Card Availability Detection
# =============================================================================

def has_remote_pcscd():
    """Check if remote pcscd socket is available via SSH tunnel."""
    socket_path = os.environ.get("PCSCLITE_CSOCK_NAME")
    if socket_path and os.path.exists(socket_path):
        return True

    # Common defaults: host uses /tmp/pcscd-smoke.comm, container uses /run/pcscd/pcscd.comm
    for candidate in ("/tmp/pcscd-smoke.comm", "/run/pcscd/pcscd.comm"):
        if os.path.exists(candidate):
            return True

    return False


def can_detect_card():
    """Attempt to detect Satochip via pyscard."""
    try:
        # Prefer a working socket if one is present but env var is not set
        if "PCSCLITE_CSOCK_NAME" not in os.environ:
            if os.path.exists("/run/pcscd/pcscd.comm"):
                os.environ["PCSCLITE_CSOCK_NAME"] = "/run/pcscd/pcscd.comm"
            elif os.path.exists("/tmp/pcscd-smoke.comm"):
                os.environ["PCSCLITE_CSOCK_NAME"] = "/tmp/pcscd-smoke.comm"

        from smartcard.System import readers
        from smartcard.CardConnection import CardConnection
        
        try:
            available_readers = readers()
        except Exception as e:
            # pcscd may not be available (e.g., running on host instead of container)
            if "context" in str(e).lower() or "establish" in str(e).lower():
                return False
            raise
        
        if not available_readers:
            return False
        
        # Try to establish connection with first reader
        reader = available_readers[0]
        try:
            connection = reader.createConnection()
            connection.connect(CardConnection.T1_protocol)
            atr = connection.getATR()
            connection.disconnect()
            return atr is not None
        except Exception:
            return False
    except ImportError:
        return False
    except Exception as e:
        # Log unexpected errors but don't crash
        print(f"Warning: can_detect_card failed with unexpected error: {e}")
        return False


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="session")
def card_available():
    """Session-scoped fixture indicating if Satochip hardware is available."""
    return can_detect_card()


@pytest.fixture(scope="session")
def remote_pcscd_available():
    """Session-scoped fixture indicating if remote pcscd tunnel is up."""
    return has_remote_pcscd()


@pytest.fixture
def skip_if_no_card(card_available):
    """
    Fixture to skip a test if card is not available.
    
    Usage:
        def test_something(skip_if_no_card):
            # test code here
    """
    if not card_available:
        pytest.skip("Satochip hardware not available")


@pytest.fixture
def skip_if_no_remote_pcscd(remote_pcscd_available):
    """
    Fixture to skip a test if remote pcscd is not available.
    
    Usage:
        def test_something(skip_if_no_remote_pcscd):
            # test code here
    """
    if not remote_pcscd_available:
        pytest.skip("Remote pcscd socket not available")


# =============================================================================
# Mock Fixtures (for tests that don't require actual hardware)
# =============================================================================

@pytest.fixture
def mock_card_connector():
    """Create a mock CardConnector for testing without hardware."""
    with patch('pysatochip.CardConnector.CardConnector') as mock:
        connector = MagicMock()
        
        # Default mock responses for card_get_status
        connector.card_get_status.return_value = {
            'setup_done': True,
            'is_seeded': True,
            'protocol_version': (0, 12, 5),
            'needs_2FA': False,
            'is_satodime': False,
        }
        
        mock.return_value = connector
        yield connector


@pytest.fixture
def satochip_plugin():
    """Create a SatochipPlugin instance (no real hardware needed)."""
    from electrum.plugins.satochip.satochip import SatochipPlugin
    # Create via object.__new__ to bypass __init__
    plugin = object.__new__(SatochipPlugin)
    plugin.name = 'satochip'
    plugin.fullname = 'Satochip'
    return plugin


# =============================================================================
# Test Markers for Selection
# =============================================================================

def pytest_collection_modifyitems(config, items):
    """
    Automatically apply skip markers based on test markers and availability.
    
    This allows tests marked with @pytest.mark.requires_card to be skipped
    if the card is not available, without requiring explicit skip logic.
    """
    # Check availability once per collection
    card_exists = can_detect_card()
    pcscd_exists = has_remote_pcscd()
    
    if not card_exists:
        skip_card = pytest.mark.skip(reason="Satochip hardware not available")
        for item in items:
            if "requires_card" in item.keywords:
                item.add_marker(skip_card)
    
    if not pcscd_exists:
        skip_pcscd = pytest.mark.skip(reason="Remote pcscd socket not available")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_pcscd)

    if not config.getoption("--allow-destructive-card-tests"):
        skip_destructive = pytest.mark.skip(
            reason="destructive card test disabled (use --allow-destructive-card-tests)"
        )
        for item in items:
            if "destructive_card" in item.keywords:
                item.add_marker(skip_destructive)

    if not config.getoption("--run-user-stories"):
        skip_user_story = pytest.mark.skip(
            reason="user story test disabled (use --run-user-stories)"
        )
        for item in items:
            if "user_story" in item.keywords:
                item.add_marker(skip_user_story)


# =============================================================================
# Session-Scoped Live Card Fixtures
# =============================================================================


class _DummyCardClient:
    """Minimal pysatochip client stub for CardConnector.

    CardConnector calls back into its client for UI operations
    (PIN prompts, error display, etc.).  This stub silently
    ignores all such callbacks so tests can run headlessly.
    """
    def request(self, req_type, *args):
        return None


@pytest.fixture(scope="session")
def cc_session(request):
    """
    Session-scoped fixture: a real pysatochip CardConnector talking to the
    remote Satochip via the SSH tunnel pcscd socket.

    Mirrors cc_live (module-scoped) but lives for the entire test session,
    shared across all user story tests.

    Prerequisites (run inside dev container or Podman VM):
      - PCSCLITE_CSOCK_NAME=/run/pcscd/pcscd.comm  (or /tmp/pcscd-smoke.comm)
      - SSH tunnel to remote Satochip established

    Yields the connected CardConnector.  Disconnects on teardown.
    Skips all dependent tests if no socket / card is reachable.
    """
    import logging

    # Ensure the pcscd socket env var is set
    if "PCSCLITE_CSOCK_NAME" not in os.environ:
        for candidate in ("/tmp/pcscd-remote.comm", "/run/pcscd/pcscd.comm", "/tmp/pcscd-smoke.comm"):
            if os.path.exists(candidate):
                os.environ["PCSCLITE_CSOCK_NAME"] = candidate
                break

    if not has_remote_pcscd():
        pytest.skip("Remote pcscd socket not available — start the SSH tunnel first")

    try:
        from pysatochip.CardConnector import CardConnector
    except ImportError:
        pytest.skip("pysatochip not installed")

    cc = None
    try:
        cc = CardConnector(_DummyCardClient(), logging.WARNING)
        import time
        for _attempt in range(5):
            try:
                _, sw1, sw2, _ = cc.card_get_status()
                if (sw1, sw2) == (0x90, 0x00):
                    break
            except Exception:
                pass
            time.sleep(0.5)
        if getattr(cc, 'needs_secure_channel', False):
            try:
                cc.card_initiate_secure_channel()
            except Exception:
                pass  # Already initialized by CardObserver; ignore.
        yield cc
    finally:
        if cc is not None:
            try:
                cc.card_disconnect()
            except Exception:
                pass


@pytest.fixture(scope="session")
def story_artifact_root(tmp_path_factory):
    """
    Session-scoped fixture that creates a timestamped artifact directory
    for user story test outputs (logs, screenshots, exported wallets, etc.).

    Returns the Path to the created directory.
    """
    import datetime
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    artifact_dir = tmp_path_factory.mktemp(f"satochip_user_stories_{timestamp}", numbered=False)
    return artifact_dir
