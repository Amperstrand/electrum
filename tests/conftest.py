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
    """Register custom pytest markers."""
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
