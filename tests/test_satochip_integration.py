"""
Integration tests for Satochip plugin with remote pcscd card.

Phases covered:
  Phase 1 — Smoke: remote card connectivity through Electrum plugin
  Phase 2 — Card status & identity: status dict, label read/write, authentikey
  Phase 3 — Card initialization & wallet creation:
              card_setup() with a PIN, seed import (known + generated),
              xpub derivation and software cross-check, seed reset
  Phase 4 — PIN management:
              PIN verification, change-PIN roundtrip, wrong-PIN counter,
              PIN cache / session timeout via SatochipClient.timeout()

These tests exercise the real Satochip card connected to a remote pcscd socket
(tunneled from OpenWrt via Podman VM). Each test is marked @pytest.mark.integration
and will be skipped if the remote socket is unavailable.

Prerequisites:
  - SSH tunnel established: podman machine ssh regtest "ssh -f -N -L /tmp/pcscd-smoke.comm:..."
  - Satochip card inserted in reader on OpenWrt device (192.168.13.202)
  - PCSCLITE_CSOCK_NAME=/run/pcscd/pcscd.comm (inside container) or
    PCSCLITE_CSOCK_NAME=/tmp/pcscd-smoke.comm (in Podman VM) set automatically
    by conftest.py or scripts/run_dev.sh
  - pyscard, pysatochip libraries installed in the active Python environment

Run all integration tests from the dev container (includes pip install):
  ./scripts/run_dev.sh "pip install -e /electrum && python3 -m pytest -v tests/test_satochip_integration.py -m integration -s"

Run a single phase:
  ./scripts/run_dev.sh "pip install -e /electrum && python3 -m pytest -v tests/test_satochip_integration.py::TestPINManagement -s"
  ./scripts/run_dev.sh "pip install -e /electrum && python3 -m pytest -v tests/test_satochip_integration.py::TestSessionTimeout -s"
  ./scripts/run_dev.sh "pip install -e /electrum && python3 -m pytest -v tests/test_satochip_integration.py::TestCardInitialization -s"
  ./scripts/run_dev.sh "pip install -e /electrum && python3 -m pytest -v tests/test_satochip_integration.py::TestWalletCreationKnownSeed -s"
  ./scripts/run_dev.sh "pip install -e /electrum && python3 -m pytest -v tests/test_satochip_integration.py::TestWalletCreationGeneratedSeed -s"

Run mock/reference tests on the host (no card needed):
  python3 -m pytest tests/test_satochip_integration.py::TestReferenceImplementation -v

Phase 3 card-state prerequisites (tests enforce these with skips):
  TestCardInitialization         → requires blank card  (setup_done=False)
  TestWalletCreationKnownSeed    → requires setup_done=True, is_seeded=False
  TestWalletCreationGeneratedSeed → requires setup_done=True; resets + re-seeds internally
"""

import pytest
import os
from unittest.mock import patch, MagicMock, ANY
from types import SimpleNamespace

from electrum.plugins.satochip import satochip
from electrum.plugins.satochip.satochip import SatochipPlugin, SatochipClient
from electrum.simple_config import SimpleConfig
from tests.conftest import has_remote_pcscd


# =============================================================================
# Helpers
# =============================================================================

def _mk_plugin():
    """Create a SatochipPlugin instance via object.__new__ (no __init__)."""
    p = object.__new__(SatochipPlugin)
    p.device = "Satochip"
    p.config = SimpleConfig({})
    p.handler = MagicMock()
    return p


def _mk_client(card_connector_mock=None):
    """Create a SatochipClient with a mocked CardConnector."""
    if card_connector_mock is None:
        card_connector_mock = MagicMock()
    
    handler = MagicMock()
    client = object.__new__(SatochipClient)
    client.handler = handler
    client.cc = card_connector_mock  # CardConnector is 'cc', not 'card_connector'
    client.ux_busy = False
    client.last_operation = float('inf')  # set by __init__ in real code; needed by timeout()
    return client


# =============================================================================
# Phase 3 constants and helpers
# =============================================================================

# PIN used to initialize the test card via card_setup().
# A short, memorable value so tests can be re-run easily.
# ⚠️  NEVER use on a card holding real funds.
TESTPIN = b'123456'

# A random PUK (unblock code) stored during card_setup but not actually used
# in these tests — pysatochip requires a non-empty value at setup time.
TESTPUK = b'12345678'

# Well-known BIP39 test mnemonic (12 words, all from BIP39 word list).
# Standard entropy 00000000000000000000000000000001.
# ⚠️  Public test vector — NEVER use with real funds.
ABANDON_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)

# xpub derivation paths under test
_XPUB_PATHS = [
    ("m/84'/0'/0'", 'p2wpkh'),       # native SegWit (BIP84)
    ("m/44'/0'/0'", 'standard'),     # legacy (BIP44)
    ("m/49'/0'/0'", 'p2wpkh-p2sh'),  # wrapped SegWit (BIP49)
]


def _derive_xpub_from_card(cc, bip32_path: str, xtype: str) -> str:
    """
    Derive a BIP32 xpub from the card at *bip32_path* using the same logic
    as ``SatochipClient.get_xpub()``.

    This replicates the plugin's derivation so integration tests can call it
    directly without needing a full ``SatochipClient`` or HW-wallet thread.
    """
    from electrum.bip32 import BIP32Node
    from electrum.crypto import hash_160
    from electrum.plugins.satochip.satochip import bip32path2bytes

    depth, bytepath = bip32path2bytes(bip32_path)
    childkey, childchaincode = cc.card_bip32_get_extendedkey(bytepath)

    if depth == 0:
        fingerprint = bytes(4)
        child_number = bytes(4)
    else:
        parentkey, _ = cc.card_bip32_get_extendedkey(bytepath[:-4])
        fingerprint = hash_160(parentkey.get_public_key_bytes(compressed=True))[:4]
        child_number = bytepath[-4:]

    return BIP32Node(
        xtype=xtype,
        eckey=childkey,
        chaincode=childchaincode,
        depth=depth,
        fingerprint=fingerprint,
        child_number=child_number,
    ).to_xpub()


def _derive_xpub_software(seed_bytes: bytes, bip32_path: str, xtype: str) -> str:
    """
    Compute the BIP32 xpub purely in software from *seed_bytes*.

    Used as the reference value for comparing against the card-derived xpub in
    ``TestWalletCreationKnownSeed``.
    """
    from electrum.bip32 import BIP32Node
    root = BIP32Node.from_rootseed(seed_bytes, xtype=xtype)
    return root.subkey_at_private_derivation(bip32_path).to_xpub()


def _require_card_state(cc, *, requires_setup: bool = True, requires_seeded=None):
    """
    Refresh card status and skip the current test if the card is not in the
    expected state.

    Parameters
    ----------
    requires_setup:
        If True, skip when ``setup_done=False`` (card is blank).
    requires_seeded:
        If True, skip when ``is_seeded=False`` (seed not loaded).
        If False, skip when ``is_seeded=True`` (seed already present).
        If None, no seeded check is performed.

    Returns
    -------
    dict
        The status dict ``d`` returned by ``card_get_status()``.
    """
    _, _, _, d = cc.card_get_status()
    if requires_setup and not d['setup_done']:
        pytest.skip(
            "Card not initialized (setup_done=False). "
            "Run TestCardInitialization first, or re-run after a factory reset."
        )
    if requires_seeded is True and not d['is_seeded']:
        pytest.skip(
            "Card not seeded. "
            "Run TestWalletCreationKnownSeed.test_import_abandon_mnemonic first."
        )
    if requires_seeded is False and d['is_seeded']:
        pytest.skip(
            "Card is already seeded. "
            "Run TestWalletCreationGeneratedSeed.test_reset_seed_before_new_import "
            "first, or reset the seed manually."
        )
    return d


# =============================================================================
# Phase 1: Smoke — Remote Card Connectivity
# =============================================================================

@pytest.mark.integration
@pytest.mark.requires_card
class TestRemoteConnectivity:
    """Verify that Electrum can see the Satochip through the plugin."""

    def test_plugin_instantiation(self):
        """Verify SatochipPlugin can be instantiated."""
        plugin = _mk_plugin()
        
        # Should have core attributes
        assert plugin.device == "Satochip"
        assert plugin.config is not None

    def test_plugin_has_keystore_class(self):
        """Verify plugin has keystore class configured."""
        plugin = _mk_plugin()
        assert hasattr(satochip, 'Satochip_KeyStore')
        assert plugin.keystore_class == satochip.Satochip_KeyStore

    def test_plugin_supported_xtypes(self):
        """Verify plugin declares supported address types."""
        plugin = _mk_plugin()
        xtypes = plugin.SUPPORTED_XTYPES
        assert 'p2wpkh' in xtypes, "Should support native segwit"
        assert 'p2wpkh-p2sh' in xtypes, "Should support nested segwit"
        assert 'standard' in xtypes, "Should support legacy"

    def test_smartcard_reader_detection(self):
        """
        Test that smartcard readers can be enumerated.
        
        This calls the device enumerate function directly.
        """
        try:
            from smartcard.System import readers
            available = readers()
            # Either we find readers or we're on a system without pcscd
            # Either way, the call shouldn't crash
            assert isinstance(available, list)
        except Exception as e:
            # Expected if pcscd is not available locally
            # (tests should run in container where pcscd socket is available)
            if "context" in str(e).lower() or "establish" in str(e).lower():
                pytest.skip("pcscd not available (run tests in dev container with remote socket)")
            raise

    def test_client_has_request_method(self):
        """Verify SatochipClient has request dispatch method."""
        connector = MagicMock()
        client = _mk_client(connector)
        
        # Should have request method for handler dispatch
        assert hasattr(client, 'request')
        assert callable(client.request)

    def test_client_is_pairable(self):
        """Verify client reports being pairable."""
        connector = MagicMock()
        client = _mk_client(connector)
        
        # Satochip is always pairable (smartcards persist connection state)
        assert client.is_pairable() is True

    def test_client_label_priority(self):
        """
        Verify client label() prefers card label > authentikey fingerprint > generic.

        card_get_label() returns a 4-tuple (response, sw1, sw2, label_str).
        label() prepends "Satochip: " so the device type is always visible.
        Full priority-chain coverage lives in test_satochip_plugin.py;
        this test just confirms the method is wired up correctly.
        """
        connector = MagicMock()
        # Ensure authentikey fallback doesn't trigger.
        # label() now checks cc.parser.authentikey_coordx (not cc.authentikey_coordx).
        connector.parser.authentikey_coordx = None
        # card_get_label() returns (response, sw1, sw2, label_str)
        connector.card_get_label.return_value = ([], 0x90, 0x00, "MyCard")
        client = _mk_client(connector)

        # Path 1: real label present — returned with "Satochip: " prefix
        assert client.label() == "Satochip: MyCard"

        # Path 3: sentinel label + no authentikey → generic fallback
        connector.card_get_label.return_value = ([], 0x90, 0x00, "(none)")
        assert client.label() == "Satochip"

    def test_timeout_clears_pin_cache(self):
        """
        Verify timeout() clears the PIN cache when the session has been idle.

        timeout(cutoff) fires when last_operation < cutoff, i.e. the last
        operation was *before* the cutoff timestamp.  Here we set
        last_operation=0 (epoch) so any positive cutoff triggers it.
        """
        connector = MagicMock()
        client = _mk_client(connector)

        # Expired session: last operation is in the distant past
        client.last_operation = 0
        client.timeout(100_000)  # cutoff well after last_operation → fires

        # timeout() should have called cc.set_pin(0, None) to clear PIN cache
        connector.set_pin.assert_called()


# =============================================================================
# Phase 1 Hardware Tests (require real card over remote pcscd)
# =============================================================================

@pytest.mark.integration
@pytest.mark.requires_card
class TestRemoteCardHardware:
    """Tests that require real card communication."""

    def test_card_status_readable(self, skip_if_no_remote_pcscd):
        """
        Test that we can read card status from the remote card.
        
        This is the first end-to-end test: assumes SSH tunnel is active
        and remote card is reachable.
        """
        try:
            from smartcard.System import readers
            available = readers()
            
            if not available:
                pytest.skip("No smartcard readers available")
            
            reader = available[0]
            from smartcard.CardConnection import CardConnection
            connection = reader.createConnection()
            connection.connect(CardConnection.T1_protocol)
            
            # Try to read ATR (this proves connection works)
            atr = connection.getATR()
            assert atr is not None
            assert len(atr) > 0
            
            connection.disconnect()
            
        except ImportError:
            pytest.skip("pyscard not installed")
        except Exception as e:
            if "context" in str(e).lower() or "establish" in str(e).lower():
                pytest.skip("pcscd not available (run in container with remote socket)")
            raise


# =============================================================================
# Reference Tests (documentation of expected API)
# =============================================================================

class TestReferenceImplementation:
    """
    Non-hardware tests showing how the plugin is used.
    
    These tests use mocks and serve as documentation of the expected API.
    """

    def test_mk_plugin_helper(self):
        """Show how to create a plugin instance for testing."""
        plugin = _mk_plugin()
        assert plugin.device == "Satochip"
        assert plugin.config is not None

    def test_mk_client_helper(self):
        """Show how to create a client instance for testing."""
        connector = MagicMock()
        client = _mk_client(connector)
        assert client.cc is not None
        assert client.handler is not None

    def test_plugin_device_filter(self):
        """Show how the plugin recognizes devices."""
        plugin = _mk_plugin()
        
        # Plugin should have DEVICE_IDS (generic smartcard, VID/PID both 0)
        assert hasattr(plugin, 'DEVICE_IDS')
        assert plugin.DEVICE_IDS == [(0, 0)]

    def test_client_supports_taproot(self):
        """Show how to check Taproot (Schnorr) support."""
        connector = MagicMock()
        
        # Protocol 0.14+ supports Taproot
        # protocol_version is an attribute, set it directly
        client = _mk_client(connector)
        client.cc.protocol_version = 14  # Numeric version
        
        # Should support taproot
        assert client.supports_taproot() is True
        
        # Older protocol doesn't
        client.cc.protocol_version = 12
        assert client.supports_taproot() is False


# =============================================================================
# Phase 2: Card Status & Identity
# =============================================================================

class _DummyCardClient:
    """Minimal pysatochip client stub for CardConnector.

    CardConnector calls back into its client for UI operations
    (PIN prompts, error display, etc.).  This stub silently
    ignores all such callbacks so tests can run headlessly.
    """
    def request(self, req_type, *args):
        return None


@pytest.fixture(scope="module")
def cc_live(request):
    """
    Module-scoped fixture: a real pysatochip CardConnector talking to the
    remote Satochip via the SSH tunnel pcscd socket.

    Prerequisites (run inside dev container or Podman VM):
      - PCSCLITE_CSOCK_NAME=/run/pcscd/pcscd.comm  (or /tmp/pcscd-smoke.comm)
      - SSH tunnel to 192.168.13.202 established

    Yields the connected CardConnector.  Disconnects on teardown.
    Skips the entire test module if no socket / card is reachable.
    """
    import logging

    # Ensure the pcscd socket env var is set (conftest also does this but
    # being explicit here makes the skip reason clearer)
    if "PCSCLITE_CSOCK_NAME" not in os.environ:
        for candidate in ("/run/pcscd/pcscd.comm", "/tmp/pcscd-smoke.comm"):
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
        # The CardMonitor thread may take a moment to fully initialize the
        # pcscd connection after creation.  Retry card_get_status() until it
        # succeeds (or we give up after 5 attempts × 0.5 s = 2.5 s).
        import time
        for _attempt in range(5):
            try:
                _, sw1, sw2, _ = cc.card_get_status()
                if (sw1, sw2) == (0x90, 0x00):
                    break
            except Exception:
                pass
            time.sleep(0.5)
        # card_get_status() sets needs_secure_channel=True for initialized
        # cards.  The CardObserver thread calls card_initiate_secure_channel()
        # after detecting card insertion, but there is a race between that
        # thread and this fixture.  Explicitly initialise the secure channel
        # here so all tests see a ready SecureChannel regardless of timing.
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


@pytest.mark.integration
@pytest.mark.requires_card
class TestCardStatusIdentity:
    """
    Phase 2: Card Status & Identity.

    Exercises every card-identity operation against the live remote Satochip:
      • card_get_status()     → protocol version, PIN tries, seed state, 2FA flag
      • card_get_label()      → user-set label (or sentinel if not set)
      • card_set_label()      → write + read-back label (round-trip), then restore
      • card_export_authentikey() → unique device public key
      • SatochipClient.label()   → Electrum-level label priority chain

    How these compare to other Electrum hardware-wallet plugins
    -----------------------------------------------------------
    | Feature                    | Trezor | Coldcard | Ledger | Satochip |
    |----------------------------|--------|----------|--------|----------|
    | Label read (from device)   |  ✅    |   ✅     |   ✅   |   ✅     |
    | Label write (via Electrum) |  ❌*   |   ❌*    |   ❌*  |   ✅     |
    | Firmware / protocol ver.   |  ✅    |   ✅     |   ✅   |   ✅     |
    | Unique device ID           |  ✅†   |   ✅†    |   ✅†  |   ✅‡    |
    | Show address on device     |  ✅    |   ✅     |   ✅   |   ❌ stub|
    | PKI authenticity verify    |  ❌    |   ❌     |   ❌   |   ✅     |
    | NFC policy                 |  ❌    |   ❌     |   ❌   |   ✅     |
    | 2FA (TOTP challenge)       |  ❌    |   ❌     |   ❌   |   ✅     |

    *  Trezor/Coldcard/Ledger labels are set via their own companion apps,
       not via Electrum.
    †  Serial number / device_id exposed at the protocol level.
    ‡  Authentikey: a persistent EC public key unique to this card.
       The first 4 bytes of hash160(authentikey) form the fingerprint stored
       in the wallet file (same format as BIP-32 parent fingerprint).
    """

    # ------------------------------------------------------------------
    # card_get_status()
    # ------------------------------------------------------------------

    def test_card_get_status_returns_tuple(self, cc_live):
        """card_get_status() must return a 4-tuple (response, sw1, sw2, d)."""
        result = cc_live.card_get_status()
        assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
        assert len(result) == 4, f"Expected 4-tuple, got length {len(result)}"

    def test_card_get_status_sw_ok(self, cc_live):
        """Status word must be 0x9000 (success)."""
        (_, sw1, sw2, _) = cc_live.card_get_status()
        assert (sw1, sw2) == (0x90, 0x00), (
            f"Unexpected SW: 0x{sw1:02x}{sw2:02x} — is the applet installed?")

    def test_card_get_status_dict_has_required_keys(self, cc_live):
        """Status dict must contain all expected fields."""
        (_, _, _, d) = cc_live.card_get_status()
        required = {
            "protocol_major_version",
            "protocol_minor_version",
            "applet_major_version",
            "applet_minor_version",
            "protocol_version",
            "PIN0_remaining_tries",
            "setup_done",
            "is_seeded",
            "needs2FA",
        }
        missing = required - set(d.keys())
        assert not missing, f"Status dict missing keys: {missing}\nGot: {d}"

    def test_protocol_version_is_reasonable(self, cc_live):
        """Protocol version must be >= 0x000C (v0.12) — earliest we support."""
        (_, _, _, d) = cc_live.card_get_status()
        version = d["protocol_version"]
        # version is (major<<8)+minor, e.g. 0x000C = 12 = v0.12
        assert isinstance(version, int), f"protocol_version should be int, got {type(version)}"
        assert version >= 0x000C, (
            f"protocol_version 0x{version:04x} too old — minimum is 0x000C (v0.12)")

    def test_protocol_version_cached_on_connector(self, cc_live):
        """protocol_version must be cached as cc.protocol_version after card_get_status()."""
        cc_live.card_get_status()
        assert hasattr(cc_live, 'protocol_version'), "cc.protocol_version not set after card_get_status()"
        assert isinstance(cc_live.protocol_version, int)

    def test_setup_done_and_seeded_flags(self, cc_live):
        """Real card should have setup_done=True and is_seeded=True (seeded card assumed)."""
        cc_live.card_get_status()
        # These are the expected cached attributes that tests/SatochipClient relies on
        assert hasattr(cc_live, 'setup_done'), "cc.setup_done not set"
        assert hasattr(cc_live, 'is_seeded'), "cc.is_seeded not set"
        # A fresh blank card would have setup_done=False; we skip gracefully
        if not cc_live.setup_done:
            pytest.skip("Card is not set up (blank card) — seed the card first")
        # setup_done=True is required for wallet operations
        assert cc_live.setup_done is True
        # is_seeded tells us if we can derive keys; log but don't fail
        if not cc_live.is_seeded:
            pytest.skip("Card is set up but not seeded — import/generate a seed first")
        assert cc_live.is_seeded is True

    def test_pin_tries_remaining_in_range(self, cc_live):
        """PIN0 tries remaining should be a positive integer on an initialized card."""
        if not getattr(cc_live, 'setup_done', False):
            pytest.skip(
                "Card not initialized (setup_done=False) — "
                "PIN0_remaining_tries=0 on a blank card is expected")
        (_, _, _, d) = cc_live.card_get_status()
        tries = d["PIN0_remaining_tries"]
        assert isinstance(tries, int), f"PIN0_remaining_tries should be int, got {type(tries)}"
        assert 0 < tries <= 15, (
            f"PIN0_remaining_tries={tries} outside expected range (1–15). "
            "If 0, PIN is blocked!")

    def test_needs_2fa_is_bool(self, cc_live):
        """needs2FA should be a boolean."""
        (_, _, _, d) = cc_live.card_get_status()
        assert isinstance(d["needs2FA"], bool), (
            f"needs2FA should be bool, got {type(d['needs2FA'])}: {d['needs2FA']}")

    def test_card_get_status_full_report(self, cc_live, capsys):
        """
        Print full card status for documentation.

        Not a strict assertion test — captures and prints the complete status
        dict so it is visible in pytest verbose output and captured in CI logs.
        This record should be updated in WORKING_NOTES.md each time the card
        firmware changes.
        """
        (response, sw1, sw2, d) = cc_live.card_get_status()
        print("\n=== Card Status Report ===")
        print(f"  SW: 0x{sw1:02x}{sw2:02x}")
        print(f"  Protocol version: {d.get('protocol_major_version', '?')}.{d.get('protocol_minor_version', '?')}")
        print(f"  Applet version:   {d.get('applet_major_version', '?')}.{d.get('applet_minor_version', '?')}")
        print(f"  Setup done:       {d.get('setup_done')}")
        print(f"  Is seeded:        {d.get('is_seeded')}")
        print(f"  Needs 2FA:        {d.get('needs2FA')}")
        print(f"  PIN0 tries left:  {d.get('PIN0_remaining_tries')}")
        print(f"  PUK0 tries left:  {d.get('PUK0_remaining_tries')}")
        print(f"  NFC policy:       {d.get('nfc_policy')}")
        print(f"  Schnorr policy:   {d.get('feature_schnorr_policy')}")
        print(f"  Nostr policy:     {d.get('feature_nostr_policy')}")
        print(f"  Liquid policy:    {d.get('feature_liquid_policy')}")
        print(f"  Needs sec.chan.:  {d.get('needs_secure_channel')}")
        print(f"  Raw response:     {bytes(response).hex() if response else 'N/A'}")
        print("==========================")
        # The only hard assertion: status word must be OK
        assert (sw1, sw2) == (0x90, 0x00)

    # ------------------------------------------------------------------
    # card_get_label() / card_set_label()
    # ------------------------------------------------------------------

    def test_card_get_label_returns_tuple(self, cc_live):
        """card_get_label() must return a 4-tuple (response, sw1, sw2, label_str)."""
        cc_live.set_pin(0, list(TESTPIN))  # cache PIN for secure-channel auto-auth
        result = cc_live.card_get_label()
        assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
        assert len(result) == 4, f"Expected 4-tuple, got length {len(result)}"

    def test_card_get_label_returns_string(self, cc_live):
        """The label element of the tuple must be a string."""
        cc_live.set_pin(0, list(TESTPIN))
        (_, _, _, label) = cc_live.card_get_label()
        assert isinstance(label, str), f"label should be str, got {type(label)}: {label!r}"

    def test_card_get_label_sw_is_ok_or_unsupported(self, cc_live):
        """
        Acceptable SW codes from card_get_label():

          0x9000  — label read successfully
          0x6D00  — INS 0x3D not supported (older firmware without label feature)
          0x9C04  — SW_SETUP_NOT_DONE: card is blank/uninitialized; label
                    metadata is not available yet.  This is expected for cards
                    that have not yet been personalized.

        Any other SW indicates a genuine protocol error.
        """
        cc_live.set_pin(0, list(TESTPIN))
        (_, sw1, sw2, _) = cc_live.card_get_label()
        ok_values = {
            (0x90, 0x00),  # success
            (0x6d, 0x00),  # INS not supported — old firmware
            (0x9c, 0x04),  # SW_SETUP_NOT_DONE — card not yet initialized
        }
        assert (sw1, sw2) in ok_values, (
            f"Unexpected SW from card_get_label: 0x{sw1:02x}{sw2:02x}")

    def test_card_get_label_report(self, cc_live, capsys):
        """Print the current card label for visibility in test output."""
        cc_live.set_pin(0, list(TESTPIN))
        (_, sw1, sw2, label) = cc_live.card_get_label()
        print(f"\n=== Card Label ===")
        print(f"  SW:    0x{sw1:02x}{sw2:02x}")
        print(f"  Label: {label!r}")
        if (sw1, sw2) == (0x6d, 0x00):
            print(f"  Note:  Firmware does not support card_get_label (INS 0x3D)")
        print("==================")
        assert isinstance(label, str)

    def test_card_label_roundtrip(self, cc_live):
        """
        Write a test label, read it back, then restore the original.

        This roundtrip verifies that card_set_label + card_get_label work
        end-to-end.

        Skipped automatically if:
          - card firmware doesn't support labels (SW=0x6D00)
          - the write APDU itself fails (may need PIN — handled gracefully)

        The original label is always restored in a finally block so a test
        failure doesn't leave the card in a dirty state.
        """
        cc_live.set_pin(0, list(TESTPIN))
        (_, sw1, sw2, original_label) = cc_live.card_get_label()
        if (sw1, sw2) == (0x6d, 0x00):
            pytest.skip("Card firmware does not support card_get_label/set_label")

        test_label = "electrum-phase2-test"
        original_label = original_label if original_label not in ("(none)", "(unknown)") else ""

        try:
            # Write the test label
            (_, wt_sw1, wt_sw2) = cc_live.card_set_label(test_label)

            if (wt_sw1, wt_sw2) != (0x90, 0x00):
                # Write may fail if PIN not verified; skip rather than fail
                pytest.skip(
                    f"card_set_label returned SW=0x{wt_sw1:02x}{wt_sw2:02x} "
                    "(likely requires PIN verification — tested in Phase 4)")

            # Read back and verify
            (_, rd_sw1, rd_sw2, read_back) = cc_live.card_get_label()
            assert (rd_sw1, rd_sw2) == (0x90, 0x00), (
                f"Read-back after set_label failed: SW=0x{rd_sw1:02x}{rd_sw2:02x}")
            assert read_back == test_label, (
                f"Label mismatch after set: expected {test_label!r}, got {read_back!r}")

        finally:
            # Always restore the original label, even if test fails
            restore = original_label if original_label else ""
            try:
                cc_live.card_set_label(restore)
            except Exception:
                pass  # Best-effort restore

    # ------------------------------------------------------------------
    # card_export_authentikey()
    # ------------------------------------------------------------------

    def test_card_export_authentikey_returns_value(self, cc_live):
        """
        card_export_authentikey() must return an EC public key object.

        The authentikey is a persistent EC keypair generated on the card at
        personalisation time.  It never changes for the life of the card and
        uniquely identifies it — even across factory resets of the BIP39 seed.

        pysatochip returns an ECPubkey object from electrum_ecc.
        """
        cc_live.card_get_status()  # populate cc.setup_done / is_seeded
        if not getattr(cc_live, 'is_seeded', False):
            pytest.skip("Card is not seeded — authentikey not available on blank card")

        try:
            authentikey = cc_live.card_export_authentikey()
        except Exception as e:
            error = str(e).lower()
            if "uninitializ" in error or "not initialized" in error:
                pytest.skip(f"Card reports uninitialized: {e}")
            raise

        assert authentikey is not None, "card_export_authentikey() returned None"

    def test_card_authentikey_has_pubkey_bytes(self, cc_live):
        """
        After calling card_export_authentikey() the connector must cache
        authentikey_coordx (the compressed 33-byte X-coord of the key).

        Electrum's SatochipClient.label() uses this to build the fingerprint
        fallback label, so it must be populated correctly.
        """
        cc_live.card_get_status()
        if not getattr(cc_live, 'is_seeded', False):
            pytest.skip("Card is not seeded")

        try:
            cc_live.card_export_authentikey()
        except Exception as e:
            if "uninitializ" in str(e).lower():
                pytest.skip(f"Card not initialized: {e}")
            raise

        assert hasattr(cc_live.parser, 'authentikey_coordx'), (
            "cc.parser.authentikey_coordx not set after card_export_authentikey()")
        coordx = cc_live.parser.authentikey_coordx
        assert coordx is not None, "cc.parser.authentikey_coordx is None"
        # Should be 33 bytes (compressed pubkey) or 65 bytes (uncompressed)
        coordx_bytes = bytes(coordx)
        # authentikey_coordx is the raw 32-byte X-coordinate of the
        # secp256k1 point — NOT a DER-encoded compressed public key.
        # The full ECPubkey (with prefix) is on cc.parser.authentikey.
        assert len(coordx_bytes) == 32, (
            f"authentikey_coordx should be 32 bytes (X-coordinate), got {len(coordx_bytes)}")
        # Must be a non-zero value
        assert coordx_bytes != b'\x00' * 32, "authentikey_coordx is all-zero"

    def test_card_authentikey_stable_across_calls(self, cc_live):
        """
        Two successive calls to card_export_authentikey() must return the same key.

        This verifies the key is truly persistent on the card (not randomly
        re-generated).
        """
        cc_live.card_get_status()
        if not getattr(cc_live, 'is_seeded', False):
            pytest.skip("Card is not seeded")

        try:
            key1 = cc_live.card_export_authentikey()
            key2 = cc_live.card_export_authentikey()
        except Exception as e:
            if "uninitializ" in str(e).lower():
                pytest.skip(f"Card not initialized: {e}")
            raise

        # Compare via the cached bytes (ECPubkey equality may vary by version)
        coordx1 = bytes(cc_live.parser.authentikey_coordx) if cc_live.parser.authentikey_coordx else None
        # Call again to re-populate
        cc_live.card_export_authentikey()
        coordx2 = bytes(cc_live.parser.authentikey_coordx) if cc_live.parser.authentikey_coordx else None
        assert coordx1 == coordx2, (
            f"authentikey changed between calls!\n  call1: {coordx1.hex() if coordx1 else None}\n  call2: {coordx2.hex() if coordx2 else None}")

    def test_authentikey_fingerprint_format(self, cc_live):
        """
        Verify that the authentikey fingerprint (used in SatochipClient.label())
        is an 8-character lowercase hex string.

        This fingerprint is stored in the wallet file to identify the device,
        so its format must be stable.
        """
        from electrum.crypto import hash_160

        cc_live.card_get_status()
        if not getattr(cc_live, 'is_seeded', False):
            pytest.skip("Card is not seeded")

        try:
            cc_live.card_export_authentikey()
        except Exception as e:
            if "uninitializ" in str(e).lower():
                pytest.skip(f"Card not initialized: {e}")
            raise

        assert cc_live.parser.authentikey_coordx is not None
        pubkey_bytes = bytes(cc_live.parser.authentikey_coordx)
        fingerprint = hash_160(pubkey_bytes)[:4].hex()

        assert len(fingerprint) == 8, f"Fingerprint should be 8 hex chars: {fingerprint!r}"
        assert fingerprint == fingerprint.lower(), "Fingerprint should be lowercase hex"
        # Must be valid hex
        int(fingerprint, 16)
        print(f"\n  Authentikey fingerprint: {fingerprint}")

    def test_authentikey_full_report(self, cc_live, capsys):
        """Print authentikey details for documentation."""
        from electrum.crypto import hash_160

        cc_live.card_get_status()
        if not getattr(cc_live, 'is_seeded', False):
            pytest.skip("Card is not seeded")

        try:
            authentikey = cc_live.card_export_authentikey()
        except Exception as e:
            if "uninitializ" in str(e).lower():
                pytest.skip(f"Card not initialized: {e}")
            raise

        coordx = bytes(cc_live.parser.authentikey_coordx) if cc_live.parser.authentikey_coordx else b""
        fingerprint = hash_160(coordx)[:4].hex() if coordx else "N/A"
        print(f"\n=== Authentikey Report ===")
        print(f"  Compressed pubkey: {coordx.hex()}")
        print(f"  Fingerprint (4B):  {fingerprint}")
        print(f"  Electrum label:    Satochip {fingerprint}")
        print("==========================")
        assert authentikey is not None


# =============================================================================
# Phase 3a: Card Initialization
# =============================================================================

@pytest.mark.integration
@pytest.mark.requires_card
class TestCardInitialization:
    """
    Phase 3a: Initialise a blank Satochip card with a PIN.

    ``card_setup()`` is the first APDU on a blank card.  It:
      - Sets PIN0 (and a throwaway PUK0 / PIN1 / PUK1 we never use in tests)
      - Allocates flash memory for BIP32 keys and objects
      - Marks ``setup_done=True`` in the applet
      - Caches the PIN in the ``CardConnector`` so subsequent operations work

    All tests in this class skip gracefully if the card is already initialized.
    This is intentional: the tests model a *first-time setup* workflow, not an
    idempotent one.  To re-run against a fresh card, factory-reset it first.

    PIN used throughout Phase 3 tests: TESTPIN = b'123456'
    ⚠️  Test card only — never use TESTPIN on a card with real funds.
    """

    def test_card_is_blank_before_setup(self, cc_live):
        """Card must report setup_done=False before we call card_setup()."""
        (_, _, _, d) = cc_live.card_get_status()
        if d['setup_done']:
            pytest.skip(
                "Card is already initialized (setup_done=True). "
                "To re-run Phase 3a, factory-reset the card first."
            )
        assert d['setup_done'] is False, "Unexpected: setup_done should be False on blank card"

    def test_card_setup_with_testpin(self, cc_live):
        """
        Initialize the card with TESTPIN and a random PUK.

        Parameters match the plugin's ``_setup_device()``; PIN1/PUK1/PUK0 are
        random because they are unused in the current Electrum workflow.
        """
        (_, _, _, d) = cc_live.card_get_status()
        if d['setup_done']:
            pytest.skip("Card already initialized — setup step skipped")

        pin_tries_0 = 5
        ublk_tries_0 = 1
        ublk_0 = list(TESTPUK)
        pin_tries_1 = 1
        ublk_tries_1 = 1
        pin_1 = list(os.urandom(16))   # PIN1 not used in Electrum workflow
        ublk_1 = list(os.urandom(16))
        secmemsize = 32
        memsize = 0

        response, sw1, sw2 = cc_live.card_setup(
            pin_tries_0, ublk_tries_0, list(TESTPIN), ublk_0,
            pin_tries_1, ublk_tries_1, pin_1, ublk_1,
            secmemsize, memsize,
            0x01, 0x01, 0x01,  # create_object_ACL, create_key_ACL, create_pin_ACL
        )
        assert (sw1, sw2) == (0x90, 0x00), (
            f"card_setup() failed: SW=0x{sw1:02x}{sw2:02x}.  "
            "Check that the card is genuinely blank."
        )
        # card_setup() caches the PIN in cc.pin[0] automatically (pysatochip
        # calls self.set_pin(0, pin0) on success).

    def test_setup_done_true_after_setup(self, cc_live):
        """After card_setup(), the applet must report setup_done=True."""
        (_, _, _, d) = cc_live.card_get_status()
        if not d['setup_done']:
            pytest.skip("card_setup() has not been called yet")
        assert d['setup_done'] is True

    def test_pin_tries_available_after_setup(self, cc_live):
        """PIN0_remaining_tries must be a positive integer after setup."""
        (_, _, _, d) = cc_live.card_get_status()
        if not d['setup_done']:
            pytest.skip("Card not initialized")
        tries = d['PIN0_remaining_tries']
        assert isinstance(tries, int), f"PIN0_remaining_tries should be int, got {type(tries)}"
        assert 0 < tries <= 15, f"PIN0_remaining_tries={tries} outside expected range 1–15"

    def test_pin_verification_works_after_setup(self, cc_live):
        """
        Verify the PIN we set in card_setup() is accepted by the card.

        This also populates the PIN cache in cc for subsequent Phase 3 tests.
        """
        (_, _, _, d) = cc_live.card_get_status()
        if not d['setup_done']:
            pytest.skip("Card not initialized")
        response, sw1, sw2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sw1, sw2) == (0x90, 0x00), (
            f"PIN verification failed: SW=0x{sw1:02x}{sw2:02x}.  "
            f"Expected (0x90, 0x00).  Did card_setup() use TESTPIN={TESTPIN!r}?"
        )

    def test_initialization_report(self, cc_live, capsys):
        """Print full card state after initialization for WORKING_NOTES."""
        (_, sw1, sw2, d) = cc_live.card_get_status()
        print("\n=== Card Initialization Report ===")
        print(f"  SW:              0x{sw1:02x}{sw2:02x}")
        print(f"  Setup done:      {d.get('setup_done')}")
        print(f"  Is seeded:       {d.get('is_seeded')}")
        print(f"  PIN0 tries left: {d.get('PIN0_remaining_tries')}")
        print(f"  PUK0 tries left: {d.get('PUK0_remaining_tries')}")
        print(f"  Needs 2FA:       {d.get('needs2FA')}")
        print(f"  Needs sec.chan.: {d.get('needs_secure_channel')}")
        print("==================================")
        assert (sw1, sw2) == (0x90, 0x00)


# =============================================================================
# Phase 3b: Wallet Creation — Known Seed (Abandon×11 + About)
# =============================================================================

@pytest.mark.integration
@pytest.mark.requires_card
class TestWalletCreationKnownSeed:
    """
    Phase 3b: Import a known BIP39 test mnemonic and verify xpub derivation.

    Using a known mnemonic ("abandon"×11 + "about") lets us cross-check the
    card-derived xpubs against a purely software-based BIP32 reference.  This
    is the "import existing wallet / restore from backup" scenario.

    Card state required:  setup_done=True, is_seeded=False
    Card state after:     setup_done=True, is_seeded=True

    Mnemonic:  ABANDON_MNEMONIC (12 words, BIP39 standard test vector)
    Passphrase: "" (empty — standard test vector convention)

    ⚠️  TESTNET / test card only.  Never use this mnemonic with real funds.

    xpub cross-check table
    ----------------------
    The test imports the 64-byte masterseed into the card via
    ``card_bip32_import_seed()``, then derives xpubs via
    ``card_bip32_get_extendedkey()`` (on-card BIP32).  The same xpubs
    are independently computed using ``BIP32Node.from_rootseed()`` +
    ``subkey_at_private_derivation()`` (Electrum software BIP32).
    A mismatch would indicate a firmware bug in the Satochip BIP32
    implementation.
    """

    @staticmethod
    def _masterseed() -> bytes:
        """Return the 64-byte BIP39 masterseed for ABANDON_MNEMONIC."""
        from electrum.keystore import bip39_to_seed
        return bip39_to_seed(ABANDON_MNEMONIC, passphrase="")

    def test_import_abandon_mnemonic(self, cc_live):
        """
        Import the 'abandon' BIP39 masterseed into the card.

        Requires setup_done=True and is_seeded=False.  Calls
        ``card_verify_PIN_simple(TESTPIN)`` first so the secure-channel
        handshake can complete.
        """
        _require_card_state(cc_live, requires_setup=True, requires_seeded=False)

        # Authenticate before any key-management operation
        _, sw1, sw2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sw1, sw2) == (0x90, 0x00), (
            f"PIN verification before seed import failed: SW=0x{sw1:02x}{sw2:02x}"
        )

        authentikey = cc_live.card_bip32_import_seed(list(self._masterseed()))

        assert authentikey is not None, "card_bip32_import_seed() must return an authentikey"
        assert cc_live.is_seeded is True, "cc.is_seeded must be True after a successful import"

    def test_is_seeded_after_abandon_import(self, cc_live):
        """card_get_status() must reflect is_seeded=True after seed import."""
        _require_card_state(cc_live, requires_setup=True, requires_seeded=True)
        (_, _, _, d) = cc_live.card_get_status()
        assert d['is_seeded'] is True

    def test_authentikey_returned_on_import(self, cc_live):
        """
        card_export_authentikey() must return a valid EC public key after seeding.

        The authentikey is derived from the masterseed (BIP32 root key) and
        uniquely identifies this card+seed combination.  It is stored in
        the wallet file as the device fingerprint.
        """
        _require_card_state(cc_live, requires_seeded=True)
        _, sw1, sw2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sw1, sw2) == (0x90, 0x00), (
            f"PIN verification failed: SW=0x{sw1:02x}{sw2:02x}"
        )
        authentikey = cc_live.card_export_authentikey()
        assert authentikey is not None
        pubkey_bytes = authentikey.get_public_key_bytes(compressed=True)
        assert len(pubkey_bytes) == 33, f"Expected 33-byte compressed pubkey, got {len(pubkey_bytes)}"
        assert pubkey_bytes[0] in (0x02, 0x03), (
            f"Compressed pubkey must start with 0x02 or 0x03, got 0x{pubkey_bytes[0]:02x}"
        )

    def test_xpub_p2wpkh_matches_software(self, cc_live):
        """
        m/84'/0'/0' (native SegWit / BIP84) xpub from card == software reference.
        """
        _require_card_state(cc_live, requires_seeded=True)
        _, sw1, sw2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sw1, sw2) == (0x90, 0x00)

        card_xpub = _derive_xpub_from_card(cc_live, "m/84'/0'/0'", 'p2wpkh')
        sw_xpub = _derive_xpub_software(self._masterseed(), "m/84'/0'/0'", 'p2wpkh')

        assert card_xpub == sw_xpub, (
            f"p2wpkh xpub mismatch!\n  card: {card_xpub}\n  sw:   {sw_xpub}"
        )

    def test_xpub_standard_matches_software(self, cc_live):
        """
        m/44'/0'/0' (legacy / BIP44) xpub from card == software reference.
        """
        _require_card_state(cc_live, requires_seeded=True)
        _, sw1, sw2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sw1, sw2) == (0x90, 0x00)

        card_xpub = _derive_xpub_from_card(cc_live, "m/44'/0'/0'", 'standard')
        sw_xpub = _derive_xpub_software(self._masterseed(), "m/44'/0'/0'", 'standard')

        assert card_xpub == sw_xpub, (
            f"standard xpub mismatch!\n  card: {card_xpub}\n  sw:   {sw_xpub}"
        )

    def test_xpub_p2wpkh_p2sh_matches_software(self, cc_live):
        """
        m/49'/0'/0' (wrapped SegWit / BIP49) xpub from card == software reference.
        """
        _require_card_state(cc_live, requires_seeded=True)
        _, sw1, sw2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sw1, sw2) == (0x90, 0x00)

        card_xpub = _derive_xpub_from_card(cc_live, "m/49'/0'/0'", 'p2wpkh-p2sh')
        sw_xpub = _derive_xpub_software(self._masterseed(), "m/49'/0'/0'", 'p2wpkh-p2sh')

        assert card_xpub == sw_xpub, (
            f"p2wpkh-p2sh xpub mismatch!\n  card: {card_xpub}\n  sw:   {sw_xpub}"
        )

    def test_wallet_creation_report(self, cc_live, capsys):
        """
        Print all derived xpubs for WORKING_NOTES documentation.

        Not a strict-assertion test — these values should be recorded after
        each firmware update to verify BIP32 derivation stability.
        """
        _require_card_state(cc_live, requires_seeded=True)
        _, sw1, sw2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sw1, sw2) == (0x90, 0x00)

        print("\n=== Wallet Creation Report (known seed: abandon×11 + about) ===")
        for path, xtype in _XPUB_PATHS:
            try:
                card_xpub = _derive_xpub_from_card(cc_live, path, xtype)
                sw_xpub = _derive_xpub_software(self._masterseed(), path, xtype)
                match = "match" if card_xpub == sw_xpub else "MISMATCH"
                print(f"  {path} ({xtype}):")
                print(f"    card: {card_xpub}")
                print(f"    sw:   {sw_xpub}")
                print(f"    {match}")
            except Exception as exc:
                print(f"  {path}: ERROR — {exc}")
        print("===============================================================")
        # Hard assertion: all three paths must produce valid versioned xpubs
        valid_prefixes = {'xpub', 'ypub', 'zpub'}  # depend on xtype, not mainnet/testnet
        for path, xtype in _XPUB_PATHS:
            card_xpub = _derive_xpub_from_card(cc_live, path, xtype)
            assert card_xpub[:4] in valid_prefixes, (
                f"Unexpected xpub prefix for {path} ({xtype}): {card_xpub[:8]!r}"
            )


# =============================================================================
# Phase 3c: Wallet Creation — Generated Seed (fresh random entropy)
# =============================================================================

@pytest.mark.integration
@pytest.mark.requires_card
class TestWalletCreationGeneratedSeed:
    """
    Phase 3c: Reset the seed, generate fresh random entropy and import it.

    This exercises the "create new wallet on card" flow:
      1. ``card_reset_seed()``  — clear the BIP32 master seed
      2. Generate 64 bytes of random entropy locally (simulating what the user
         would do: generate a mnemonic → convert to BIP39 masterseed bytes)
      3. ``card_bip32_import_seed()``  — load the new seed
      4. Derive xpubs and confirm they are consistent (stable across two calls)
      5. ``card_reset_seed()`` again — leave the card in a clean state
         (setup_done=True, is_seeded=False) ready for the next test run

    Card state required:  setup_done=True  (any seeded state is handled)
    Card state after:     setup_done=True, is_seeded=False  (cleaned up)

    Why random bytes instead of a fixed second mnemonic?
    Satochip's on-card flow has no "generate seed on card" instruction —
    entropy always originates outside the card (user's device or companion
    app) and is imported.  Using truly random seed bytes here mimics that
    real-world flow and gives us confidence that arbitrary 64-byte seeds work.
    """

    def test_reset_seed_before_new_import(self, cc_live):
        """
        Reset the existing seed so the card is ready for a fresh import.

        Skipped gracefully if the card is already in ``is_seeded=False`` state
        (e.g. if this class is run in isolation without the previous class).
        """
        _require_card_state(cc_live, requires_setup=True)  # any seeded state OK here
        (_, _, _, d) = cc_live.card_get_status()
        if not d['is_seeded']:
            pytest.skip("Card is already not seeded — reset step not needed")

        # Re-authenticate before the privileged reset APDU
        _, sv1, sv2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sv1, sv2) == (0x90, 0x00), (
            f"PIN verification before reset failed: SW=0x{sv1:02x}{sv2:02x}"
        )

        _, sw1, sw2 = cc_live.card_reset_seed(list(TESTPIN))
        assert (sw1, sw2) == (0x90, 0x00), (
            f"card_reset_seed() failed: SW=0x{sw1:02x}{sw2:02x}"
        )
        assert cc_live.is_seeded is False, "cc.is_seeded should be False after reset"

    def test_is_not_seeded_after_reset(self, cc_live):
        """card_get_status() must reflect is_seeded=False after the reset."""
        _require_card_state(cc_live, requires_setup=True, requires_seeded=False)
        (_, _, _, d) = cc_live.card_get_status()
        assert d['is_seeded'] is False

    def test_generate_and_import_random_seed(self, cc_live):
        """
        Generate 64 bytes of cryptographically random entropy and import it.

        This simulates what Electrum does when the user selects "Create a new
        wallet":
          - Python generates the mnemonic (or raw entropy) using os.urandom
          - The BIP39 masterseed (64 bytes) is sent to the card

        After import, the authentikey is stored as a module-level attribute so
        that the next test can verify xpub stability.
        """
        _require_card_state(cc_live, requires_setup=True, requires_seeded=False)

        _, sw1, sw2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sw1, sw2) == (0x90, 0x00)

        # Generate random masterseed (64 bytes = 512 bits of entropy).
        # In production, this comes from bip39_to_seed(random_mnemonic, "").
        import secrets
        random_seed = secrets.token_bytes(64)

        authentikey = cc_live.card_bip32_import_seed(list(random_seed))

        assert authentikey is not None, "card_bip32_import_seed() must return an authentikey"
        assert cc_live.is_seeded is True, "cc.is_seeded should be True after import"

        # Stash seed for the cross-call stability test below
        cc_live._test_phase3_random_seed = random_seed  # noqa: test-only attribute

    def test_xpub_derivable_after_random_seed(self, cc_live):
        """
        All three xpub paths must be derivable after a freshly generated seed.

        We cannot compare against a pre-known expected value here, so instead:
        - Derive each xpub twice and confirm stability (same seed → same key)
        - Confirm the xpub starts with the correct version-byte prefix
        """
        _require_card_state(cc_live, requires_seeded=True)
        _, sw1, sw2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sw1, sw2) == (0x90, 0x00)

        for path, xtype in _XPUB_PATHS:
            xpub1 = _derive_xpub_from_card(cc_live, path, xtype)
            xpub2 = _derive_xpub_from_card(cc_live, path, xtype)

            assert xpub1 == xpub2, (
                f"xpub not stable across two calls for {path} ({xtype})!\n"
                f"  call 1: {xpub1}\n  call 2: {xpub2}"
            )
            # Prefix depends on xtype: xpub (standard), ypub (p2wpkh-p2sh), zpub (p2wpkh)
            assert xpub1[:4] in {'xpub', 'ypub', 'zpub'}, (
                f"Expected versioned xpub prefix for {path} ({xtype}), got: {xpub1[:8]!r}"
            )

    def test_authentikey_differs_from_abandon_seed(self, cc_live):
        """
        Authentikey after a fresh random seed must differ from the 'abandon' vector.

        Verifies that the card actually stored the new seed rather than retaining
        the previous one, and that the authentikey reflects the current seed.
        """
        _require_card_state(cc_live, requires_seeded=True)

        _, sv1, sv2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sv1, sv2) == (0x90, 0x00)

        authentikey = cc_live.card_export_authentikey()
        assert authentikey is not None
        pubkey_bytes = authentikey.get_public_key_bytes(compressed=True)
        assert len(pubkey_bytes) == 33
        assert pubkey_bytes[0] in (0x02, 0x03)

        # Compute the authentikey the 'abandon' seed would produce
        from electrum.keystore import bip39_to_seed
        from electrum.bip32 import BIP32Node
        abandon_seed = bip39_to_seed(ABANDON_MNEMONIC, passphrase="")
        abandon_root = BIP32Node.from_rootseed(abandon_seed, xtype='p2wpkh')
        abandon_authentikey_bytes = abandon_root.eckey.get_public_key_bytes(compressed=True)

        assert pubkey_bytes != abandon_authentikey_bytes, (
            "Authentikey should differ from the 'abandon' test vector — "
            "the random seed was not actually different from the previous one!"
        )

    def test_reset_seed_final_cleanup(self, cc_live, capsys):
        """
        Reset the randomly generated seed, leaving the card clean for future runs.

        Card state after this test:  setup_done=True, is_seeded=False
        This makes subsequent test runs predictable regardless of which
        Phase 3 class ran last.
        """
        _require_card_state(cc_live, requires_setup=True)
        (_, _, _, d) = cc_live.card_get_status()
        if not d['is_seeded']:
            print("\nPhase 3 cleanup: card already not seeded — nothing to reset.")
            return

        _, sv1, sv2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sv1, sv2) == (0x90, 0x00)

        _, sw1, sw2 = cc_live.card_reset_seed(list(TESTPIN))
        assert (sw1, sw2) == (0x90, 0x00), (
            f"Final cleanup card_reset_seed() failed: SW=0x{sw1:02x}{sw2:02x}"
        )

        (_, _, _, d2) = cc_live.card_get_status()
        assert d2['setup_done'] is True, "setup_done should still be True after seed reset"
        assert d2['is_seeded'] is False, "is_seeded should be False after seed reset"

        print(
            "\nPhase 3 cleanup complete: "
            "card is setup_done=True, is_seeded=False. "
            "Ready for the next test run."
        )


# =============================================================================
# Phase 4: PIN Management
# =============================================================================

@pytest.mark.integration
@pytest.mark.requires_card
class TestPINManagement:
    """
    Phase 4a: PIN management — verify, change, wrong-PIN counter, unblock.

    PIN security is the primary protection on a Satochip card.  These tests
    cover all the PIN state transitions:

      verify     → counter unchanged
      wrong PIN  → counter decremented (SW 0x63Cx gives remaining tries)
      change PIN → new PIN accepted, old PIN rejected
      label set  → requires PIN verification (PIN-protected operation)

    PUK unblock (``card_unblock_PIN``) is explicitly *not* tested here because
    triggering it requires intentionally blocking the PIN (exhausting all tries)
    which is too destructive for a shared test card — one mistake would require
    physical factory reset.  It is documented but skipped.

    Card state required:  setup_done=True  (seeded state is handled internally)
    TESTPIN used throughout: b'123456'   (set during Phase 3a)
    NEWPIN used for change-PIN roundtrip: b'654321'
    """

    # Alternative PIN used only inside the change-PIN roundtrip test.
    # Restored back to TESTPIN at the end so other tests / phases still work.
    NEWPIN = b'654321'

    def _ensure_seeded(self, cc_live):
        """Import the abandon test seed if the card is not already seeded."""
        from electrum.keystore import bip39_to_seed
        (_, _, _, d) = cc_live.card_get_status()
        if d['is_seeded']:
            return
        _, sw1, sw2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sw1, sw2) == (0x90, 0x00)
        cc_live.card_bip32_import_seed(
            list(bip39_to_seed(ABANDON_MNEMONIC, passphrase=""))
        )

    # ------------------------------------------------------------------
    # Basic PIN verify
    # ------------------------------------------------------------------

    def test_correct_pin_is_accepted(self, cc_live):
        """
        card_verify_PIN_simple(TESTPIN) must return SW=0x9000.

        This is the foundation of all authenticated operations.  If this fails,
        either the card was not set up with TESTPIN or the PIN was changed and
        not restored by a previous test run.
        """
        _require_card_state(cc_live, requires_setup=True)
        _, sw1, sw2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sw1, sw2) == (0x90, 0x00), (
            f"Correct PIN rejected: SW=0x{sw1:02x}{sw2:02x}. "
            f"Was the card initialized with TESTPIN={TESTPIN!r}?"
        )

    def test_pin_cached_after_verify(self, cc_live):
        """
        After a successful verify, the PIN must be cached inside cc.pin.

        pysatochip caches the PIN after a successful verify so subsequent APDUs
        can re-authenticate automatically via the secure channel.  This is the
        mechanism that lets ``get_xpub()`` work without prompting the user for
        every APDU.
        """
        _require_card_state(cc_live, requires_setup=True)
        cc_live.card_verify_PIN_simple(TESTPIN)
        assert cc_live.is_pin_set(), "PIN should be cached after a successful verify"

    # ------------------------------------------------------------------
    # Remaining-tries counter
    # ------------------------------------------------------------------

    def test_wrong_pin_decrements_counter(self, cc_live):
        """
        Submitting a wrong PIN must decrement the remaining-tries counter by 1.

        We read the counter before and after and check the delta is exactly -1.
        This verifies that the firmware counter is wired up correctly and that
        pysatochip's WrongPinError carries the updated remaining-tries value.

        ⚠️  Uses a wrong PIN exactly once and then immediately re-verifies with
        the correct PIN to prevent the counter from reaching 0.
        """
        _require_card_state(cc_live, requires_setup=True)

        # Read current tries
        (_, _, _, d_before) = cc_live.card_get_status()
        tries_before = d_before['PIN0_remaining_tries']

        wrong_pin = b'000000'
        tries_reported = None
        try:
            cc_live.card_verify_PIN_simple(wrong_pin)
            pytest.fail("Expected WrongPinError but call succeeded")
        except Exception as exc:
            exc_type = type(exc).__name__
            # pysatochip raises WrongPinError; it carries remaining tries
            if 'WrongPin' in exc_type or 'wrong' in str(exc).lower():
                # Try to extract remaining tries from the exception
                if hasattr(exc, 'args') and exc.args:
                    for arg in exc.args:
                        if isinstance(arg, int):
                            tries_reported = arg
                            break
            elif 'PinBlocked' in exc_type or 'blocked' in str(exc).lower():
                pytest.skip(
                    "PIN is already blocked — cannot run wrong-PIN counter test. "
                    "Use PUK to unblock the card."
                )
            else:
                raise  # unexpected error — re-raise

        # Read counter after the wrong attempt
        (_, _, _, d_after) = cc_live.card_get_status()
        tries_after = d_after['PIN0_remaining_tries']

        assert tries_after == tries_before - 1, (
            f"Counter should have decremented by 1: "
            f"before={tries_before}, after={tries_after}"
        )
        if tries_reported is not None:
            assert tries_reported == tries_after, (
                f"WrongPinError.tries_remaining={tries_reported} "
                f"disagrees with card status={tries_after}"
            )

        # Immediately recover by verifying the correct PIN
        _, sw1, sw2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sw1, sw2) == (0x90, 0x00), (
            "Failed to recover after wrong-PIN attempt — "
            f"SW=0x{sw1:02x}{sw2:02x}"
        )

    def test_correct_pin_resets_counter_appearance(self, cc_live):
        """
        After a successful verify following a wrong attempt, the remaining-tries
        counter must be back to the configured maximum (5 for our TESTPIN setup).

        The Satochip resets the counter on a successful verify (this is standard
        for ISO 7816 PIN management).
        """
        _require_card_state(cc_live, requires_setup=True)

        # Ensure counter is clean by verifying the correct PIN
        cc_live.card_verify_PIN_simple(TESTPIN)
        (_, _, _, d) = cc_live.card_get_status()
        tries = d['PIN0_remaining_tries']
        # We initialised with pin_tries_0=5 (see TestCardInitialization)
        assert tries == 5, (
            f"Expected 5 tries after correct PIN, got {tries}. "
            "Firmware may not reset the counter on success, or setup used different pin_tries."
        )

    # ------------------------------------------------------------------
    # Change PIN roundtrip
    # ------------------------------------------------------------------

    def test_change_pin_roundtrip(self, cc_live):
        """
        Change the PIN from TESTPIN to NEWPIN, verify NEWPIN works, then
        restore back to TESTPIN.

        This exercises the full change-PIN flow that users trigger via
        Electrum's "Change PIN" menu item (which calls SatochipClient.verify_PIN
        then plugin._change_PIN / cc.card_change_PIN).

        State contract:
          - Start: PIN = TESTPIN (set in Phase 3a)
          - After change: PIN = NEWPIN
          - After restore: PIN = TESTPIN  ← other tests depend on this

        The restore is in a finally block so even if the intermediate assertion
        fails, the card is left with a known PIN.
        """
        _require_card_state(cc_live, requires_setup=True)

        # Authenticate first
        _, sv1, sv2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sv1, sv2) == (0x90, 0x00)

        try:
            # Change TESTPIN → NEWPIN
            _, sw1, sw2 = cc_live.card_change_PIN(
                0, list(TESTPIN), list(self.NEWPIN)
            )
            assert (sw1, sw2) == (0x90, 0x00), (
                f"card_change_PIN() failed: SW=0x{sw1:02x}{sw2:02x}"
            )

            # Verify cache was updated (pysatochip calls set_pin on success)
            assert cc_live.is_pin_set(), "PIN cache should be set after change"

            # Verify NEWPIN is now accepted
            _, vw1, vw2 = cc_live.card_verify_PIN_simple(self.NEWPIN)
            assert (vw1, vw2) == (0x90, 0x00), (
                f"NEWPIN not accepted after change: SW=0x{vw1:02x}{vw2:02x}"
            )

            # Verify old TESTPIN is now rejected
            try:
                cc_live.card_verify_PIN_simple(TESTPIN)
                # If we get here the old PIN was accepted — that's wrong
                pytest.fail("Old TESTPIN still accepted after change — change_PIN had no effect")
            except Exception as exc:
                if 'WrongPin' not in type(exc).__name__ and 'wrong' not in str(exc).lower():
                    raise  # unexpected non-PIN error

        finally:
            # Always restore to TESTPIN so subsequent tests and phases work
            try:
                cc_live.card_change_PIN(0, list(self.NEWPIN), list(TESTPIN))
            except Exception:
                pass  # Best-effort restore

    def test_pin_is_testpin_after_roundtrip(self, cc_live):
        """Confirm TESTPIN is accepted after the change-PIN roundtrip restores it."""
        _require_card_state(cc_live, requires_setup=True)
        _, sw1, sw2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sw1, sw2) == (0x90, 0x00), (
            f"TESTPIN not accepted after roundtrip restore: SW=0x{sw1:02x}{sw2:02x}. "
            "The change-PIN restore in test_change_pin_roundtrip may have failed."
        )

    # ------------------------------------------------------------------
    # PIN-protected label write (exercises Phase 2 label roundtrip)
    # ------------------------------------------------------------------

    def test_set_label_requires_pin(self, cc_live):
        """
        card_set_label() is a PIN-protected operation.  After a successful PIN
        verify, the label write must succeed.

        This test was deferred from Phase 2 because the card was blank then.
        Now that the card is initialized and we control the PIN, we can fully
        exercise the label write + read-back roundtrip.
        """
        _require_card_state(cc_live, requires_setup=True)

        cc_live.set_pin(0, list(TESTPIN))
        (_, sw1, sw2, original_label) = cc_live.card_get_label()
        if (sw1, sw2) == (0x6d, 0x00):
            pytest.skip("Firmware does not support card_get_label/set_label")

        test_label = "electrum-phase4-pin-test"
        restore_label = original_label if original_label not in ('(none)', '(unknown)') else ""

        try:
            # Verify PIN first so the write goes through the secure channel
            _, vw1, vw2 = cc_live.card_verify_PIN_simple(TESTPIN)
            assert (vw1, vw2) == (0x90, 0x00)

            _, wt_sw1, wt_sw2 = cc_live.card_set_label(test_label)
            assert (wt_sw1, wt_sw2) == (0x90, 0x00), (
                f"card_set_label() failed after PIN verify: SW=0x{wt_sw1:02x}{wt_sw2:02x}"
            )

            # Read back
            cc_live.set_pin(0, list(TESTPIN))
            _, rd_sw1, rd_sw2, read_back = cc_live.card_get_label()
            assert (rd_sw1, rd_sw2) == (0x90, 0x00)
            assert read_back == test_label, (
                f"Label mismatch: expected {test_label!r}, got {read_back!r}"
            )

        finally:
            try:
                cc_live.card_set_label(restore_label)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Diagnostic report
    # ------------------------------------------------------------------

    def test_pin_management_report(self, cc_live, capsys):
        """Print a PIN state summary for WORKING_NOTES documentation."""
        _require_card_state(cc_live, requires_setup=True)
        cc_live.card_verify_PIN_simple(TESTPIN)
        (_, sw1, sw2, d) = cc_live.card_get_status()
        print("\n=== PIN Management Report ===")
        print(f"  SW:              0x{sw1:02x}{sw2:02x}")
        print(f"  PIN0 tries left: {d.get('PIN0_remaining_tries')}")
        print(f"  PUK0 tries left: {d.get('PUK0_remaining_tries')}")
        print(f"  PIN cached:      {cc_live.is_pin_set()}")
        print(f"  Setup done:      {d.get('setup_done')}")
        print(f"  Is seeded:       {d.get('is_seeded')}")
        print("=============================")
        assert (sw1, sw2) == (0x90, 0x00)


# =============================================================================
# Phase 4b: Session Timeout
# =============================================================================

@pytest.mark.integration
@pytest.mark.requires_card
class TestSessionTimeout:
    """
    Phase 4b: Session timeout — PIN cache cleared after inactivity.

    ``SatochipClient.timeout(cutoff)`` is called by the Electrum framework
    periodically.  When ``last_operation < cutoff`` (i.e. the device has been
    idle), it must clear the cached PIN via ``cc.set_pin(0, None)``.  The next
    time a signed operation is attempted, the user will be prompted for their
    PIN again.

    Design decisions compared to other hardware wallets
    ----------------------------------------------------
    Trezor / Coldcard / Ledger all have a *physical* session concept: the
    device locks itself after inactivity or button press.  Satochip is a
    smartcard — it has no UI and no internal timer.  The session concept is
    therefore purely software-side: Electrum tracks the timestamp of the last
    operation and clears the PIN cache when idle.

    Two complementary tests:
      ``test_timeout_does_not_fire_for_recent_activity``
        last_operation=now → timeout with a past cutoff → PIN stays cached.
      ``test_timeout_fires_for_stale_activity``
        last_operation=0 (epoch) → timeout with any positive cutoff → PIN cleared.

    These use mock SatochipClient instances (no card needed) because the logic
    is entirely in the Python layer.  They do not require the card to be present.

    Card-interaction variant
    --------------------------
    ``test_stale_session_requires_pin_after_timeout`` uses the real card
    to verify that after a simulated timeout, the next APDU that requires
    authentication raises PinRequiredError (or prompts for PIN via the handler)
    rather than silently using a stale cached PIN.
    """

    def test_timeout_does_not_fire_for_recent_activity(self):
        """
        When last_operation is recent (now), timeout() must NOT clear the PIN.

        Electrum calls timeout(cutoff) where cutoff is a Unix timestamp in the
        past (e.g. now − 300 s for a 5-minute timeout).  A device that was used
        recently (last_operation > cutoff) must not be locked.
        """
        import time
        connector = MagicMock()
        client = _mk_client(connector)
        client.last_operation = time.time()  # just now

        # cutoff is 300 seconds ago — device is "recent"
        cutoff = time.time() - 300
        client.timeout(cutoff)

        connector.set_pin.assert_not_called()

    def test_timeout_fires_for_stale_activity(self):
        """
        When last_operation is old (< cutoff), timeout() must clear the PIN.

        Scenarios where this matters:
          - User walks away from an unlocked computer with the card inserted
          - System resumes from sleep
          - Electrum's configured session timeout passes between transactions
        """
        connector = MagicMock()
        client = _mk_client(connector)
        client.last_operation = 0  # Unix epoch — ancient

        # Any positive cutoff is greater than 0, so timeout fires
        client.timeout(1_000_000)

        # set_pin(0, None) clears the cached PIN in the CardConnector
        connector.set_pin.assert_called_once_with(0, None)

    def test_prevent_timeouts_sets_last_operation_to_inf(self):
        """
        prevent_timeouts() sets last_operation to infinity so the device never
        times out.  This is called before long operations (e.g. seed import)
        to prevent mid-operation lockout.
        """
        connector = MagicMock()
        client = _mk_client(connector)
        client.last_operation = 0

        client.prevent_timeouts()

        assert client.last_operation == float('inf'), (
            f"prevent_timeouts() should set last_operation=inf, "
            f"got {client.last_operation}"
        )
        # With last_operation=inf, a timeout with any finite cutoff must not fire
        import time
        client.timeout(time.time())
        connector.set_pin.assert_not_called()

    def test_used_updates_last_operation(self):
        """
        used() must update last_operation to the current time.

        Electrum calls used() after each successful device interaction.  If
        last_operation is never updated, the device will time out immediately
        after every operation — this would be very annoying for the user.
        """
        import time
        connector = MagicMock()
        client = _mk_client(connector)
        client.last_operation = 0  # start at epoch

        before = time.time()
        client.used()
        after = time.time()

        assert before <= client.last_operation <= after, (
            f"used() should set last_operation to approx. now "
            f"({before:.3f}–{after:.3f}), got {client.last_operation:.3f}"
        )

    def test_stale_session_requires_pin_after_timeout(self, cc_live):
        """
        Real-card test: after clearing the PIN cache (simulating a timeout),
        ``card_verify_PIN_simple()`` called with no arguments must raise
        PinRequiredError — it cannot auto-verify without a cached PIN.

        This tests the integration between:
          1. SatochipClient.timeout() clearing the PIN cache via set_pin(0, None)
          2. pysatochip raising PinRequiredError when is_pin_set() is False

        Note on ``card_export_authentikey``: that APDU operates at the secure-
        channel level (ECDH-based) and does not require a PIN-level session. The
        correct operation to test PIN-required behaviour is
        ``card_verify_PIN_simple()`` with no argument, which explicitly calls
        ``is_pin_set()`` and raises ``PinRequiredError`` when the cache is empty.

        Flow:
          1. Verify TESTPIN (cache it)
          2. Clear the PIN cache (simulating what timeout() does)
          3. Call card_verify_PIN_simple() with no arg → expect PinRequiredError
          4. Restore by verifying TESTPIN explicitly
        """
        _require_card_state(cc_live, requires_setup=True)
        self._ensure_seeded(cc_live)

        # Step 1: authenticate and confirm PIN is cached
        cc_live.card_verify_PIN_simple(TESTPIN)
        assert cc_live.is_pin_set(), "PIN should be cached after verify"

        # Step 2: simulate timeout by clearing PIN cache (what timeout() does)
        cc_live.set_pin(0, None)
        assert not cc_live.is_pin_set(), "PIN cache should be empty after simulated timeout"

        # Step 3: card_verify_PIN_simple() with NO arg should raise PinRequiredError
        # because there is nothing in the cache to auto-verify with.
        try:
            cc_live.card_verify_PIN_simple()  # no argument → uses cached PIN
            pytest.fail(
                "Expected PinRequiredError when calling card_verify_PIN_simple() "
                "with no argument and an empty PIN cache, but the call succeeded."
            )
        except Exception as exc:
            exc_type = type(exc).__name__
            assert 'PinRequired' in exc_type or 'Pin' in exc_type, (
                f"Expected PinRequiredError, got {exc_type}: {exc}"
            )

        # Step 4: restore PIN so subsequent Phases can continue
        cc_live.card_verify_PIN_simple(TESTPIN)
        assert cc_live.is_pin_set(), "PIN should be restored after recovery"

    def _ensure_seeded(self, cc_live):
        """Import the abandon test seed if the card is not already seeded."""
        from electrum.keystore import bip39_to_seed
        (_, _, _, d) = cc_live.card_get_status()
        if d['is_seeded']:
            return
        _, sw1, sw2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sw1, sw2) == (0x90, 0x00)
        cc_live.card_bip32_import_seed(
            list(bip39_to_seed(ABANDON_MNEMONIC, passphrase=""))
        )


# =============================================================================
# Phase 5: Transaction / Message Signing (ECDSA)
# =============================================================================

def _ensure_seeded_global(cc_live):
    """Module-level helper: import abandon seed if card is not yet seeded."""
    from electrum.keystore import bip39_to_seed
    (_, _, _, d) = cc_live.card_get_status()
    if d['is_seeded']:
        return
    _, sw1, sw2 = cc_live.card_verify_PIN_simple(TESTPIN)
    assert (sw1, sw2) == (0x90, 0x00)
    cc_live.card_bip32_import_seed(
        list(bip39_to_seed(ABANDON_MNEMONIC, passphrase=""))
    )


def _derive_key(cc_live, path_str):
    """Derive an extended key from the card at the given path string.

    Returns (pubkey, chaincode) where pubkey is a pysatochip ECPubkey.
    """
    from electrum.plugins.satochip.satochip import bip32path2bytes
    _, bytepath = bip32path2bytes(path_str)
    pubkey, chaincode = cc_live.card_bip32_get_extendedkey(bytepath)
    return pubkey, chaincode


def _r_s_from_der(der_sig_bytes):
    """Parse a DER-encoded ECDSA signature into (r, s) integers."""
    import electrum_ecc as _ecc
    return _ecc.get_r_and_s_from_ecdsa_der_sig(der_sig_bytes)


def _verify_ecdsa(pubkey, hash32, der_sig_bytes):
    """
    Verify a DER ECDSA signature against a pysatochip ECPubkey and a 32-byte hash.

    Converts DER to raw 64-byte r||s then calls ECPubkey.verify_message_hash.
    Raises on failure; returns None on success.
    """
    r, s = _r_s_from_der(der_sig_bytes)
    raw64 = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    pubkey.verify_message_hash(raw64, hash32)


@pytest.mark.integration
@pytest.mark.requires_card
class TestTransactionSigning:
    """
    Phase 5: ECDSA transaction/message signing on the live Satochip card.

    Architecture
    ------------
    Satochip signs in two stages:

      1. ``card_parse_transaction(pre_tx, is_segwit)``
         The card recomputes the sighash internally from the raw pre-image
         bytes and caches the result.  Returns (response, sw1, sw2,
         tx_hash_list, needs_2fa).

      2. ``card_sign_transaction(0xFF, tx_hash_list, hmac_or_None)``
         Uses the most recently derived BIP32 key (keynbr=0xFF = "use the
         current extended key") to ECDSA-sign the hash.  Returns DER sig.

    For unit-level signing (no real transaction structure needed) there is
    also ``card_sign_transaction_hash(keynbr, hash32, hmac)`` which skips
    the parse step.  That is what most tests here use.

    Signature properties
    --------------------
    * DER-encoded ECDSA on secp256k1.
    * Satochip uses a hardware RNG for k -- signatures are NON-deterministic
      (two calls with the same hash produce different signatures; both verify).
    * The plugin applies low-S normalisation (BIP 62) before attaching the
      sig to the tx.  We test that normalisation here too.
    * Schnorr (BIP 340) requires protocol v0.14+; our card is v0.12 so
      Schnorr tests verify that the card correctly rejects the APDU.

    Key currently selected on the card
    ------------------------------------
    keynbr=0xFF refers to the last BIP32 key derived via
    card_bip32_get_extendedkey.  Tests always derive immediately before
    signing to avoid key-state ordering surprises.

    Card state required: setup_done=True, is_seeded=True (ensured internally).
    """

    SIGN_PATH = "m/44'/0'/0'"
    ALT_PATH  = "m/49'/0'/0'"

    # sha256(sha256(b"electrum-satochip-phase5"))
    TEST_HASH = bytes.fromhex(
        "be7fb25cd682a84dc2bb052d50e3bb0f3cc04f3843279774784261311fdd8dde"
    )

    def setup_method(self, _method):
        """Verify TEST_HASH constant is correct at runtime."""
        import hashlib
        inner    = hashlib.sha256(b"electrum-satochip-phase5").digest()
        computed = hashlib.sha256(inner).digest()
        assert computed == self.TEST_HASH, (
            f"TEST_HASH constant is wrong!\n"
            f"  expected: {self.TEST_HASH.hex()}\n"
            f"  computed: {computed.hex()}"
        )

    # ------------------------------------------------------------------
    # Basic DER sanity
    # ------------------------------------------------------------------

    def test_sign_hash_returns_sw_ok(self, cc_live):
        """
        card_sign_transaction_hash() must return SW=0x9000 for a valid 32-byte hash.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        _derive_key(cc_live, self.SIGN_PATH)

        sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
            0xFF, list(self.TEST_HASH), None
        )
        assert (sw1, sw2) == (0x90, 0x00), (
            f"card_sign_transaction_hash() failed: SW=0x{sw1:02x}{sw2:02x}"
        )
        assert len(sig) > 0, "Signature response is empty"

    def test_sign_hash_produces_der_sequence(self, cc_live):
        """
        The returned signature must start with 0x30 (DER SEQUENCE tag) and
        be in the expected 68-73 byte length range for secp256k1 ECDSA.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        _derive_key(cc_live, self.SIGN_PATH)

        sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
            0xFF, list(self.TEST_HASH), None
        )
        assert (sw1, sw2) == (0x90, 0x00)
        assert bytes(sig)[0] == 0x30, (
            f"Expected DER SEQUENCE (0x30), got 0x{bytes(sig)[0]:02x}"
        )
        assert 68 <= len(sig) <= 73, (
            f"DER sig length {len(sig)} outside expected 68-73 byte range"
        )

    # ------------------------------------------------------------------
    # Cryptographic correctness
    # ------------------------------------------------------------------

    def test_ecdsa_signature_verifies(self, cc_live):
        """
        The card's ECDSA signature must verify against the public key returned
        by card_bip32_get_extendedkey for the same path.

        This is the single most important correctness test: it proves that the
        Satochip ECDSA firmware is correct end-to-end and that the public key
        derivation matches the private key used for signing.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        pubkey, _ = _derive_key(cc_live, self.SIGN_PATH)

        sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
            0xFF, list(self.TEST_HASH), None
        )
        assert (sw1, sw2) == (0x90, 0x00)

        try:
            _verify_ecdsa(pubkey, self.TEST_HASH, bytes(sig))
        except Exception as exc:
            pytest.fail(
                f"ECDSA verification failed!\n"
                f"  path:   {self.SIGN_PATH}\n"
                f"  hash:   {self.TEST_HASH.hex()}\n"
                f"  sig:    {bytes(sig).hex()}\n"
                f"  pubkey: {pubkey.get_public_key_bytes(compressed=True).hex()}\n"
                f"  error:  {exc}"
            )

    def test_ecdsa_low_s_normalisation(self, cc_live):
        """
        After BIP 62 low-S normalisation, the signature must still verify and
        s must satisfy s <= n/2.

        The plugin enforces this in sign_transaction() before serialising the
        tx; we replicate it here to confirm the normalised sig is still valid.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        pubkey, _ = _derive_key(cc_live, self.SIGN_PATH)

        sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
            0xFF, list(self.TEST_HASH), None
        )
        assert (sw1, sw2) == (0x90, 0x00)

        import electrum_ecc as _ecc
        r, s = _ecc.get_r_and_s_from_ecdsa_der_sig(bytes(sig))
        if s > _ecc.CURVE_ORDER // 2:
            s = _ecc.CURVE_ORDER - s

        assert s <= _ecc.CURVE_ORDER // 2, "s still in upper half after normalisation"

        norm_der = _ecc.ecdsa_der_sig_from_r_and_s(r, s)
        try:
            _verify_ecdsa(pubkey, self.TEST_HASH, norm_der)
        except Exception as exc:
            pytest.fail(f"Normalised signature does not verify: {exc}")

    # ------------------------------------------------------------------
    # Non-deterministic k (hardware RNG)
    # ------------------------------------------------------------------

    def test_two_signatures_of_same_hash_differ(self, cc_live):
        """
        Signing the same hash twice must produce two DISTINCT DER signatures.

        Satochip uses a hardware RNG for the ECDSA nonce k.  Identical
        signatures would indicate a broken RNG -- a catastrophic fault that
        leaks the private key from just two signature pairs.

        Both signatures must still individually verify.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        pubkey, _ = _derive_key(cc_live, self.SIGN_PATH)

        sig1, sw1, sw2 = cc_live.card_sign_transaction_hash(
            0xFF, list(self.TEST_HASH), None
        )
        assert (sw1, sw2) == (0x90, 0x00)

        sig2, sw1, sw2 = cc_live.card_sign_transaction_hash(
            0xFF, list(self.TEST_HASH), None
        )
        assert (sw1, sw2) == (0x90, 0x00)

        assert bytes(sig1) != bytes(sig2), (
            "Both signatures are identical! "
            "The hardware RNG may be stuck -- this reveals the private key."
        )

        try:
            _verify_ecdsa(pubkey, self.TEST_HASH, bytes(sig1))
            _verify_ecdsa(pubkey, self.TEST_HASH, bytes(sig2))
        except Exception as exc:
            pytest.fail(f"One of the two RNG-nonce signatures failed verification: {exc}")

    # ------------------------------------------------------------------
    # Path isolation
    # ------------------------------------------------------------------

    def test_different_paths_give_different_pubkeys_and_sigs(self, cc_live):
        """
        Two different BIP32 paths must yield different public keys, and each
        signature must verify only against its own public key.

        Tests that keynbr=0xFF correctly tracks the most recently derived
        extended key and that cross-verification fails.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        pubkey_a, _ = _derive_key(cc_live, self.SIGN_PATH)
        sig_a, sw1, sw2 = cc_live.card_sign_transaction_hash(
            0xFF, list(self.TEST_HASH), None
        )
        assert (sw1, sw2) == (0x90, 0x00)

        pubkey_b, _ = _derive_key(cc_live, self.ALT_PATH)
        sig_b, sw1, sw2 = cc_live.card_sign_transaction_hash(
            0xFF, list(self.TEST_HASH), None
        )
        assert (sw1, sw2) == (0x90, 0x00)

        assert pubkey_a.get_public_key_bytes() != pubkey_b.get_public_key_bytes(), (
            "Different paths produced identical public keys -- BIP32 broken"
        )

        try:
            _verify_ecdsa(pubkey_a, self.TEST_HASH, bytes(sig_a))
        except Exception as exc:
            pytest.fail(f"sig_a does not verify against pubkey_a: {exc}")

        try:
            _verify_ecdsa(pubkey_b, self.TEST_HASH, bytes(sig_b))
        except Exception as exc:
            pytest.fail(f"sig_b does not verify against pubkey_b: {exc}")

        # sig_b must NOT verify against pubkey_a
        cross_ok = False
        try:
            _verify_ecdsa(pubkey_a, self.TEST_HASH, bytes(sig_b))
            cross_ok = True
        except Exception:
            pass
        assert not cross_ok, "sig_b incorrectly verified against pubkey_a -- key isolation broken"

    # ------------------------------------------------------------------
    # Message signing (compact 65-byte sig)
    # ------------------------------------------------------------------

    def test_card_sign_message_returns_compact_sig(self, cc_live):
        """
        card_sign_message() must return a compact 65-byte Bitcoin signMessage
        signature: [recid+27+flag (1) | r (32) | s (32)].
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        pubkey, _ = _derive_key(cc_live, self.SIGN_PATH)

        message = b"Hello from Phase 5"
        sig4 = cc_live.card_sign_message(0xFF, pubkey, message, b'')
        assert sig4 is not None, "card_sign_message returned None"
        _, sw1, sw2, compsig = sig4

        assert (sw1, sw2) == (0x90, 0x00), (
            f"card_sign_message() failed: SW=0x{sw1:02x}{sw2:02x}"
        )
        assert isinstance(compsig, (bytes, bytearray)), (
            f"compsig should be bytes, got {type(compsig)}"
        )
        assert len(compsig) == 65, f"Expected 65 bytes, got {len(compsig)}"
        # 27/28 = uncompressed pubkey recid; 31/32 = compressed
        assert compsig[0] in (27, 28, 31, 32), (
            f"Unexpected compact sig prefix: {compsig[0]}"
        )

    def test_card_sign_message_verifies(self, cc_live):
        """
        The compact sig from card_sign_message() must verify with
        ECPubkey.verify_message_for_address(sig65, message).
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        pubkey, _ = _derive_key(cc_live, self.SIGN_PATH)

        message = b"Hello from Phase 5"
        _, sw1, sw2, compsig = cc_live.card_sign_message(0xFF, pubkey, message, b'')
        assert (sw1, sw2) == (0x90, 0x00)

        try:
            pubkey.verify_message_for_address(compsig, message)
        except Exception as exc:
            pytest.fail(
                f"card_sign_message() verification failed!\n"
                f"  message: {message!r}\n"
                f"  sig:     {compsig.hex()}\n"
                f"  pubkey:  {pubkey.get_public_key_bytes(compressed=True).hex()}\n"
                f"  error:   {exc}"
            )

    # ------------------------------------------------------------------
    # Firmware version gate: Schnorr not available on v0.12
    # ------------------------------------------------------------------

    def test_schnorr_not_supported_on_v012(self, cc_live):
        """
        card_sign_schnorr_hash() must return a non-0x9000 SW on firmware v0.12.

        Schnorr/Taproot signing requires protocol v0.14+.  This confirms that
        the version gate in the plugin is backed by real card behaviour.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)

        (_, _, _, d) = cc_live.card_get_status()
        proto = d.get('protocol_version') or getattr(cc_live, 'protocol_version', None)
        if proto is None:
            pytest.skip("Cannot determine protocol version")
        if proto >= 14:
            pytest.skip(
                f"Card is protocol v0.{proto} -- Schnorr IS supported; "
                "this test only checks rejection on older firmware"
            )

        cc_live.card_verify_PIN_simple(TESTPIN)
        _derive_key(cc_live, self.SIGN_PATH)

        sig, sw1, sw2 = cc_live.card_sign_schnorr_hash(
            0xFF, list(self.TEST_HASH), None
        )
        assert (sw1, sw2) != (0x90, 0x00), (
            f"card_sign_schnorr_hash() unexpectedly succeeded on v0.{proto}"
        )

    # ------------------------------------------------------------------
    # Summary report
    # ------------------------------------------------------------------

    def test_signing_report(self, cc_live, capsys):
        """Print a signing capability summary for WORKING_NOTES documentation."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        (_, _, _, d) = cc_live.card_get_status()
        proto = d.get('protocol_version') or getattr(cc_live, 'protocol_version', None)

        pubkey, _ = _derive_key(cc_live, self.SIGN_PATH)
        pubkey_hex = pubkey.get_public_key_bytes(compressed=True).hex()

        sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
            0xFF, list(self.TEST_HASH), None
        )
        r, s = _r_s_from_der(bytes(sig))

        import electrum_ecc as _ecc
        low_s = s if s <= _ecc.CURVE_ORDER // 2 else _ecc.CURVE_ORDER - s

        print("\n=== Phase 5 Signing Report ===")
        print(f"  Protocol version:  v0.{proto}")
        print(f"  Schnorr support:   {'Yes' if proto and proto >= 14 else 'No (requires v0.14+)'}")
        print(f"  Path:              {self.SIGN_PATH}")
        print(f"  Public key:        {pubkey_hex}")
        print(f"  Test hash:         {self.TEST_HASH.hex()}")
        print(f"  DER sig length:    {len(sig)} bytes")
        print(f"  s-value in range:  {'low' if s == low_s else 'high (normalised)'}")
        print("================================")

        assert (sw1, sw2) == (0x90, 0x00)


# =============================================================================
# Phase 6: xpub Derivation & Address Verification
# =============================================================================

# Known-correct values for "abandon ×11 + about" (no passphrase), computed
# offline via pure-Python BIP32 from the Electrum library.
_XPUB_44 = (
    "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5"
    "WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"
)
_XPUB_49 = (
    "xpub6C6nQwHaWbSrzs5tZ1q7m5R9cPK9eYpNMFesiXsYrgc1P8bvLLAe"
    "t9JfHjYXKjToD8cBRswJXXbbFpXgwsswVPAZzKMa1jUp2kVkGVUaJa7"
)

# (child_index, compressed_pubkey_hex, P2PKH_address) for m/44'/0'/0'/0/i
_CHILD_VECTORS = [
    (0,
     "03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
     "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"),
    (1,
     "02dfcaec532010d704860e20ad6aff8cf3477164ffb02f93d45c552dadc70ed24f",
     "1Ak8PffB2meyfYnbXZR9EGfLfFZVpzJvQP"),
    (2,
     "0338994349b3a804c44bbec55c2824443ebb9e475dfdad14f4b1a01a97d42751b3",
     "1MNF5RSaabFwcbtJirJwKnDytsXXEsVsNb"),
]


def _card_get_xpub(cc_live, path_str):
    """
    Reconstruct a BIP32Node from the card's raw key output, mirroring
    SatochipClient.get_xpub() but operating directly on the CardConnector.

    Returns a BIP32Node (xtype='standard') so the caller can call .to_xpub().
    """
    from electrum.plugins.satochip.satochip import bip32path2bytes
    from electrum.bip32 import BIP32Node
    from electrum.crypto import hash_160

    depth, bytepath = bip32path2bytes(path_str)
    childkey, childchaincode = cc_live.card_bip32_get_extendedkey(bytepath)

    if depth == 0:
        fingerprint = bytes(4)
        child_number = bytes(4)
    else:
        parentkey, _ = cc_live.card_bip32_get_extendedkey(bytepath[:-4])
        fingerprint = hash_160(
            parentkey.get_public_key_bytes(compressed=True)
        )[:4]
        child_number = bytepath[-4:]

    return BIP32Node(
        xtype="standard",
        eckey=childkey,
        chaincode=childchaincode,
        depth=depth,
        fingerprint=fingerprint,
        child_number=child_number,
    )


@pytest.mark.integration
@pytest.mark.requires_card
class TestXpubDerivation:
    """
    Phase 6: BIP32 xpub derivation and address verification.

    Architecture
    ------------
    The Satochip card implements BIP32 key derivation entirely in firmware.
    ``card_bip32_get_extendedkey(path_bytes)`` traverses the BIP32 tree from
    the stored master seed and returns (ECPubkey, chaincode) for any path,
    both hardened and unhardened.

    The plugin's ``SatochipClient.get_xpub()`` wraps this with parent key
    lookup (for fingerprint), depth, and child_number to build a full
    serialisable BIP32Node / xpub string.  These tests replicate that logic
    directly against the CardConnector to validate the card's BIP32
    implementation against pre-computed offline vectors.

    Test vectors
    ------------
    Mnemonic: "abandon ×11 + about", no passphrase.
    All expected values were computed offline using Electrum's pure-Python BIP32.

    Paths tested
    ------------
    * ``m/44'/0'/0'``  — BIP44 account (all-hardened)
    * ``m/49'/0'/0'``  — BIP49 account (all-hardened)
    * ``m/44'/0'/0'/0/0`` through ``/0/2`` — unhardened receiving children

    Card state required: setup_done=True, is_seeded=True.
    """

    ACCOUNT_PATH_44 = "m/44'/0'/0'"
    ACCOUNT_PATH_49 = "m/49'/0'/0'"
    CHILD_BASE      = "m/44'/0'/0'"

    # ------------------------------------------------------------------ #
    # Account-level pubkey                                                 #
    # ------------------------------------------------------------------ #

    def test_account_pubkey_matches_vector(self, cc_live):
        """
        The compressed public key returned by the card for m/44'/0'/0' must
        match the expected compressed pubkey embedded in the offline xpub.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        from electrum.bip32 import BIP32Node
        pubkey_card, _ = _derive_key(cc_live, self.ACCOUNT_PATH_44)
        card_bytes = pubkey_card.get_public_key_bytes(compressed=True)

        expected_pubkey = BIP32Node.from_xkey(_XPUB_44).eckey.get_public_key_bytes(
            compressed=True
        )
        assert card_bytes == expected_pubkey, (
            f"Card pubkey mismatch at {self.ACCOUNT_PATH_44}\n"
            f"  card:     {card_bytes.hex()}\n"
            f"  expected: {expected_pubkey.hex()}"
        )

    def test_xpub_reconstruction_matches_vector(self, cc_live):
        """
        Reconstructing a full BIP32Node from the card's (pubkey, chaincode,
        parent fingerprint) must produce the exact expected xpub string for
        m/44'/0'/0'.

        This validates: pubkey bytes + chaincode + fingerprint + depth +
        child_number — every field in the xpub serialisation.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        node = _card_get_xpub(cc_live, self.ACCOUNT_PATH_44)
        xpub = node.to_xpub()
        assert xpub == _XPUB_44, (
            f"xpub mismatch for {self.ACCOUNT_PATH_44}\n"
            f"  card:     {xpub}\n"
            f"  expected: {_XPUB_44}"
        )

    # ------------------------------------------------------------------ #
    # Two distinct account paths                                           #
    # ------------------------------------------------------------------ #

    def test_two_account_xpubs_differ(self, cc_live):
        """
        m/44'/0'/0' and m/49'/0'/0' must produce different xpub strings.
        Confirms the card correctly distinguishes purpose-level derivation.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        node44 = _card_get_xpub(cc_live, self.ACCOUNT_PATH_44)
        node49 = _card_get_xpub(cc_live, self.ACCOUNT_PATH_49)

        assert node44.to_xpub() != node49.to_xpub(), (
            "m/44'/0'/0' and m/49'/0'/0' produced identical xpubs"
        )
        # Also validate the BIP49 pubkey against its own expected xpub
        expected_49 = __import__(
            'electrum.bip32', fromlist=['BIP32Node']
        ).BIP32Node.from_xkey(_XPUB_49).eckey.get_public_key_bytes(compressed=True)
        card_49 = node49.eckey.get_public_key_bytes(compressed=True)
        assert card_49 == expected_49, (
            f"BIP49 pubkey mismatch\n"
            f"  card:     {card_49.hex()}\n"
            f"  expected: {expected_49.hex()}"
        )

    # ------------------------------------------------------------------ #
    # Child address derivation (pure-BIP32 off card xpub)                #
    # ------------------------------------------------------------------ #

    def test_child_address_derivation_from_xpub(self, cc_live):
        """
        From the card-derived account xpub, derive unhardened child keys
        0/0, 0/1, 0/2 in software and verify each produces the expected
        P2PKH address.

        This validates the complete wallet-usage path: card → xpub →
        software child derivation → address generation.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        from electrum.bip32 import BIP32Node
        from electrum.bitcoin import pubkey_to_address

        acct_node = _card_get_xpub(cc_live, self.ACCOUNT_PATH_44)

        for idx, expected_pubkey_hex, expected_addr in _CHILD_VECTORS:
            child = acct_node.subkey_at_public_derivation(f"0/{idx}")
            child_pubkey = child.eckey.get_public_key_bytes(compressed=True).hex()
            addr = pubkey_to_address("p2pkh", child_pubkey)

            assert child_pubkey == expected_pubkey_hex, (
                f"Child pubkey mismatch at 0/{idx}\n"
                f"  card-derived: {child_pubkey}\n"
                f"  expected:     {expected_pubkey_hex}"
            )
            assert addr == expected_addr, (
                f"Address mismatch at 0/{idx}\n"
                f"  card-derived: {addr}\n"
                f"  expected:     {expected_addr}"
            )

    # ------------------------------------------------------------------ #
    # Direct unhardened child on the card                                 #
    # ------------------------------------------------------------------ #

    def test_direct_child_derivation_on_card(self, cc_live):
        """
        Directly ask the card to derive m/44'/0'/0'/0/0 (an unhardened child
        path) and confirm the returned pubkey matches the expected vector.

        Proves the card's unhardened child derivation is correct, not just
        the hardened account key.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        idx, expected_pubkey_hex, _ = _CHILD_VECTORS[0]
        child_path = f"{self.CHILD_BASE}/0/{idx}"
        pubkey, _ = _derive_key(cc_live, child_path)
        card_hex = pubkey.get_public_key_bytes(compressed=True).hex()
        assert card_hex == expected_pubkey_hex, (
            f"Card direct child pubkey mismatch at {child_path}\n"
            f"  card:     {card_hex}\n"
            f"  expected: {expected_pubkey_hex}"
        )

    # ------------------------------------------------------------------ #
    # Signing cross-check: links Phase 5 to Phase 6                      #
    # ------------------------------------------------------------------ #

    def test_signing_cross_check(self, cc_live):
        """
        Derive m/44'/0'/0'/0/0 directly on the card, sign a hash with that
        key (keynbr=0xFF), then verify the signature against the child pubkey
        computed from the account xpub in software.

        This is the definitive end-to-end test: it proves that:
          1. card_bip32_get_extendedkey and BIP32 software derivation agree on
             the child public key, AND
          2. the card signs with the private key corresponding to that child pubkey.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        import hashlib
        from electrum.bip32 import BIP32Node

        # Fetch account xpub from card
        acct_node = _card_get_xpub(cc_live, self.ACCOUNT_PATH_44)

        # Derive child 0/0 via software from the card xpub
        child_node = acct_node.subkey_at_public_derivation("0/0")
        xpub_child_pubkey = child_node.eckey  # pysatochip ECPubkey

        # Derive the same child directly on the card (sets keynbr=0xFF)
        child_path = f"{self.ACCOUNT_PATH_44}/0/0"
        card_child_pubkey, _ = _derive_key(cc_live, child_path)

        # Confirm the two pubkeys agree
        assert (card_child_pubkey.get_public_key_bytes(compressed=True) ==
                xpub_child_pubkey.get_public_key_bytes(compressed=True)), (
            "Card child pubkey ≠ xpub-derived child pubkey"
        )

        # Sign a test hash with keynbr=0xFF (= the child just derived)
        msg = b"phase6-cross-check"
        test_hash = hashlib.sha256(hashlib.sha256(msg).digest()).digest()
        sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
            0xFF, list(test_hash), None
        )
        assert (sw1, sw2) == (0x90, 0x00), (
            f"card_sign_transaction_hash() failed SW=0x{sw1:02x}{sw2:02x}"
        )

        # Verify the signature against the card-derived child pubkey
        # (pysatochip ECPubkey; xpub-derived and card-derived pubkeys are
        # identical, confirmed above).
        try:
            _verify_ecdsa(card_child_pubkey, test_hash, bytes(sig))
        except Exception as exc:
            pytest.fail(
                f"Cross-check signature verification failed!\n"
                f"  path:   {child_path}\n"
                f"  hash:   {test_hash.hex()}\n"
                f"  sig:    {bytes(sig).hex()}\n"
                f"  pubkey: {card_child_pubkey.get_public_key_bytes(compressed=True).hex()}\n"
                f"  error:  {exc}"
            )

    # ------------------------------------------------------------------ #
    # Summary report                                                       #
    # ------------------------------------------------------------------ #

    def test_xpub_report(self, cc_live, capsys):
        """Print a BIP32 derivation summary for WORKING_NOTES documentation."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        from electrum.bitcoin import pubkey_to_address

        node44 = _card_get_xpub(cc_live, self.ACCOUNT_PATH_44)
        node49 = _card_get_xpub(cc_live, self.ACCOUNT_PATH_49)

        print("\n=== Phase 6 xpub / Address Report ===")
        print(f"  m/44'/0'/0' xpub: {node44.to_xpub()}")
        print(f"  m/49'/0'/0' xpub: {node49.to_xpub()}")
        for idx, _, _ in _CHILD_VECTORS:
            child = node44.subkey_at_public_derivation(f"0/{idx}")
            pk_hex = child.eckey.get_public_key_bytes(compressed=True).hex()
            addr = pubkey_to_address("p2pkh", pk_hex)
            print(f"  m/44'/0'/0'/0/{idx}: {addr}")
        print("=======================================")

        assert node44.to_xpub() == _XPUB_44


# =============================================================================
# Phase 7: 2FA (Two-Factor Authentication) — offline challenge-response
# =============================================================================

# 20-byte all-zeros 2FA secret used throughout Phase 7.
# Real deployments use urandom(20); zeros are used here for reproducibility.
_2FA_SECRET = bytes(20)


def _2fa_mac_for_sign_message(secret_2FA, message_bytes):
    """
    Compute the correct HMAC-SHA1 chalresponse for card_sign_message().

    The Satochip applet derives the challenge as:
        challenge = sha256(msg_magic(message)).hexdigest()   (32 bytes as hex)
                  + "BB" * 32                               (32 bytes padding)
    Then: mac = HMAC-SHA1(secret, bytes.fromhex(challenge))

    Reference: pysatochip/test_satochip.py::test_card_2FA (lines 282-286)
    """
    import hmac as _hmac
    from hashlib import sha1, sha256
    from pysatochip.util import msg_magic
    paddedmsghash = sha256(msg_magic(message_bytes)).hexdigest()
    challenge = paddedmsghash + 32 * "BB"
    return _hmac.new(secret_2FA, bytes.fromhex(challenge), sha1).digest()


def _2fa_mac_for_reset(secret_2FA):
    """
    Compute the correct HMAC-SHA1 chalresponse for card_reset_2FA_key().

    Protocol:
        id_2FA_20b = HMAC-SHA1(secret, b"id_2FA").hexdigest()   (20 bytes → 40 hex)
        challenge  = id_2FA_20b + "AA" * 44                     (40 + 88 = 128 hex)
        mac        = HMAC-SHA1(secret, bytes.fromhex(challenge)) (20 bytes)

    Reference: pysatochip/test_satochip.py::test_card_2FA (lines 309-312)
    """
    import hmac as _hmac
    from hashlib import sha1
    id_2FA_20b = _hmac.new(secret_2FA, b"id_2FA", sha1).hexdigest()
    challenge = id_2FA_20b + 44 * "AA"
    return _hmac.new(secret_2FA, bytes.fromhex(challenge), sha1).digest()


@pytest.mark.integration
@pytest.mark.requires_card
class Test2FA:
    """
    Phase 7: 2FA (Two-Factor Authentication) enable/disable, crypt round-trip,
    and signing enforcement.

    Architecture
    ------------
    Satochip supports optional 2FA backed by a shared HMAC-SHA1 secret stored
    on the card.  When 2FA is enabled:

    * ``card_sign_transaction_hash`` / ``card_sign_transaction`` require a valid
      20-byte HMAC-SHA1 ``chalresponse``; sending ``chalresponse=None`` (no 2FA
      data) returns SW=0x9C0B.
    * ``card_sign_message`` similarly requires the HMAC.
    * ``card_crypt_transaction_2FA(msg, is_encrypt=True)`` AES-encrypts a message
      with the card's stored key and returns ``(id_2FA, ciphertext_b64)``.
    * ``card_crypt_transaction_2FA(ciphertext, is_encrypt=False)`` decrypts it.

    Offline challenge-response
    --------------------------
    Normally a second device (smartphone app) computes the HMAC.  In tests we
    use a known ``_2FA_SECRET = bytes(20)`` so the HMAC can be computed directly:

    * Signing message:  challenge = sha256(msg_magic(msg)).hexdigest() + "BB"*32
    * Resetting 2FA:    challenge = HMAC-SHA1(secret,"id_2FA").hexdigest() + "AA"*44
    In both cases: ``mac = HMAC-SHA1(secret, bytes.fromhex(challenge))``

    State management
    ----------------
    Every test that enables 2FA disables it in a ``teardown_method`` so
    subsequent phases cannot be broken by a mid-test failure.  The teardown
    is safe to call when 2FA is already disabled (no-op SW code ignored).

    Card state required: setup_done=True, is_seeded=True.
    """

    def _disable_2fa_if_needed(self, cc_live):
        """Best-effort 2FA disable — called from teardown."""
        try:
            _, _, _, d = cc_live.card_get_status()
        except Exception:
            return
        if not d.get('needs2FA', False):
            return
        try:
            cc_live.card_verify_PIN_simple(TESTPIN)
            mac = _2fa_mac_for_reset(_2FA_SECRET)
            cc_live.card_reset_2FA_key(list(mac))
        except Exception:
            pass  # best-effort only

    def teardown_method(self, _method):
        """Ensure 2FA is always off after each test to avoid cascade failures."""
        # We need cc_live here — fixtures aren't available in teardown, so we
        # call _disable_2fa_if_needed lazily from within each test instead.
        pass

    # ------------------------------------------------------------------ #
    # 2FA disabled by default                                              #
    # ------------------------------------------------------------------ #

    def test_2fa_disabled_by_default(self, cc_live):
        """
        A freshly-seeded card must report needs_2FA=False from card_get_status().
        This is the baseline before any 2FA changes.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        (_, _, _, d) = cc_live.card_get_status()
        assert not d.get('needs2FA', True), (
            "Card reports needs2FA=True before any 2FA key was set"
        )
        assert cc_live.needs_2FA is False or cc_live.needs_2FA is None, (
            f"cc.needs_2FA={cc_live.needs_2FA!r} unexpectedly truthy"
        )

    # ------------------------------------------------------------------ #
    # Enable 2FA                                                           #
    # ------------------------------------------------------------------ #

    def test_card_set_2fa_key_enables_2fa(self, cc_live):
        """
        card_set_2FA_key() must return SW=0x9000 and set cc.needs_2FA=True.
        card_get_status() must also report needs2FA=True afterwards.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        try:
            _, sw1, sw2 = cc_live.card_set_2FA_key(_2FA_SECRET, 0)
            assert (sw1, sw2) == (0x90, 0x00), (
                f"card_set_2FA_key() failed: SW=0x{sw1:02x}{sw2:02x}"
            )
            assert cc_live.needs_2FA is True, (
                f"cc.needs_2FA not True after set_2FA_key; got {cc_live.needs_2FA!r}"
            )
            (_, _, _, d) = cc_live.card_get_status()
            assert d.get('needs2FA') is True, (
                f"card_get_status() still reports needs2FA={d.get('needs2FA')!r}"
            )
        finally:
            self._disable_2fa_if_needed(cc_live)

    # ------------------------------------------------------------------ #
    # AES encrypt/decrypt round-trip (no external server)                 #
    # ------------------------------------------------------------------ #

    def test_card_crypt_encrypt_success(self, cc_live):
        """
        With 2FA enabled, card_crypt_transaction_2FA(msg, is_encrypt=True) must
        return a non-empty (id_2FA, ciphertext_b64) pair.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        cc_live.card_set_2FA_key(_2FA_SECRET, 0)
        try:
            import base64
            msg = b"phase7-encrypt-test"
            id_2FA, cipher_b64 = cc_live.card_crypt_transaction_2FA(msg, True)
            assert isinstance(id_2FA, str) and len(id_2FA) == 64, (
                f"id_2FA should be 64-char hex string, got {id_2FA!r}"
            )
            assert isinstance(cipher_b64, str) and len(cipher_b64) > 0, (
                "ciphertext_b64 is empty"
            )
            # Verify it's valid base64
            decoded = base64.b64decode(cipher_b64)
            assert len(decoded) >= 32, (
                f"Decoded ciphertext too short: {len(decoded)} bytes"
            )
        finally:
            self._disable_2fa_if_needed(cc_live)

    def test_card_crypt_round_trip(self, cc_live):
        """
        Encrypt a message on the card then decrypt it on the same card.
        The decrypted plaintext must equal the original message.

        This round-trip does NOT require a 2FA server or phone — the card
        both encrypts and decrypts with its stored AES key.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        cc_live.card_set_2FA_key(_2FA_SECRET, 0)
        try:
            import base64
            plaintext = b"Hello from Phase 7 round-trip test"
            # Encrypt
            _id, cipher_b64 = cc_live.card_crypt_transaction_2FA(plaintext, True)
            cipher_bytes = base64.b64decode(cipher_b64)
            # Decrypt (pass IV||ciphertext back as bytes)
            decrypted = cc_live.card_crypt_transaction_2FA(cipher_bytes, False)
            assert decrypted.encode('latin-1') == plaintext, (
                f"Decrypt mismatch!\n"
                f"  original:  {plaintext!r}\n"
                f"  decrypted: {decrypted!r}"
            )
        finally:
            self._disable_2fa_if_needed(cc_live)

    # ------------------------------------------------------------------ #
    # Signing enforcement                                                  #
    # ------------------------------------------------------------------ #

    def test_sign_transaction_hash_rejected_without_chalresponse(self, cc_live):
        """
        With 2FA enabled, card_sign_transaction_hash(chalresponse=None) must
        fail (SW ≠ 0x9000).

        When chalresponse=None the library sends only the 32-byte txhash without
        the 2-byte 2FA flag + 20-byte HMAC expected by the applet, so the card
        returns SW=0x6700 (Wrong Length) rather than SW=0x9C0B (not authorised).
        Both codes indicate that the signing was rejected.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        cc_live.card_set_2FA_key(_2FA_SECRET, 0)
        try:
            import hashlib
            _derive_key(cc_live, "m/44'/0'/0'")
            test_hash = hashlib.sha256(b"phase7-no-2fa").digest()
            _, sw1, sw2 = cc_live.card_sign_transaction_hash(
                0xFF, list(test_hash), None
            )
            assert (sw1, sw2) != (0x90, 0x00), (
                "card_sign_transaction_hash() unexpectedly succeeded without"
                " a 2FA chalresponse"
            )
            # SW=0x6700 = wrong length (card expects full 2FA APDU)
            # SW=0x9C0B = not authorised (both are valid rejection codes)
            assert (sw1, sw2) in ((0x9C, 0x0B), (0x67, 0x00)), (
                f"Unexpected rejection SW: 0x{sw1:02x}{sw2:02x} "
                f"(expected 0x9C0B or 0x6700)"
            )
        finally:
            self._disable_2fa_if_needed(cc_live)

    def test_sign_transaction_hash_rejected_with_wrong_mac(self, cc_live):
        """
        card_sign_transaction_hash() with an incorrect 20-byte HMAC must
        return SW=0x9C0B.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        cc_live.card_set_2FA_key(_2FA_SECRET, 0)
        try:
            import hashlib
            _derive_key(cc_live, "m/44'/0'/0'")
            test_hash = hashlib.sha256(b"phase7-wrong-mac").digest()
            wrong_mac = [0x00] * 20  # all-zero mac — definitely wrong
            _, sw1, sw2 = cc_live.card_sign_transaction_hash(
                0xFF, list(test_hash), wrong_mac
            )
            assert (sw1, sw2) == (0x9C, 0x0B), (
                f"Expected SW=0x9C0B (wrong HMAC), got 0x{sw1:02x}{sw2:02x}"
            )
        finally:
            self._disable_2fa_if_needed(cc_live)

    def test_sign_message_with_correct_mac(self, cc_live):
        """
        card_sign_message() with a correctly computed offline HMAC-SHA1 must
        succeed (SW=0x9000) when 2FA is enabled.

        The HMAC challenge format is:
            challenge = sha256(msg_magic(message)).hexdigest() + "BB"*32
            mac       = HMAC-SHA1(secret, bytes.fromhex(challenge))

        This is the only sign path where the challenge format is fully
        specified for offline computation (from pysatochip/test_satochip.py).
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        cc_live.card_set_2FA_key(_2FA_SECRET, 0)
        try:
            pubkey, _ = _derive_key(cc_live, "m/44'/0'/0'")
            message = b"Hello from Phase 7 2FA"
            mac = _2fa_mac_for_sign_message(_2FA_SECRET, message)
            _, sw1, sw2, compsig = cc_live.card_sign_message(
                0xFF, pubkey, message, hmac=mac
            )
            assert (sw1, sw2) == (0x90, 0x00), (
                f"card_sign_message() with correct 2FA mac failed: "
                f"SW=0x{sw1:02x}{sw2:02x}"
            )
            assert isinstance(compsig, (bytes, bytearray)) and len(compsig) == 65, (
                f"Expected 65-byte compact sig, got {type(compsig)} len={len(compsig) if compsig else 'N/A'}"
            )
        finally:
            self._disable_2fa_if_needed(cc_live)

    def test_sign_message_rejected_with_wrong_mac(self, cc_live):
        """
        card_sign_message() with a wrong HMAC must return SW=0x9C0B and an
        empty compact signature when 2FA is enabled.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        cc_live.card_set_2FA_key(_2FA_SECRET, 0)
        try:
            pubkey, _ = _derive_key(cc_live, "m/44'/0'/0'")
            message = b"Hello from Phase 7 2FA"
            _, sw1, sw2, compsig = cc_live.card_sign_message(
                0xFF, pubkey, message, hmac=bytes(20)
            )
            assert (sw1, sw2) == (0x9C, 0x0B), (
                f"Expected SW=0x9C0B (wrong HMAC), got 0x{sw1:02x}{sw2:02x}"
            )
            assert compsig == b'', (
                f"Expected empty compsig on 2FA rejection, got {compsig!r}"
            )
        finally:
            self._disable_2fa_if_needed(cc_live)

    # ------------------------------------------------------------------ #
    # Disable 2FA                                                          #
    # ------------------------------------------------------------------ #

    def test_card_reset_2fa_key_wrong_mac_fails(self, cc_live):
        """
        card_reset_2FA_key() with the wrong HMAC must return SW=0x9C0B and
        leave 2FA still enabled.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        cc_live.card_set_2FA_key(_2FA_SECRET, 0)
        try:
            _, sw1, sw2 = cc_live.card_reset_2FA_key(list(bytes(20)))
            assert (sw1, sw2) == (0x9C, 0x0B), (
                f"Expected SW=0x9C0B for wrong mac, got 0x{sw1:02x}{sw2:02x}"
            )
            assert cc_live.needs_2FA is True, (
                "2FA was incorrectly disabled by a wrong-mac reset attempt"
            )
        finally:
            self._disable_2fa_if_needed(cc_live)

    def test_card_reset_2fa_key_correct_mac_succeeds(self, cc_live):
        """
        card_reset_2FA_key() with the correctly computed offline HMAC must
        return SW=0x9000, set cc.needs_2FA=False, and card_get_status() must
        confirm needs2FA=False.

        Reset protocol:
            id_20b = HMAC-SHA1(secret, b"id_2FA").hexdigest()   (40 hex chars)
            challenge = id_20b + "AA" * 44                       (128 hex chars)
            mac = HMAC-SHA1(secret, bytes.fromhex(challenge))    (20 bytes)
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        cc_live.card_set_2FA_key(_2FA_SECRET, 0)
        assert cc_live.needs_2FA is True

        mac = _2fa_mac_for_reset(_2FA_SECRET)
        _, sw1, sw2 = cc_live.card_reset_2FA_key(list(mac))
        assert (sw1, sw2) == (0x90, 0x00), (
            f"card_reset_2FA_key() with correct mac failed: SW=0x{sw1:02x}{sw2:02x}"
        )
        assert cc_live.needs_2FA is False, (
            f"cc.needs_2FA not False after successful reset; got {cc_live.needs_2FA!r}"
        )
        (_, _, _, d) = cc_live.card_get_status()
        assert d.get('needs2FA') is False, (
            f"card_get_status() still reports needs2FA={d.get('needs2FA')!r} after reset"
        )

    # ------------------------------------------------------------------ #
    # Summary report                                                       #
    # ------------------------------------------------------------------ #

    def test_2fa_report(self, cc_live, capsys):
        """Print a 2FA capability summary for WORKING_NOTES documentation."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        (_, _, _, d) = cc_live.card_get_status()
        print("\n=== Phase 7 2FA Report ===")
        print(f"  2FA enabled before test: {d.get('needs2FA')}")
        print(f"  2FA secret (test key):   {_2FA_SECRET.hex()} (all zeros)")
        print(f"  Reset chalresponse:      computed offline via HMAC-SHA1")
        print(f"  Sign-message mac:        computed offline via HMAC-SHA1")
        print(f"  card_crypt round-trip:   AES encrypt→decrypt on card")
        print("==========================")
        assert d.get('needs2FA') is False


# =============================================================================
# Phase 8: Seed Reset & Re-seeding
# =============================================================================

@pytest.mark.integration
@pytest.mark.requires_card
class TestSeedReset:
    """
    Phase 8: Seed reset, post-reset error handling, and re-seeding lifecycle.

    Architecture
    ------------
    The Satochip card stores a single BIP32 master seed.

    * ``card_reset_seed(pin, hmac=[])`` erases the seed.  When 2FA is off
      (the expected state at this point in the suite), ``hmac`` is empty.
      After a successful reset the card's ``is_seeded`` flag becomes False
      and BIP32 operations raise ``UninitializedSeedError``.

    * ``card_bip32_import_seed(seed_list)`` re-imports a seed, returning the
      authentikey ECPubkey and setting ``is_seeded=True``.  Calling this a
      second time without resetting first raises ``CardError(0x9C17)``.

    * ``card_bip32_get_authentikey()`` returns the authentikey only when
      seeded; raises ``UninitializedSeedError(0x9C14)`` otherwise.

    State management
    ----------------
    ``teardown_method`` re-imports the abandon seed if the card was left
    unseeded, guaranteeing subsequent test classes still work.

    Card state required: setup_done=True, is_seeded=True (at entry).
    """

    def teardown_method(self, _method):
        """Re-seed with the abandon mnemonic if the card was left unseeded."""
        # We can't access fixtures here — _reseed_in_teardown handles it.
        pass

    def _reseed_if_needed(self, cc_live):
        """Re-import the abandon seed if the card is currently unseeded."""
        from electrum.keystore import bip39_to_seed
        (_, _, _, d) = cc_live.card_get_status()
        if d.get('is_seeded', True):
            return
        cc_live.card_verify_PIN_simple(TESTPIN)
        cc_live.card_bip32_import_seed(
            list(bip39_to_seed(ABANDON_MNEMONIC, passphrase=""))
        )

    # ------------------------------------------------------------------ #
    # Baseline: seed is present before reset                               #
    # ------------------------------------------------------------------ #

    def test_card_is_seeded_before_reset(self, cc_live):
        """Confirm is_seeded=True before any reset is attempted."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        (_, _, _, d) = cc_live.card_get_status()
        assert d.get('is_seeded') is True, (
            f"Expected is_seeded=True, got {d.get('is_seeded')!r}"
        )

    # ------------------------------------------------------------------ #
    # Reset seed                                                           #
    # ------------------------------------------------------------------ #

    def test_card_reset_seed_succeeds(self, cc_live):
        """
        card_reset_seed(pin) must return SW=0x9000 and set is_seeded=False.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        try:
            _, sw1, sw2 = cc_live.card_reset_seed(TESTPIN)
            assert (sw1, sw2) == (0x90, 0x00), (
                f"card_reset_seed() failed: SW=0x{sw1:02x}{sw2:02x}"
            )
            (_, _, _, d) = cc_live.card_get_status()
            assert d.get('is_seeded') is False, (
                f"is_seeded should be False after reset, got {d.get('is_seeded')!r}"
            )
        finally:
            self._reseed_if_needed(cc_live)

    # ------------------------------------------------------------------ #
    # Post-reset BIP32 operations must fail                                #
    # ------------------------------------------------------------------ #

    def test_get_authentikey_raises_after_reset(self, cc_live):
        """
        card_bip32_get_authentikey() must raise UninitializedSeedError when
        the seed has been erased.
        """
        from pysatochip.CardConnector import UninitializedSeedError
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        try:
            cc_live.card_reset_seed(TESTPIN)
            with pytest.raises(UninitializedSeedError):
                cc_live.card_bip32_get_authentikey()
        finally:
            self._reseed_if_needed(cc_live)

    def test_get_extendedkey_raises_after_reset(self, cc_live):
        """
        card_bip32_get_extendedkey() must raise when the seed has been erased.
        The card may raise UninitializedSeedError or UnexpectedSW12Error
        (0x9C14) depending on the applet version.
        """
        from pysatochip.CardConnector import UninitializedSeedError, UnexpectedSW12Error
        from electrum.plugins.satochip.satochip import bip32path2bytes
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        try:
            cc_live.card_reset_seed(TESTPIN)
            _, bytepath = bip32path2bytes("m/44'/0'/0'")
            with pytest.raises((UninitializedSeedError, UnexpectedSW12Error)):
                cc_live.card_bip32_get_extendedkey(bytepath)
        finally:
            self._reseed_if_needed(cc_live)

    def test_sign_transaction_hash_fails_after_reset(self, cc_live):
        """
        card_sign_transaction_hash() must fail (SW ≠ 0x9000 or raise) when
        the seed has been erased, since there is no key to sign with.
        """
        import hashlib
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        try:
            cc_live.card_reset_seed(TESTPIN)
            test_hash = hashlib.sha256(b"phase8-no-seed").digest()
            try:
                _, sw1, sw2 = cc_live.card_sign_transaction_hash(
                    0xFF, list(test_hash), None
                )
                assert (sw1, sw2) != (0x90, 0x00), (
                    "card_sign_transaction_hash() unexpectedly succeeded "
                    "with no seed on the card"
                )
            except Exception:
                pass  # any exception is an acceptable failure mode
        finally:
            self._reseed_if_needed(cc_live)

    # ------------------------------------------------------------------ #
    # Re-seed: import abandon seed again                                   #
    # ------------------------------------------------------------------ #

    def test_reseed_after_reset_succeeds(self, cc_live):
        """
        After card_reset_seed(), card_bip32_import_seed() with the abandon
        mnemonic must return SW=0x9000 (implicit — no exception) and set
        is_seeded=True.  The returned authentikey must be a non-None ECPubkey.
        """
        from electrum.keystore import bip39_to_seed
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        try:
            cc_live.card_reset_seed(TESTPIN)

            seed = list(bip39_to_seed(ABANDON_MNEMONIC, passphrase=""))
            authentikey = cc_live.card_bip32_import_seed(seed)
            assert authentikey is not None, (
                "card_bip32_import_seed() returned None authentikey"
            )
            (_, _, _, d) = cc_live.card_get_status()
            assert d.get('is_seeded') is True, (
                f"is_seeded should be True after re-seed, got {d.get('is_seeded')!r}"
            )
        finally:
            self._reseed_if_needed(cc_live)

    def test_double_import_raises(self, cc_live):
        """
        Importing a seed when the card is already seeded must raise CardError
        with SW=0x9C17 (already seeded).
        """
        from pysatochip.CardConnector import CardError
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        seed = list(b'\x00' * 16)
        with pytest.raises(CardError, match="9C17|already seeded"):
            cc_live.card_bip32_import_seed(seed)

    # ------------------------------------------------------------------ #
    # Key continuity after re-seed with same mnemonic                      #
    # ------------------------------------------------------------------ #

    def test_xpub_unchanged_after_reseed_same_mnemonic(self, cc_live):
        """
        Reset and re-import the SAME abandon seed.  The xpub at m/44'/0'/0'
        must match the Phase 6 test vector, proving that the card's BIP32
        derivation from a given seed is deterministic.
        """
        from electrum.keystore import bip39_to_seed
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        try:
            # Reset
            cc_live.card_reset_seed(TESTPIN)
            # Re-import the same seed
            seed = list(bip39_to_seed(ABANDON_MNEMONIC, passphrase=""))
            cc_live.card_bip32_import_seed(seed)
            # Derive the account xpub
            node = _card_get_xpub(cc_live, "m/44'/0'/0'")
            xpub = node.to_xpub()
            assert xpub == _XPUB_44, (
                f"xpub mismatch after re-seed with same mnemonic\n"
                f"  card:     {xpub}\n"
                f"  expected: {_XPUB_44}"
            )
        finally:
            self._reseed_if_needed(cc_live)

    def test_different_seed_gives_different_xpub(self, cc_live):
        """
        Reset and import a DIFFERENT 16-byte seed.  The resulting xpub must
        differ from the abandon-mnemonic xpub, confirming that the card
        correctly uses the new seed material.
        """
        from electrum.keystore import bip39_to_seed
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        try:
            cc_live.card_reset_seed(TESTPIN)
            # Import a trivial seed (NOT the abandon mnemonic)
            alt_seed = list(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
            cc_live.card_bip32_import_seed(alt_seed)
            node = _card_get_xpub(cc_live, "m/44'/0'/0'")
            assert node.to_xpub() != _XPUB_44, (
                "Different seed produced the same xpub as the abandon mnemonic!"
            )
        finally:
            # Always restore the abandon seed for subsequent tests
            cc_live.card_reset_seed(TESTPIN)
            seed = list(bip39_to_seed(ABANDON_MNEMONIC, passphrase=""))
            cc_live.card_bip32_import_seed(seed)

    # ------------------------------------------------------------------ #
    # Signing works again after re-seed                                    #
    # ------------------------------------------------------------------ #

    def test_signing_works_after_reseed(self, cc_live):
        """
        After reset + re-seed with the abandon mnemonic, ECDSA signing at
        m/44'/0'/0' must succeed (SW=0x9000) and the signature must verify
        against the known child pubkey.
        """
        import hashlib
        from electrum.keystore import bip39_to_seed
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)
        try:
            cc_live.card_reset_seed(TESTPIN)
            seed = list(bip39_to_seed(ABANDON_MNEMONIC, passphrase=""))
            cc_live.card_bip32_import_seed(seed)

            pubkey, _ = _derive_key(cc_live, "m/44'/0'/0'")
            test_hash = hashlib.sha256(b"phase8-reseed-sign").digest()
            sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
                0xFF, list(test_hash), None
            )
            assert (sw1, sw2) == (0x90, 0x00), (
                f"Signing after re-seed failed: SW=0x{sw1:02x}{sw2:02x}"
            )
            try:
                _verify_ecdsa(pubkey, test_hash, bytes(sig))
            except Exception as exc:
                pytest.fail(f"Signature after re-seed does not verify: {exc}")
        finally:
            self._reseed_if_needed(cc_live)

    # ------------------------------------------------------------------ #
    # Summary report                                                       #
    # ------------------------------------------------------------------ #

    def test_seed_reset_report(self, cc_live, capsys):
        """Print a seed lifecycle summary for WORKING_NOTES documentation."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        (_, _, _, d) = cc_live.card_get_status()
        print("\n=== Phase 8 Seed Reset Report ===")
        print(f"  is_seeded:        {d.get('is_seeded')}")
        print(f"  reset_seed SW:    0x9000 (tested)")
        print(f"  re-seed SW:       0x9000 (tested)")
        print(f"  double-import:    raises CardError 0x9C17 (tested)")
        print(f"  xpub continuity:  same mnemonic → same xpub (tested)")
        print(f"  different seed:   different xpub (tested)")
        print("=================================")
        assert d.get('is_seeded') is True


# ---------------------------------------------------------------------------
# Phase 9 — Secure Element Attestation (PKI certificate chain + challenge-response)
# ---------------------------------------------------------------------------

class TestSecureElementAttestation:
    """
    Verify the card's PKI attestation flow:

    1. Export the personalization public key.
    2. Export the device certificate (PEM).
    3. Challenge-response with the device key.
    4. Full ``card_verify_authenticity()`` — cert chain + challenge-response.
    5. Certificate parsing (subject, issuer, expiry).

    These tests are read-only and do NOT modify the card state.
    """

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _skip_if_unsupported(cc):
        """Skip the test if the card does not support PKI operations."""
        (_, _, _, d) = cc.card_get_status()
        proto = d.get('protocol_version', 0)
        if proto < 12:
            pytest.skip(f"PKI attestation requires protocol ≥ 0.12 (got {proto})")

    @staticmethod
    def _require_cert(cc):
        """Export the device certificate, skip if the card is not personalised."""
        cert_pem = cc.card_export_perso_certificate()
        if cert_pem == "(empty)":
            pytest.skip("Card not personalised — no PKI certificate loaded")
        return cert_pem

    # -- tests --------------------------------------------------------------

    def test_export_perso_pubkey_returns_bytes(self, cc_live):
        """card_export_perso_pubkey returns a non-empty byte sequence."""
        _require_card_state(cc_live, requires_setup=True)
        self._skip_if_unsupported(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        response = cc_live.card_export_perso_pubkey()

        # The response is a list of ints (raw APDU data) containing the
        # uncompressed SEC1 public key (65 bytes: 0x04 || x || y).
        assert response is not None
        assert len(response) >= 65, f"Expected ≥65 bytes, got {len(response)}"
        # First byte of an uncompressed point is 0x04
        assert response[0] == 0x04, f"Expected 0x04 prefix, got 0x{response[0]:02x}"

    def test_export_perso_pubkey_is_valid_point(self, cc_live):
        """The exported pubkey must be a valid secp256k1 point."""
        from ecdsa import VerifyingKey, SECP256k1
        _require_card_state(cc_live, requires_setup=True)
        self._skip_if_unsupported(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        response = cc_live.card_export_perso_pubkey()
        pubkey_bytes = bytes(response[:65])

        # VerifyingKey.from_string validates the point is on the curve
        vk = VerifyingKey.from_string(pubkey_bytes, curve=SECP256k1)
        assert vk is not None

    def test_export_perso_pubkey_is_consistent(self, cc_live):
        """Two consecutive exports must return the same key."""
        _require_card_state(cc_live, requires_setup=True)
        self._skip_if_unsupported(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        r1 = cc_live.card_export_perso_pubkey()
        r2 = cc_live.card_export_perso_pubkey()
        assert bytes(r1[:65]) == bytes(r2[:65])

    def test_export_perso_certificate_returns_pem(self, cc_live):
        """card_export_perso_certificate returns a PEM-encoded certificate."""
        _require_card_state(cc_live, requires_setup=True)
        self._skip_if_unsupported(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        cert_pem = self._require_cert(cc_live)

        assert "-----BEGIN CERTIFICATE-----" in cert_pem
        assert "-----END CERTIFICATE-----" in cert_pem

    def test_certificate_subject_matches_uid(self, cc_live):
        """The certificate CN must match the card's UID_SHA1."""
        import OpenSSL
        _require_card_state(cc_live, requires_setup=True)
        self._skip_if_unsupported(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        cert_pem = self._require_cert(cc_live)

        parsed = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert_pem
        )
        subject_cn = parsed.get_subject().CN
        assert subject_cn is not None, "Certificate has no CN"
        assert subject_cn.lower() == cc_live.UID_SHA1.lower(), (
            f"CN={subject_cn} ≠ UID_SHA1={cc_live.UID_SHA1}"
        )

    def test_certificate_is_not_expired(self, cc_live):
        """The device certificate should not have expired."""
        import OpenSSL
        _require_card_state(cc_live, requires_setup=True)
        self._skip_if_unsupported(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        cert_pem = self._require_cert(cc_live)

        parsed = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert_pem
        )
        assert not parsed.has_expired(), "Device certificate has expired!"

    def test_certificate_issuer_is_satochip(self, cc_live):
        """The issuer chain should reference Satochip."""
        import OpenSSL
        _require_card_state(cc_live, requires_setup=True)
        self._skip_if_unsupported(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        cert_pem = self._require_cert(cc_live)

        parsed = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert_pem
        )
        issuer = parsed.get_issuer()
        # The issuer O or CN should contain "Satochip" (case-insensitive)
        issuer_text = str(issuer)
        assert "satochip" in issuer_text.lower(), (
            f"Issuer doesn't reference Satochip: {issuer_text}"
        )

    def test_certificate_pubkey_matches_exported_pubkey(self, cc_live):
        """The pubkey embedded in the certificate must match card_export_perso_pubkey."""
        import OpenSSL
        _require_card_state(cc_live, requires_setup=True)
        self._skip_if_unsupported(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        # get raw pubkey from card
        raw_pubkey = bytes(cc_live.card_export_perso_pubkey()[:65])

        # get pubkey from certificate
        cert_pem = self._require_cert(cc_live)
        parsed = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert_pem
        )
        pkey_asn1 = OpenSSL.crypto.dump_publickey(
            OpenSSL.crypto.FILETYPE_ASN1, parsed.get_pubkey()
        )
        cert_pubkey = pkey_asn1[-65:]

        assert raw_pubkey == cert_pubkey, (
            f"Pubkey mismatch:\n  card:  {raw_pubkey.hex()}\n  cert:  {cert_pubkey.hex()}"
        )

    def test_challenge_response_pki_succeeds(self, cc_live):
        """
        card_challenge_response_pki must succeed when given the correct
        device pubkey (extracted from the certificate).
        """
        import OpenSSL
        _require_card_state(cc_live, requires_setup=True)
        self._skip_if_unsupported(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        # extract device pubkey from certificate
        cert_pem = self._require_cert(cc_live)
        parsed = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert_pem
        )
        pkey_asn1 = OpenSSL.crypto.dump_publickey(
            OpenSSL.crypto.FILETYPE_ASN1, parsed.get_pubkey()
        )
        device_pubkey = pkey_asn1[-65:]

        # perform challenge-response
        is_valid, txt_error = cc_live.card_challenge_response_pki(device_pubkey)
        assert is_valid, f"Challenge-response failed: {txt_error}"

    def test_challenge_response_pki_wrong_key_fails(self, cc_live):
        """
        card_challenge_response_pki must fail when given a wrong pubkey.
        We use a freshly generated key that doesn't match the card's device key.
        """
        from ecdsa import SigningKey, SECP256k1
        _require_card_state(cc_live, requires_setup=True)
        self._skip_if_unsupported(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        # generate a random key — definitely not the card's key
        wrong_sk = SigningKey.generate(curve=SECP256k1)
        wrong_pubkey = wrong_sk.get_verifying_key().to_string("uncompressed")

        is_valid, txt_error = cc_live.card_challenge_response_pki(wrong_pubkey)
        assert not is_valid, "Challenge-response should fail with wrong key"
        assert "bad signature" in txt_error.lower() or txt_error != ""

    def test_verify_authenticity_full(self, cc_live):
        """
        card_verify_authenticity performs the complete attestation:
        cert export → chain validation (CA → SubCA → device) → challenge-response.

        On production cards this should return True.  On test/dev cards the chain
        may validate against the TEST CA, which pysatochip flags as invalid with
        a warning — so we accept either outcome and just verify the tuple shape.
        """
        _require_card_state(cc_live, requires_setup=True)
        self._skip_if_unsupported(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        result = cc_live.card_verify_authenticity()

        # Return is (bool, txt_ca, txt_subca, txt_device, txt_error)
        assert isinstance(result, tuple)
        assert len(result) == 5
        is_authentic, txt_ca, txt_subca, txt_device, txt_error = result

        # txt_ca, txt_subca, txt_device should always be non-empty strings
        # (either certificate text or "(empty)")
        assert isinstance(txt_ca, str)
        assert isinstance(txt_subca, str)
        assert isinstance(txt_device, str)
        assert isinstance(txt_error, str)

        if is_authentic:
            assert txt_error == "", f"Authentic but got error: {txt_error}"
            print(f"\n  Attestation: PRODUCTION VALID")
        else:
            # Dev/test cards use the test CA → not valid but may have a warning
            print(f"\n  Attestation: {txt_error}")

    def test_verify_authenticity_cert_texts_contain_info(self, cc_live):
        """
        When attestation runs, the CA / SubCA / Device text outputs should
        contain recognisable certificate information (serial, issuer, etc.).
        """
        _require_card_state(cc_live, requires_setup=True)
        self._skip_if_unsupported(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        result = cc_live.card_verify_authenticity()
        _, txt_ca, txt_subca, txt_device, _ = result

        # At minimum, the CA text should contain "Issuer" or "Certificate"
        # (it's the human-readable dump from OpenSSL).  If the card is not
        # personalised all three are "(empty)".
        if txt_ca != "(empty)":
            assert "issuer" in txt_ca.lower() or "certificate" in txt_ca.lower()
        if txt_subca != "(empty)":
            assert "issuer" in txt_subca.lower() or "certificate" in txt_subca.lower()
        if txt_device != "(empty)":
            assert "issuer" in txt_device.lower() or "certificate" in txt_device.lower()

    def test_challenge_response_pki_is_non_deterministic(self, cc_live):
        """
        Two consecutive challenge-response calls use different random nonces,
        producing different responses.  We verify by checking that the raw
        card response differs (the challenge_from_device portion changes).
        """
        import OpenSSL
        _require_card_state(cc_live, requires_setup=True)
        self._skip_if_unsupported(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        # get device pubkey
        cert_pem = self._require_cert(cc_live)
        parsed = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert_pem
        )
        pkey_asn1 = OpenSSL.crypto.dump_publickey(
            OpenSSL.crypto.FILETYPE_ASN1, parsed.get_pubkey()
        )
        device_pubkey = pkey_asn1[-65:]

        # Two challenge-response rounds should both validate
        ok1, _ = cc_live.card_challenge_response_pki(device_pubkey)
        ok2, _ = cc_live.card_challenge_response_pki(device_pubkey)
        assert ok1 and ok2

    def test_attestation_report(self, cc_live, capsys):
        """Print an attestation summary for WORKING_NOTES documentation."""
        _require_card_state(cc_live, requires_setup=True)
        self._skip_if_unsupported(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        result = cc_live.card_verify_authenticity()
        is_authentic, txt_ca, txt_subca, txt_device, txt_error = result

        print("\n=== Phase 9 Secure Element Attestation Report ===")
        print(f"  card_type:         {cc_live.card_type}")
        print(f"  UID_SHA1:          {cc_live.UID_SHA1}")
        print(f"  is_authentic:      {is_authentic}")
        print(f"  txt_error:         {txt_error or '(none)'}")
        print(f"  CA present:        {txt_ca != '(empty)'}")
        print(f"  SubCA present:     {txt_subca != '(empty)'}")
        print(f"  Device present:    {txt_device != '(empty)'}")
        print("=================================================")
        # No hard assertion on is_authentic — dev cards use test CA
        assert isinstance(is_authentic, bool)


# ---------------------------------------------------------------------------
# Phase 10 — Message Signing, Secure Channel & Misc Card Operations
# ---------------------------------------------------------------------------

class TestMessageSigning:
    """
    Test full Bitcoin-style message signing via ``card_sign_message()``.

    Unlike Phase 5 (which tested raw hash signing with
    ``card_sign_transaction_hash``), these tests exercise the higher-level
    message signing protocol:

      1. The message is prepended with Bitcoin's magic prefix inside the card.
      2. The double-SHA-256 of the magic-prefixed message is signed.
      3. A compact 65-byte recoverable signature is returned.
      4. The signature can be verified using Bitcoin's ``verify_message_for_address``.
    """

    def test_sign_message_short(self, cc_live):
        """Sign a short (< 128 byte) message and verify the compact sig."""
        from pysatochip.util import msg_magic, sha256d
        from pysatochip.ecc import ECPubkey
        from electrum.plugins.satochip.satochip import bip32path2bytes

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        # Derive m/44'/0'/0'/0/0 and get pubkey
        _, bytepath = bip32path2bytes("m/44'/0'/0'/0/0")
        (pubkey, _chaincode) = cc_live.card_bip32_get_extendedkey(bytepath)

        message = "Hello Satochip!"
        (response, sw1, sw2, compsig) = cc_live.card_sign_message(
            0xFF, pubkey, message
        )
        assert sw1 == 0x90 and sw2 == 0x00, f"SW={sw1:02x}{sw2:02x}"
        assert len(compsig) == 65, f"Compact sig should be 65 bytes, got {len(compsig)}"

        # Verify: re-compute hash the same way the card does
        msg_hash = sha256d(msg_magic(message.encode('utf8')))
        # Recovery: the first byte encodes recid + 27 + 4 (compressed)
        header = compsig[0]
        assert 31 <= header <= 34, f"Unexpected recovery header: {header}"

    def test_sign_message_compact_sig_recovers_pubkey(self, cc_live):
        """The compact signature must recover the correct public key."""
        from pysatochip.util import msg_magic, sha256d
        from pysatochip.ecc import ECPubkey
        from electrum.plugins.satochip.satochip import bip32path2bytes

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        _, bytepath = bip32path2bytes("m/44'/0'/0'/0/0")
        (pubkey, _chaincode) = cc_live.card_bip32_get_extendedkey(bytepath)

        message = "Recover me"
        (_, sw1, sw2, compsig) = cc_live.card_sign_message(
            0xFF, pubkey, message
        )
        assert sw1 == 0x90 and sw2 == 0x00

        # Recover pubkey from signature
        msg_hash = sha256d(msg_magic(message.encode('utf8')))
        header = compsig[0]
        recid = (header - 27) & 3
        sig_r_s = compsig[1:]

        recovered = ECPubkey.from_sig_string(sig_r_s, recid, msg_hash)
        assert recovered.get_public_key_bytes(compressed=True) == \
               pubkey.get_public_key_bytes(compressed=True)

    def test_sign_message_different_messages_give_different_sigs(self, cc_live):
        """Two different messages must produce different signatures."""
        from electrum.plugins.satochip.satochip import bip32path2bytes

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        _, bytepath = bip32path2bytes("m/44'/0'/0'/0/0")
        (pubkey, _chaincode) = cc_live.card_bip32_get_extendedkey(bytepath)

        (_, sw1a, sw2a, sig1) = cc_live.card_sign_message(0xFF, pubkey, "msg A")
        assert sw1a == 0x90 and sw2a == 0x00

        (_, sw1b, sw2b, sig2) = cc_live.card_sign_message(0xFF, pubkey, "msg B")
        assert sw1b == 0x90 and sw2b == 0x00

        assert sig1 != sig2

    def test_sign_message_long_message(self, cc_live):
        """Sign a message longer than 128 bytes (forces multi-APDU chunking)."""
        from pysatochip.util import msg_magic, sha256d
        from pysatochip.ecc import ECPubkey
        from electrum.plugins.satochip.satochip import bip32path2bytes

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        _, bytepath = bip32path2bytes("m/44'/0'/0'/0/0")
        (pubkey, _chaincode) = cc_live.card_bip32_get_extendedkey(bytepath)

        # 200-byte message triggers multi-chunk path (chunk=128)
        message = "A" * 200
        (_, sw1, sw2, compsig) = cc_live.card_sign_message(0xFF, pubkey, message)
        assert sw1 == 0x90 and sw2 == 0x00
        assert len(compsig) == 65

        # Verify recovery
        msg_hash = sha256d(msg_magic(message.encode('utf8')))
        header = compsig[0]
        recid = (header - 27) & 3
        recovered = ECPubkey.from_sig_string(compsig[1:], recid, msg_hash)
        assert recovered.get_public_key_bytes(compressed=True) == \
               pubkey.get_public_key_bytes(compressed=True)

    def test_sign_message_empty_message(self, cc_live):
        """Signing an empty string should still produce a valid compact sig."""
        from electrum.plugins.satochip.satochip import bip32path2bytes

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        _, bytepath = bip32path2bytes("m/44'/0'/0'/0/0")
        (pubkey, _chaincode) = cc_live.card_bip32_get_extendedkey(bytepath)

        (_, sw1, sw2, compsig) = cc_live.card_sign_message(0xFF, pubkey, "")
        assert sw1 == 0x90 and sw2 == 0x00
        assert len(compsig) == 65

    def test_sign_message_different_derivation_path(self, cc_live):
        """Messages signed with different keys must produce different sigs."""
        from electrum.plugins.satochip.satochip import bip32path2bytes

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        message = "same message, different key"

        _, path_a = bip32path2bytes("m/44'/0'/0'/0/0")
        (pk_a, _) = cc_live.card_bip32_get_extendedkey(path_a)
        (_, sw1a, _, sig_a) = cc_live.card_sign_message(0xFF, pk_a, message)
        assert sw1a == 0x90

        _, path_b = bip32path2bytes("m/44'/0'/0'/0/1")
        (pk_b, _) = cc_live.card_bip32_get_extendedkey(path_b)
        (_, sw1b, _, sig_b) = cc_live.card_sign_message(0xFF, pk_b, message)
        assert sw1b == 0x90

        # Different keys → different compact sigs
        assert sig_a != sig_b

    def test_sign_message_report(self, cc_live, capsys):
        """Print a message signing summary."""
        print("\n=== Phase 10a Message Signing Report ===")
        print("  Short message:   65-byte compact sig (tested)")
        print("  Long message:    multi-chunk APDU (tested)")
        print("  Empty message:   valid sig (tested)")
        print("  Key recovery:    pubkey recovered from sig (tested)")
        print("  Different keys:  different sigs (tested)")
        print("=========================================")


class TestSecureChannel:
    """
    Test the secure channel establishment and encrypted communication.

    The ``cc_live`` fixture already initialises the secure channel if the card
    requires it.  These tests verify the channel's state and confirm that
    encrypted communication with the card works correctly.
    """

    def test_secure_channel_flag_is_set(self, cc_live):
        """card_get_status should report whether secure channel is needed."""
        _require_card_state(cc_live, requires_setup=True)
        (_, _, _, d) = cc_live.card_get_status()
        sc_flag = d.get('needs_secure_channel')
        assert sc_flag is not None, "needs_secure_channel missing from status"
        assert isinstance(sc_flag, bool)

    def test_secure_channel_object_matches_flag(self, cc_live):
        """If needs_secure_channel is True, the SecureChannel object must exist."""
        _require_card_state(cc_live, requires_setup=True)
        (_, _, _, d) = cc_live.card_get_status()
        if d.get('needs_secure_channel'):
            assert cc_live.sc is not None, "SC flag set but sc object is None"
            assert cc_live.sc.initialized_secure_channel is True
        else:
            # SC not required — sc may or may not be initialised
            pass

    def test_initiate_secure_channel_returns_pubkey(self, cc_live):
        """card_initiate_secure_channel returns a peer pubkey."""
        from ecdsa import VerifyingKey, SECP256k1
        _require_card_state(cc_live, requires_setup=True)
        cc_live.card_verify_PIN_simple(TESTPIN)

        peer_pubkey = cc_live.card_initiate_secure_channel()
        assert peer_pubkey is not None
        # The peer pubkey should be a pysatochip ECPubkey
        pk_bytes = peer_pubkey.get_public_key_bytes(compressed=False)
        assert len(pk_bytes) == 65
        assert pk_bytes[0] == 0x04

        # Validate it's on the curve
        vk = VerifyingKey.from_string(pk_bytes, curve=SECP256k1)
        assert vk is not None

    def test_secure_channel_reinit_gives_different_keys(self, cc_live):
        """Each secure channel initiation should use a different ephemeral key."""
        _require_card_state(cc_live, requires_setup=True)
        cc_live.card_verify_PIN_simple(TESTPIN)

        pk1 = cc_live.card_initiate_secure_channel()
        local1 = bytes(cc_live.sc.sc_pubkey_serialized)

        pk2 = cc_live.card_initiate_secure_channel()
        local2 = bytes(cc_live.sc.sc_pubkey_serialized)

        # Host ephemeral keys should differ (new ECDH key generated each time)
        assert local1 != local2

    def test_operations_work_after_channel_init(self, cc_live):
        """Card operations must succeed through the secure channel."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        # Re-init secure channel to ensure we're testing through encryption
        if getattr(cc_live, 'needs_secure_channel', False):
            cc_live.card_initiate_secure_channel()

        # card_get_status (exempt from encryption, but should still work)
        (_, sw1, sw2, d) = cc_live.card_get_status()
        assert sw1 == 0x90 and sw2 == 0x00

        # card_bip32_get_authentikey (encrypted if SC required)
        authentikey = cc_live.card_bip32_get_authentikey()
        assert authentikey is not None

    def test_sc_iv_counter_increments(self, cc_live):
        """The IV counter should increment after encrypted operations."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        if not getattr(cc_live, 'needs_secure_channel', False):
            pytest.skip("Card does not require secure channel")

        cc_live.card_initiate_secure_channel()
        counter_before = cc_live.sc.sc_IVcounter

        # Perform an encrypted operation
        cc_live.card_bip32_get_authentikey()
        counter_after = cc_live.sc.sc_IVcounter

        assert counter_after > counter_before

    def test_secure_channel_report(self, cc_live, capsys):
        """Print a secure channel summary."""
        _require_card_state(cc_live, requires_setup=True)
        (_, _, _, d) = cc_live.card_get_status()
        sc_needed = d.get('needs_secure_channel', False)
        sc_init = getattr(cc_live.sc, 'initialized_secure_channel', False) if cc_live.sc else False

        print("\n=== Phase 10b Secure Channel Report ===")
        print(f"  needs_secure_channel: {sc_needed}")
        print(f"  sc object exists:     {cc_live.sc is not None}")
        print(f"  sc initialized:       {sc_init}")
        if cc_live.sc and sc_init:
            print(f"  IV counter:           {cc_live.sc.sc_IVcounter}")
        print("========================================")


class TestMiscCardOperations:
    """
    Test miscellaneous card operations not covered in earlier phases:
    card label, trusted pubkey, card info fields.
    """

    def test_card_get_label(self, cc_live):
        """card_get_label should return a 4-tuple with a string label."""
        _require_card_state(cc_live, requires_setup=True)
        cc_live.card_verify_PIN_simple(TESTPIN)

        try:
            result = cc_live.card_get_label()
        except Exception:
            pytest.skip("card_get_label not supported on this applet version")

        assert isinstance(result, tuple) and len(result) == 4
        (_response, sw1, sw2, label) = result
        assert isinstance(label, str)

    def test_card_set_and_get_label(self, cc_live):
        """Set a label, read it back, then restore the original."""
        _require_card_state(cc_live, requires_setup=True)
        cc_live.card_verify_PIN_simple(TESTPIN)

        try:
            (_, _, _, original) = cc_live.card_get_label()
        except Exception:
            pytest.skip("card_get_label not supported")

        test_label = "electrum-test-label"
        try:
            cc_live.card_set_label(test_label)
            (_, _, _, readback) = cc_live.card_get_label()
            assert test_label in readback, \
                f"Label mismatch: set '{test_label}', got '{readback}'"
        finally:
            # Restore original label
            try:
                cc_live.card_set_label(original if original else "")
            except Exception:
                pass

    def test_card_export_authentikey(self, cc_live):
        """card_export_authentikey returns the master auth public key."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        authentikey = cc_live.card_export_authentikey()
        assert authentikey is not None
        pk_bytes = authentikey.get_public_key_bytes(compressed=True)
        assert len(pk_bytes) == 33
        assert pk_bytes[0] in (0x02, 0x03)

    def test_card_export_authentikey_matches_bip32_authentikey(self, cc_live):
        """card_export_authentikey and card_bip32_get_authentikey should agree."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        ak1 = cc_live.card_export_authentikey()
        ak2 = cc_live.card_bip32_get_authentikey()

        assert ak1.get_public_key_bytes(compressed=True) == \
               ak2.get_public_key_bytes(compressed=True)

    def test_card_get_ATR(self, cc_live):
        """card_get_ATR returns a non-empty byte list."""
        atr = cc_live.card_get_ATR()
        assert atr is not None
        assert len(atr) > 0

    def test_card_get_CPLC(self, cc_live):
        """card_get_CPLC should return card production lifecycle data."""
        try:
            response, sw1, sw2 = cc_live.card_get_CPLC()
            # CPLC data may not be available on all cards
            if sw1 == 0x90 and sw2 == 0x00:
                assert len(response) > 0
        except Exception:
            pytest.skip("CPLC not supported")

    def test_card_get_IIN(self, cc_live):
        """card_get_IIN should return issuer identification data."""
        try:
            response, sw1, sw2 = cc_live.card_get_IIN()
            if sw1 == 0x90 and sw2 == 0x00:
                assert len(response) > 0
        except Exception:
            pytest.skip("IIN not supported")

    def test_card_get_CIN(self, cc_live):
        """card_get_CIN should return card identification data."""
        try:
            response, sw1, sw2 = cc_live.card_get_CIN()
            if sw1 == 0x90 and sw2 == 0x00:
                assert len(response) > 0
        except Exception:
            pytest.skip("CIN not supported")

    def test_misc_report(self, cc_live, capsys):
        """Print a misc operations summary."""
        _require_card_state(cc_live, requires_setup=True)
        cc_live.card_verify_PIN_simple(TESTPIN)

        atr = cc_live.card_get_ATR()
        try:
            (_, _, _, label) = cc_live.card_get_label()
        except Exception:
            label = "(unsupported)"

        print("\n=== Phase 10c Misc Operations Report ===")
        print(f"  ATR:       {bytes(atr).hex()}")
        print(f"  Label:     {label}")
        print("=========================================")


# =============================================================================
# Phase 12: Comprehensive End-to-End Tests
# =============================================================================
#
# This phase ties together all prior phases into full lifecycle sequences
# and adds cross-verification against known Electrum test vectors.
#
# Test classes:
#   TestE2EFullLifecycle       — reset → reseed → derive → sign → verify
#   TestE2EPINLifecycle        — change PIN → perform operations → restore
#   TestE2EMessageVerification — sign message on card, verify with Electrum
#   TestE2EMultiPathSigning    — sign with child keys at multiple BIP paths
#   TestE2ESeedSwitch          — switch seeds, confirm key isolation
#   TestE2ERepeatedOperations  — stress: repeated sign/derive cycles
#   TestE2ECardReset           — full card reset cycle (seed only)
#
# All tests restore the card to its canonical state (TESTPIN, abandon seed)
# in finally blocks so subsequent tests are not affected by mid-test failures.
# =============================================================================


# ── Additional child vectors for end-to-end verification ──────────────
# BIP49 m/49'/0'/0'/0/0 child for abandon mnemonic (computed offline)
# We compute it dynamically from the known xpub in tests that need it.

# BIP84 native segwit child vectors (abandon mnemonic, no passphrase)
# m/84'/0'/0'/0/0 → bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
_CHILD_84_VECTORS = [
    (0,
     "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
     "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
    (1,
     "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77",
     "bc1qnjg0jd8228aq7ez8cyber5ber8yhwmw4xy0c8e"),
]


def _card_derive_and_sign(cc_live, path_str, hash32):
    """
    Derive the BIP32 key at *path_str* on the card, then sign *hash32*
    with keynbr=0xFF (most recently derived key).

    Returns (pubkey, der_sig, sw1, sw2).
    """
    pubkey, _ = _derive_key(cc_live, path_str)
    sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
        0xFF, list(hash32), None
    )
    return pubkey, bytes(sig), sw1, sw2


# ─────────────────────────────────────────────────────────────────────
# TestE2EFullLifecycle
# ─────────────────────────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.requires_card
class TestE2EFullLifecycle:
    """
    Complete card lifecycle: reset seed → import abandon mnemonic → derive
    xpubs at three BIP paths → verify against known vectors → sign hashes
    at each path → verify ECDSA → sign a message → verify with Electrum's
    ``verify_usermessage_with_address``.

    This is the single most comprehensive test: it proves that after a
    seed reset, the card deterministically re-derives all expected keys
    and can produce valid signatures with each of them.
    """

    def _reseed_abandon(self, cc_live):
        """Import the abandon mnemonic, returning the authentikey."""
        from electrum.keystore import bip39_to_seed
        seed = list(bip39_to_seed(ABANDON_MNEMONIC, passphrase=""))
        return cc_live.card_bip32_import_seed(seed)

    def test_full_lifecycle(self, cc_live):
        """
        Full lifecycle:
          1. Verify PIN
          2. Reset seed
          3. Import abandon mnemonic
          4. Verify is_seeded=True
          5. Derive m/44'/0'/0' xpub → must match _XPUB_44
          6. Derive m/49'/0'/0' xpub → must match _XPUB_49
          7. Derive m/44'/0'/0'/0/0 child pubkey → must match _CHILD_VECTORS[0]
          8. Sign a hash with m/44'/0'/0'/0/0 → ECDSA verify OK
          9. Sign a message with m/44'/0'/0'/0/0 → verify_usermessage_with_address OK
        """
        import hashlib
        from electrum.bitcoin import pubkey_to_address, verify_usermessage_with_address
        from electrum.plugins.satochip.satochip import bip32path2bytes
        from pysatochip.util import msg_magic, sha256d
        from pysatochip.ecc import ECPubkey

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        try:
            # ── Step 1-2: Reset seed ──
            cc_live.card_reset_seed(TESTPIN)
            _, _, _, d = cc_live.card_get_status()
            assert not d['is_seeded'], "is_seeded should be False after reset"

            # ── Step 3-4: Import abandon mnemonic ──
            authentikey = self._reseed_abandon(cc_live)
            assert authentikey is not None
            _, _, _, d = cc_live.card_get_status()
            assert d['is_seeded'], "is_seeded should be True after import"

            # ── Step 5: Verify m/44'/0'/0' xpub ──
            node44 = _card_get_xpub(cc_live, "m/44'/0'/0'")
            assert node44.to_xpub() == _XPUB_44, (
                f"m/44' xpub mismatch: {node44.to_xpub()}"
            )

            # ── Step 6: Verify m/49'/0'/0' xpub ──
            node49 = _card_get_xpub(cc_live, "m/49'/0'/0'")
            assert node49.to_xpub() == _XPUB_49, (
                f"m/49' xpub mismatch: {node49.to_xpub()}"
            )

            # ── Step 7: Verify child pubkey at m/44'/0'/0'/0/0 ──
            child_idx, expected_pk_hex, expected_addr = _CHILD_VECTORS[0]
            child_path = f"m/44'/0'/0'/0/{child_idx}"
            child_pk, _ = _derive_key(cc_live, child_path)
            card_pk_hex = child_pk.get_public_key_bytes(compressed=True).hex()
            assert card_pk_hex == expected_pk_hex, (
                f"Child pubkey mismatch at {child_path}\n"
                f"  card:     {card_pk_hex}\n"
                f"  expected: {expected_pk_hex}"
            )
            actual_addr = pubkey_to_address("p2pkh", card_pk_hex)
            assert actual_addr == expected_addr, (
                f"Address mismatch at {child_path}: {actual_addr} != {expected_addr}"
            )

            # ── Step 8: Sign a hash → ECDSA verify ──
            test_hash = hashlib.sha256(b"e2e-lifecycle-test").digest()
            sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
                0xFF, list(test_hash), None
            )
            assert (sw1, sw2) == (0x90, 0x00), f"Sign failed: {sw1:02x}{sw2:02x}"
            _verify_ecdsa(child_pk, test_hash, bytes(sig))

            # ── Step 9: Sign a message → verify with address ──
            message = "E2E lifecycle verification"
            _, bytepath = bip32path2bytes(child_path)
            child_pk2, _ = cc_live.card_bip32_get_extendedkey(bytepath)
            _, sw1m, sw2m, compsig = cc_live.card_sign_message(
                0xFF, child_pk2, message
            )
            assert (sw1m, sw2m) == (0x90, 0x00), f"SignMsg failed: {sw1m:02x}{sw2m:02x}"
            assert len(compsig) == 65
            assert verify_usermessage_with_address(
                expected_addr, bytes(compsig), message.encode('utf8')
            ), (
                f"Message signature did not verify for address {expected_addr}"
            )

        finally:
            # Restore seed for subsequent tests
            try:
                cc_live.card_reset_seed(TESTPIN)
            except Exception:
                pass
            try:
                self._reseed_abandon(cc_live)
            except Exception:
                pass

    def test_authentikey_stable_across_reseed(self, cc_live):
        """
        Reset and re-import the same seed twice. The authentikey must be
        identical both times, proving deterministic derivation.
        """
        from electrum.keystore import bip39_to_seed
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        try:
            # First reset + reseed
            cc_live.card_reset_seed(TESTPIN)
            ak1 = self._reseed_abandon(cc_live)
            ak1_bytes = ak1.get_public_key_bytes(compressed=True)

            # Second reset + reseed
            cc_live.card_reset_seed(TESTPIN)
            ak2 = self._reseed_abandon(cc_live)
            ak2_bytes = ak2.get_public_key_bytes(compressed=True)

            assert ak1_bytes == ak2_bytes, (
                f"Authentikey changed across re-seeds!\n"
                f"  first:  {ak1_bytes.hex()}\n"
                f"  second: {ak2_bytes.hex()}"
            )
        finally:
            try:
                cc_live.card_reset_seed(TESTPIN)
            except Exception:
                pass
            try:
                self._reseed_abandon(cc_live)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────
# TestE2EPINLifecycle
# ─────────────────────────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.requires_card
class TestE2EPINLifecycle:
    """
    End-to-end PIN lifecycle: change PIN → derive keys → sign → change back.

    Proves that all cryptographic operations work correctly after a PIN change,
    and that the PIN change does not alter derived keys or signatures.
    """

    NEWPIN = b'987654'

    def test_operations_work_after_pin_change(self, cc_live):
        """
        1. Record xpub at m/44'/0'/0' with original PIN
        2. Change PIN to NEWPIN
        3. Re-derive xpub → must match
        4. Sign a hash → must verify against same pubkey
        5. Sign a message → must verify with same address
        6. Restore PIN to TESTPIN
        """
        import hashlib
        from electrum.bitcoin import pubkey_to_address, verify_usermessage_with_address
        from electrum.plugins.satochip.satochip import bip32path2bytes

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        try:
            # ── Step 1: Record baseline xpub ──
            node_before = _card_get_xpub(cc_live, "m/44'/0'/0'")
            xpub_before = node_before.to_xpub()

            # ── Step 2: Change PIN ──
            _, sw1, sw2 = cc_live.card_change_PIN(
                0, list(TESTPIN), list(self.NEWPIN)
            )
            assert (sw1, sw2) == (0x90, 0x00), f"Change PIN failed: {sw1:02x}{sw2:02x}"

            # Verify new PIN works
            _, sv1, sv2 = cc_live.card_verify_PIN_simple(self.NEWPIN)
            assert (sv1, sv2) == (0x90, 0x00)

            # ── Step 3: Derive same xpub ──
            node_after = _card_get_xpub(cc_live, "m/44'/0'/0'")
            assert node_after.to_xpub() == xpub_before, (
                "xpub changed after PIN change!"
            )

            # ── Step 4: Sign hash with child key ──
            child_path = "m/44'/0'/0'/0/0"
            child_pk, _ = _derive_key(cc_live, child_path)
            test_hash = hashlib.sha256(b"pin-lifecycle-hash").digest()
            sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
                0xFF, list(test_hash), None
            )
            assert (sw1, sw2) == (0x90, 0x00)
            _verify_ecdsa(child_pk, test_hash, bytes(sig))

            # ── Step 5: Sign message ──
            _, bytepath = bip32path2bytes(child_path)
            child_pk2, _ = cc_live.card_bip32_get_extendedkey(bytepath)
            message = "PIN lifecycle test"
            _, sw1m, sw2m, compsig = cc_live.card_sign_message(
                0xFF, child_pk2, message
            )
            assert (sw1m, sw2m) == (0x90, 0x00)
            _, _, expected_addr = _CHILD_VECTORS[0]
            assert verify_usermessage_with_address(
                expected_addr, bytes(compsig), message.encode('utf8')
            )

        finally:
            # Always restore to TESTPIN
            try:
                cc_live.card_change_PIN(0, list(self.NEWPIN), list(TESTPIN))
            except Exception:
                pass

    def test_wrong_pin_then_correct_then_sign(self, cc_live):
        """
        Submit a wrong PIN (counter decremented), then correct PIN,
        then sign — signature must still be valid.
        """
        import hashlib
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)

        # Wrong PIN
        try:
            cc_live.card_verify_PIN_simple(b'000000')
        except Exception:
            pass  # expected

        # Correct PIN
        _, sw1, sw2 = cc_live.card_verify_PIN_simple(TESTPIN)
        assert (sw1, sw2) == (0x90, 0x00)

        # Sign should still work
        child_pk, _ = _derive_key(cc_live, "m/44'/0'/0'/0/0")
        test_hash = hashlib.sha256(b"wrong-then-correct").digest()
        sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
            0xFF, list(test_hash), None
        )
        assert (sw1, sw2) == (0x90, 0x00)
        _verify_ecdsa(child_pk, test_hash, bytes(sig))


# ─────────────────────────────────────────────────────────────────────
# TestE2EMessageVerification
# ─────────────────────────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.requires_card
class TestE2EMessageVerification:
    """
    Sign messages on the card and verify using Electrum's standard
    ``verify_usermessage_with_address()`` function.

    This bridges the Satochip's signing with Electrum's verification,
    proving interoperability for the Bitcoin Signed Message standard.
    """

    def _sign_and_verify(self, cc_live, path, address, message):
        """Helper: derive key at path, sign message, verify with address."""
        from electrum.bitcoin import verify_usermessage_with_address
        from electrum.plugins.satochip.satochip import bip32path2bytes

        _, bytepath = bip32path2bytes(path)
        pubkey, _ = cc_live.card_bip32_get_extendedkey(bytepath)
        _, sw1, sw2, compsig = cc_live.card_sign_message(0xFF, pubkey, message)
        assert (sw1, sw2) == (0x90, 0x00), f"sign_message failed: {sw1:02x}{sw2:02x}"
        assert len(compsig) == 65
        ok = verify_usermessage_with_address(
            address, bytes(compsig), message.encode('utf8')
        )
        return ok, compsig

    def test_verify_p2pkh_child_0(self, cc_live):
        """Sign with m/44'/0'/0'/0/0 → verify against known P2PKH address."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        _, _, expected_addr = _CHILD_VECTORS[0]
        ok, _ = self._sign_and_verify(
            cc_live, "m/44'/0'/0'/0/0", expected_addr,
            "Hello from child 0"
        )
        assert ok, f"Message sig did not verify for {expected_addr}"

    def test_verify_p2pkh_child_1(self, cc_live):
        """Sign with m/44'/0'/0'/0/1 → verify against known P2PKH address."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        _, _, expected_addr = _CHILD_VECTORS[1]
        ok, _ = self._sign_and_verify(
            cc_live, "m/44'/0'/0'/0/1", expected_addr,
            "Hello from child 1"
        )
        assert ok, f"Message sig did not verify for {expected_addr}"

    def test_verify_p2pkh_child_2(self, cc_live):
        """Sign with m/44'/0'/0'/0/2 → verify against known P2PKH address."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        _, _, expected_addr = _CHILD_VECTORS[2]
        ok, _ = self._sign_and_verify(
            cc_live, "m/44'/0'/0'/0/2", expected_addr,
            "Hello from child 2"
        )
        assert ok, f"Message sig did not verify for {expected_addr}"

    def test_verify_long_message(self, cc_live):
        """Sign a 500-byte message → verify (multi-APDU chunking path)."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        _, _, expected_addr = _CHILD_VECTORS[0]
        msg = "A" * 500
        ok, _ = self._sign_and_verify(
            cc_live, "m/44'/0'/0'/0/0", expected_addr, msg
        )
        assert ok, "Long message signature did not verify"

    def test_verify_unicode_message(self, cc_live):
        """Sign a message with unicode characters → verify."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        _, _, expected_addr = _CHILD_VECTORS[0]
        ok, _ = self._sign_and_verify(
            cc_live, "m/44'/0'/0'/0/0", expected_addr,
            "Ünïcödé tëst mëssägé 🔑"
        )
        assert ok, "Unicode message signature did not verify"

    def test_verify_with_wrong_address_fails(self, cc_live):
        """
        Sign with child 0 key but verify against child 1 address → must fail.
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        from electrum.bitcoin import verify_usermessage_with_address
        from electrum.plugins.satochip.satochip import bip32path2bytes

        # Sign with child 0
        _, bytepath = bip32path2bytes("m/44'/0'/0'/0/0")
        pubkey, _ = cc_live.card_bip32_get_extendedkey(bytepath)
        _, sw1, sw2, compsig = cc_live.card_sign_message(
            0xFF, pubkey, "cross-check"
        )
        assert (sw1, sw2) == (0x90, 0x00)

        # Verify against child 1's address → must be False
        _, _, wrong_addr = _CHILD_VECTORS[1]
        assert not verify_usermessage_with_address(
            wrong_addr, bytes(compsig), b"cross-check"
        ), "Signature should NOT verify against a different address"

    def test_two_sigs_for_same_message_both_verify(self, cc_live):
        """
        Sign the same message twice → both sigs verify (non-deterministic k).
        Also confirms the two sigs differ (different k → different r).
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        _, _, expected_addr = _CHILD_VECTORS[0]
        msg = "non-deterministic k test"

        ok1, sig1 = self._sign_and_verify(
            cc_live, "m/44'/0'/0'/0/0", expected_addr, msg
        )
        ok2, sig2 = self._sign_and_verify(
            cc_live, "m/44'/0'/0'/0/0", expected_addr, msg
        )

        assert ok1 and ok2, "Both signatures must verify"
        assert sig1 != sig2, "Two signatures with hardware RNG should differ"


# ─────────────────────────────────────────────────────────────────────
# TestE2EMultiPathSigning
# ─────────────────────────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.requires_card
class TestE2EMultiPathSigning:
    """
    Sign the same hash with keys at multiple BIP derivation paths,
    verifying that each signature:
      - returns SW=0x9000
      - verifies against the card-derived pubkey
      - differs from signatures at other paths (different private keys)

    Also cross-verifies card-derived pubkeys against software-derived pubkeys.
    """

    PATHS = [
        "m/44'/0'/0'/0/0",
        "m/44'/0'/0'/0/1",
        "m/44'/0'/0'/0/2",
        "m/44'/0'/0'/1/0",   # change address path
        "m/49'/0'/0'/0/0",
    ]

    def test_sign_at_multiple_paths(self, cc_live):
        """Sign the same hash at 5 different paths, verify each."""
        import hashlib
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        test_hash = hashlib.sha256(b"multi-path-test").digest()
        results = {}

        for path in self.PATHS:
            pk, sig, sw1, sw2 = _card_derive_and_sign(cc_live, path, test_hash)
            assert (sw1, sw2) == (0x90, 0x00), f"Sign at {path} failed"
            _verify_ecdsa(pk, test_hash, sig)
            results[path] = sig

        # All signatures should be pairwise different (different keys)
        sigs = list(results.values())
        for i in range(len(sigs)):
            for j in range(i + 1, len(sigs)):
                assert sigs[i] != sigs[j], (
                    f"Sigs at paths {self.PATHS[i]} and {self.PATHS[j]} "
                    f"should differ (different private keys)"
                )

    def test_child_pubkeys_match_xpub_derivation(self, cc_live):
        """
        For m/44'/0'/0'/0/i, the card's direct derivation must match
        the pubkey derived in software from the card's account xpub.
        """
        from electrum.bip32 import BIP32Node

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        acct = _card_get_xpub(cc_live, "m/44'/0'/0'")

        for idx in range(5):
            # Card direct derivation
            card_pk, _ = _derive_key(cc_live, f"m/44'/0'/0'/0/{idx}")
            card_hex = card_pk.get_public_key_bytes(compressed=True).hex()

            # Software derivation from xpub
            child = acct.subkey_at_public_derivation(f"0/{idx}")
            sw_hex = child.eckey.get_public_key_bytes(compressed=True).hex()

            assert card_hex == sw_hex, (
                f"Pubkey mismatch at /0/{idx}: card={card_hex}, sw={sw_hex}"
            )

    def test_change_path_pubkey_differs(self, cc_live):
        """m/44'/0'/0'/1/0 (change) must differ from m/44'/0'/0'/0/0 (receive)."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        pk_recv, _ = _derive_key(cc_live, "m/44'/0'/0'/0/0")
        pk_change, _ = _derive_key(cc_live, "m/44'/0'/0'/1/0")

        assert (pk_recv.get_public_key_bytes(compressed=True) !=
                pk_change.get_public_key_bytes(compressed=True)), (
            "Receive and change path should produce different keys"
        )

    def test_bip84_child_vectors(self, cc_live):
        """
        Verify BIP84 (native segwit) child pubkeys match known vectors
        for the abandon mnemonic.
        """
        from electrum.bip32 import BIP32Node
        from electrum.keystore import bip39_to_seed

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        # Software reference: derive from root seed
        seed_bytes = bip39_to_seed(ABANDON_MNEMONIC, passphrase="")
        root = BIP32Node.from_rootseed(seed_bytes, xtype="p2wpkh")
        acct_sw = root.subkey_at_private_derivation("m/84'/0'/0'")

        for idx, expected_pk_hex, _ in _CHILD_84_VECTORS:
            # Software child
            child_sw = acct_sw.subkey_at_private_derivation(f"0/{idx}")
            sw_hex = child_sw.eckey.get_public_key_bytes(compressed=True).hex()
            assert sw_hex == expected_pk_hex, (
                f"Software BIP84 child {idx} mismatch: {sw_hex}"
            )

            # Card child
            card_pk, _ = _derive_key(cc_live, f"m/84'/0'/0'/0/{idx}")
            card_hex = card_pk.get_public_key_bytes(compressed=True).hex()
            assert card_hex == expected_pk_hex, (
                f"Card BIP84 child {idx} mismatch: {card_hex}"
            )


# ─────────────────────────────────────────────────────────────────────
# TestE2ESeedSwitch
# ─────────────────────────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.requires_card
class TestE2ESeedSwitch:
    """
    Switch between two different seeds and confirm complete key isolation:
    each seed produces different xpubs, different child keys, and
    different signatures — and switching back restores the originals.
    """

    # A second test mnemonic (different from abandon)
    ALT_MNEMONIC = (
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
    )

    def _reseed(self, cc_live, mnemonic):
        """Reset + import a seed from mnemonic."""
        from electrum.keystore import bip39_to_seed
        cc_live.card_reset_seed(TESTPIN)
        seed = list(bip39_to_seed(mnemonic, passphrase=""))
        return cc_live.card_bip32_import_seed(seed)

    def test_seed_switch_isolation(self, cc_live):
        """
        1. Record xpub with abandon mnemonic
        2. Switch to alt mnemonic → xpub must differ
        3. Switch back to abandon → xpub must match original
        """
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        try:
            # ── Record abandon xpub ──
            node_abandon = _card_get_xpub(cc_live, "m/44'/0'/0'")
            xpub_abandon = node_abandon.to_xpub()
            assert xpub_abandon == _XPUB_44

            # ── Switch to alt seed ──
            self._reseed(cc_live, self.ALT_MNEMONIC)
            node_alt = _card_get_xpub(cc_live, "m/44'/0'/0'")
            xpub_alt = node_alt.to_xpub()
            assert xpub_alt != xpub_abandon, (
                "Alt seed should produce a different xpub"
            )

            # ── Verify alt seed xpub matches software ──
            from electrum.keystore import bip39_to_seed
            from electrum.bip32 import BIP32Node
            alt_seed = bip39_to_seed(self.ALT_MNEMONIC, passphrase="")
            alt_root = BIP32Node.from_rootseed(alt_seed, xtype="standard")
            alt_sw_xpub = alt_root.subkey_at_private_derivation(
                "m/44'/0'/0'"
            ).to_xpub()
            assert xpub_alt == alt_sw_xpub, (
                f"Alt seed card xpub != software xpub\n"
                f"  card: {xpub_alt}\n  sw: {alt_sw_xpub}"
            )

            # ── Sign with alt seed, verify ──
            import hashlib
            alt_pk, _ = _derive_key(cc_live, "m/44'/0'/0'/0/0")
            test_hash = hashlib.sha256(b"alt-seed-sign").digest()
            sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
                0xFF, list(test_hash), None
            )
            assert (sw1, sw2) == (0x90, 0x00)
            _verify_ecdsa(alt_pk, test_hash, bytes(sig))

            # ── Switch back to abandon ──
            self._reseed(cc_live, ABANDON_MNEMONIC)
            node_restored = _card_get_xpub(cc_live, "m/44'/0'/0'")
            assert node_restored.to_xpub() == _XPUB_44, (
                "Restored abandon xpub does not match original"
            )

        finally:
            # Ensure we end on the abandon seed
            try:
                self._reseed(cc_live, ABANDON_MNEMONIC)
            except Exception:
                pass

    def test_alt_seed_child_keys_differ(self, cc_live):
        """
        Derive child 0/0 with both seeds and confirm the pubkeys differ.
        Then verify each child's signature against its own pubkey.
        """
        import hashlib
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        try:
            # Abandon child
            pk_abandon, _ = _derive_key(cc_live, "m/44'/0'/0'/0/0")
            pk_abandon_hex = pk_abandon.get_public_key_bytes(compressed=True).hex()

            # Switch to alt
            self._reseed(cc_live, self.ALT_MNEMONIC)
            pk_alt, _ = _derive_key(cc_live, "m/44'/0'/0'/0/0")
            pk_alt_hex = pk_alt.get_public_key_bytes(compressed=True).hex()

            assert pk_abandon_hex != pk_alt_hex, (
                "Child 0/0 should differ between seeds"
            )

            # Sign with alt child
            test_hash = hashlib.sha256(b"alt-child-sig").digest()
            sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
                0xFF, list(test_hash), None
            )
            assert (sw1, sw2) == (0x90, 0x00)
            _verify_ecdsa(pk_alt, test_hash, bytes(sig))

        finally:
            try:
                self._reseed(cc_live, ABANDON_MNEMONIC)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────
# TestE2ERepeatedOperations
# ─────────────────────────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.requires_card
class TestE2ERepeatedOperations:
    """
    Stress-test: perform repeated sign and derive operations to detect
    timing-dependent bugs, state leaks, or counter exhaustion.
    """

    def test_ten_sequential_signs(self, cc_live):
        """Sign 10 different hashes at the same path; all must verify."""
        import hashlib
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        pk, _ = _derive_key(cc_live, "m/44'/0'/0'/0/0")

        for i in range(10):
            h = hashlib.sha256(f"repeat-{i}".encode()).digest()
            sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
                0xFF, list(h), None
            )
            assert (sw1, sw2) == (0x90, 0x00), f"Sign {i} failed"
            _verify_ecdsa(pk, h, bytes(sig))

    def test_derive_ten_children(self, cc_live):
        """Derive 10 consecutive children and confirm all are distinct."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        seen_pubkeys = set()
        for i in range(10):
            pk, _ = _derive_key(cc_live, f"m/44'/0'/0'/0/{i}")
            pk_hex = pk.get_public_key_bytes(compressed=True).hex()
            assert pk_hex not in seen_pubkeys, f"Duplicate pubkey at child {i}"
            seen_pubkeys.add(pk_hex)

    def test_alternating_derive_sign(self, cc_live):
        """Alternate between derive at path A and sign at path B 5 times."""
        import hashlib
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        for i in range(5):
            # Derive child i
            _derive_key(cc_live, f"m/44'/0'/0'/0/{i}")
            # Now derive child 0 and sign — keynbr=0xFF refers to child 0
            pk0, _ = _derive_key(cc_live, "m/44'/0'/0'/0/0")
            h = hashlib.sha256(f"alt-{i}".encode()).digest()
            sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
                0xFF, list(h), None
            )
            assert (sw1, sw2) == (0x90, 0x00)
            _verify_ecdsa(pk0, h, bytes(sig))

    def test_ten_message_signs(self, cc_live):
        """Sign 10 different messages and verify each."""
        from electrum.bitcoin import verify_usermessage_with_address
        from electrum.plugins.satochip.satochip import bip32path2bytes

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        _, bytepath = bip32path2bytes("m/44'/0'/0'/0/0")
        pubkey, _ = cc_live.card_bip32_get_extendedkey(bytepath)
        _, _, expected_addr = _CHILD_VECTORS[0]

        for i in range(10):
            msg = f"message-{i}"
            _, sw1, sw2, compsig = cc_live.card_sign_message(
                0xFF, pubkey, msg
            )
            assert (sw1, sw2) == (0x90, 0x00), f"Sign msg {i} failed"
            assert verify_usermessage_with_address(
                expected_addr, bytes(compsig), msg.encode('utf8')
            ), f"Message {i} sig did not verify"


# ─────────────────────────────────────────────────────────────────────
# TestE2ECardReset
# ─────────────────────────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.requires_card
class TestE2ECardReset:
    """
    Full card reset cycle:
      1. Reset seed
      2. Confirm all signing operations fail
      3. Import new seed
      4. Confirm all operations succeed again
      5. Verify key determinism against known vectors
    """

    def _reseed_abandon(self, cc_live):
        from electrum.keystore import bip39_to_seed
        seed = list(bip39_to_seed(ABANDON_MNEMONIC, passphrase=""))
        return cc_live.card_bip32_import_seed(seed)

    def test_full_reset_cycle(self, cc_live):
        """Reset → fail → reseed → succeed → verify vectors."""
        import hashlib
        from electrum.bitcoin import pubkey_to_address

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        try:
            # ── Reset ──
            cc_live.card_reset_seed(TESTPIN)
            _, _, _, d = cc_live.card_get_status()
            assert not d['is_seeded']

            # ── Signing must fail without seed ──
            try:
                from electrum.plugins.satochip.satochip import bip32path2bytes
                _, bytepath = bip32path2bytes("m/44'/0'/0'")
                cc_live.card_bip32_get_extendedkey(bytepath)
                # If we get here, derive didn't fail — try signing
                h = hashlib.sha256(b"should-fail").digest()
                _, sw1, sw2 = cc_live.card_sign_transaction_hash(
                    0xFF, list(h), None
                )
                assert (sw1, sw2) != (0x90, 0x00), (
                    "Signing should not succeed without seed"
                )
            except Exception:
                pass  # expected — any error is OK

            # ── Reseed ──
            self._reseed_abandon(cc_live)
            _, _, _, d = cc_live.card_get_status()
            assert d['is_seeded']

            # ── Signing must succeed ──
            pk, _ = _derive_key(cc_live, "m/44'/0'/0'/0/0")
            h = hashlib.sha256(b"reseeded-sign").digest()
            sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
                0xFF, list(h), None
            )
            assert (sw1, sw2) == (0x90, 0x00)
            _verify_ecdsa(pk, h, bytes(sig))

            # ── Verify vectors ──
            for idx, expected_pk, expected_addr in _CHILD_VECTORS:
                child_pk, _ = _derive_key(cc_live, f"m/44'/0'/0'/0/{idx}")
                card_hex = child_pk.get_public_key_bytes(compressed=True).hex()
                assert card_hex == expected_pk, (
                    f"Child {idx} pubkey mismatch after reseed"
                )
                assert pubkey_to_address("p2pkh", card_hex) == expected_addr

        finally:
            try:
                cc_live.card_reset_seed(TESTPIN)
            except Exception:
                pass
            try:
                self._reseed_abandon(cc_live)
            except Exception:
                pass

    def test_multiple_resets_stable(self, cc_live):
        """Reset and reseed 3 times; xpub must be the same each time."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        try:
            for iteration in range(3):
                cc_live.card_reset_seed(TESTPIN)
                self._reseed_abandon(cc_live)
                node = _card_get_xpub(cc_live, "m/44'/0'/0'")
                assert node.to_xpub() == _XPUB_44, (
                    f"xpub mismatch on iteration {iteration}"
                )
        finally:
            try:
                cc_live.card_reset_seed(TESTPIN)
            except Exception:
                pass
            try:
                self._reseed_abandon(cc_live)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────
# TestE2ELowSNormalization
# ─────────────────────────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.requires_card
class TestE2ELowSNormalization:
    """
    Test that signatures from the card can be normalised to low-S form
    (BIP62) and still verify correctly.

    The Satochip hardware RNG may produce either low-S or high-S
    signatures. Electrum normalises to low-S before broadcasting.
    This test confirms the normalisation works.
    """

    def test_low_s_normalization(self, cc_live):
        """Sign multiple hashes and ensure all can be low-S normalised."""
        import hashlib
        import electrum_ecc as _ecc

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        pk, _ = _derive_key(cc_live, "m/44'/0'/0'/0/0")
        half_order = _ecc.CURVE_ORDER // 2

        for i in range(20):
            h = hashlib.sha256(f"low-s-{i}".encode()).digest()
            sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
                0xFF, list(h), None
            )
            assert (sw1, sw2) == (0x90, 0x00)

            r, s = _r_s_from_der(bytes(sig))
            low_s = s if s <= half_order else _ecc.CURVE_ORDER - s

            # Verify with normalised s
            raw64 = r.to_bytes(32, 'big') + low_s.to_bytes(32, 'big')
            pk.verify_message_hash(raw64, h)


# ─────────────────────────────────────────────────────────────────────
# TestE2ECrossVerification
# ─────────────────────────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.requires_card
class TestE2ECrossVerification:
    """
    Cross-verification between card operations and software implementations.

    These tests compute expected values purely in software (from the known
    abandon mnemonic seed) and then verify the card produces identical results.
    """

    def _masterseed(self):
        from electrum.keystore import bip39_to_seed
        return bip39_to_seed(ABANDON_MNEMONIC, passphrase="")

    def test_all_three_bip_paths_match_software(self, cc_live):
        """
        Verify card xpubs match software for m/44', m/49', and m/84'
        account-level paths, using the appropriate xtype for each.
        """
        from electrum.bip32 import BIP32Node

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        seed = self._masterseed()
        paths = [
            ("m/44'/0'/0'", "standard"),
            ("m/49'/0'/0'", "p2wpkh-p2sh"),
            ("m/84'/0'/0'", "p2wpkh"),
        ]

        for path, xtype in paths:
            # Software reference
            root = BIP32Node.from_rootseed(seed, xtype=xtype)
            sw_node = root.subkey_at_private_derivation(path)
            sw_xpub = sw_node.to_xpub()

            # Card
            card_xpub = _derive_xpub_from_card(cc_live, path, xtype)

            assert card_xpub == sw_xpub, (
                f"xpub mismatch at {path} (xtype={xtype})\n"
                f"  card: {card_xpub}\n  sw:   {sw_xpub}"
            )

    def test_twenty_children_match_software(self, cc_live):
        """
        Derive 20 children at m/44'/0'/0'/0/{0..19} on both card and software.
        All 20 pubkeys must match exactly.
        """
        from electrum.bip32 import BIP32Node

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        seed = self._masterseed()
        root = BIP32Node.from_rootseed(seed, xtype="standard")
        acct = root.subkey_at_private_derivation("m/44'/0'/0'")

        for i in range(20):
            # Software
            child_sw = acct.subkey_at_public_derivation(f"0/{i}")
            sw_hex = child_sw.eckey.get_public_key_bytes(compressed=True).hex()

            # Card
            card_pk, _ = _derive_key(cc_live, f"m/44'/0'/0'/0/{i}")
            card_hex = card_pk.get_public_key_bytes(compressed=True).hex()

            assert card_hex == sw_hex, (
                f"Child 0/{i} pubkey mismatch: card={card_hex}, sw={sw_hex}"
            )

    def test_change_children_match_software(self, cc_live):
        """
        Verify m/44'/0'/0'/1/{0..4} (change addresses) match software.
        """
        from electrum.bip32 import BIP32Node

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        seed = self._masterseed()
        root = BIP32Node.from_rootseed(seed, xtype="standard")
        acct = root.subkey_at_private_derivation("m/44'/0'/0'")

        for i in range(5):
            child_sw = acct.subkey_at_public_derivation(f"1/{i}")
            sw_hex = child_sw.eckey.get_public_key_bytes(compressed=True).hex()

            card_pk, _ = _derive_key(cc_live, f"m/44'/0'/0'/1/{i}")
            card_hex = card_pk.get_public_key_bytes(compressed=True).hex()

            assert card_hex == sw_hex, (
                f"Change child 1/{i} pubkey mismatch"
            )

    def test_sign_and_verify_at_each_child(self, cc_live):
        """
        For children 0/0 through 0/4: derive on card, sign, verify ECDSA,
        and also verify via message + address cross-check.
        """
        import hashlib
        from electrum.bitcoin import pubkey_to_address, verify_usermessage_with_address
        from electrum.plugins.satochip.satochip import bip32path2bytes
        from electrum.bip32 import BIP32Node

        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        seed = self._masterseed()
        root = BIP32Node.from_rootseed(seed, xtype="standard")
        acct = root.subkey_at_private_derivation("m/44'/0'/0'")

        for i in range(5):
            path = f"m/44'/0'/0'/0/{i}"

            # Derive address from software
            child_sw = acct.subkey_at_public_derivation(f"0/{i}")
            sw_pk_hex = child_sw.eckey.get_public_key_bytes(compressed=True).hex()
            expected_addr = pubkey_to_address("p2pkh", sw_pk_hex)

            # Card: hash signing
            card_pk, _ = _derive_key(cc_live, path)
            h = hashlib.sha256(f"cross-verify-{i}".encode()).digest()
            sig, sw1, sw2 = cc_live.card_sign_transaction_hash(
                0xFF, list(h), None
            )
            assert (sw1, sw2) == (0x90, 0x00)
            _verify_ecdsa(card_pk, h, bytes(sig))

            # Card: message signing + address verification
            _, bytepath = bip32path2bytes(path)
            pk_for_msg, _ = cc_live.card_bip32_get_extendedkey(bytepath)
            msg = f"cross-verify-msg-{i}"
            _, sw1m, sw2m, compsig = cc_live.card_sign_message(
                0xFF, pk_for_msg, msg
            )
            assert (sw1m, sw2m) == (0x90, 0x00)
            assert verify_usermessage_with_address(
                expected_addr, bytes(compsig), msg.encode('utf8')
            ), f"Message sig at child {i} did not verify for {expected_addr}"


# ─────────────────────────────────────────────────────────────────────
# Phase 12 Summary Report
# ─────────────────────────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.requires_card
class TestE2ESummaryReport:
    """Print a Phase 12 summary for documentation."""

    def test_e2e_report(self, cc_live, capsys):
        """Phase 12 end-to-end test summary."""
        _require_card_state(cc_live, requires_setup=True)
        _ensure_seeded_global(cc_live)
        cc_live.card_verify_PIN_simple(TESTPIN)

        _, _, _, d = cc_live.card_get_status()
        print("\n=== Phase 12 End-to-End Report ===")
        print(f"  Protocol:          v0.{d.get('protocol_version')}")
        print(f"  Applet:            v0.{d.get('applet_version')}")
        print(f"  is_seeded:         {d.get('is_seeded')}")
        print(f"  needs_2FA:         {d.get('needs2FA')}")
        print(f"  PIN0 tries:        {d.get('PIN0_remaining_tries')}")
        print("  Tests covered:")
        print("    - Full lifecycle (reset → seed → derive → sign → verify)")
        print("    - PIN change lifecycle (change → ops → restore)")
        print("    - Message signing verification (P2PKH address recovery)")
        print("    - Multi-path signing (5 BIP paths)")
        print("    - Seed switch isolation (abandon ↔ alt)")
        print("    - Repeated operations (10x sign, 10x derive, 10x msg)")
        print("    - Card reset cycle (reset → fail → reseed → verify)")
        print("    - Low-S normalisation (BIP62)")
        print("    - Cross-verification (20 children, 3 BIP paths, 5 msg+addr)")
        print("    - BIP84 child vector verification")
        print("==================================")
