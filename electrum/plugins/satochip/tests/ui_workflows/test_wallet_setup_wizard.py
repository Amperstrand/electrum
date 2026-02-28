"""
test_wallet_setup_wizard.py — UI workflow test for the Satochip wallet setup wizard.

Drives the Satochip hardware wallet setup flow through the real wizard logic layer
(KeystoreWizard / NewWalletWizard), injecting MockCardConnector at the pysatochip
boundary. The real QENewWalletWizard class is also instantiated and optionally shown.

Architecture
------------
This test uses a *hybrid* approach:

  Layer 1 – Logic layer (KeystoreWizard subclass)
    Drives wizard_data dicts through resolve_next() — the same code path used
    by both the Qt wizard and the cmdline wizard. This is fast, headless, and
    deterministic.

  Layer 2 – Qt class instantiation (QENewWalletWizard)
    The real QENewWalletWizard is constructed and registered with qtbot.
    When SATOCHIP_OBSERVE_GUI=1, show() IS called so the wizard is visible.

  Layer 3 – Observer window (SATOCHIP_OBSERVE_GUI=1)
    A separate status window shows each wizard step as it executes, using the
    same create_gui_observer() / set_status() pattern as the user story tests.
    A 2-second pause at the end lets you read the final state before teardown.

Why not drive full Qt navigation?
  The Qt wizard's WCWalletName page calls self.wizard._daemon.get_wallet(path)
  and expects interactive user input (text in a QLineEdit). Automating all
  pages via qtbot.mouseClick requires a running event loop that processes every
  signal, which reliably times out in headless CI. The logic-layer approach is
  the pattern Electrum itself uses in tests/test_wizard.py.

Run headless (CI):
    python3.11 -m pytest -v electrum/plugins/satochip/tests/ui_workflows/ \\
        --run-ui-workflows -s

Run with GUI observer (shows windows on screen):
    SATOCHIP_OBSERVE_GUI=1 python3.11 -m pytest -v \\
        electrum/plugins/satochip/tests/ui_workflows/ --run-ui-workflows -s
"""

import json
import os
import time
from pathlib import Path
from typing import Optional
from unittest.mock import patch, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Guard: skip entire module at import time if PyQt6 is missing
# ---------------------------------------------------------------------------
try:
    from PyQt6.QtWidgets import QApplication
    _QT_AVAILABLE = True
except ImportError:
    _QT_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _QT_AVAILABLE,
    reason="PyQt6 not available — skip UI workflow tests"
)

# ---------------------------------------------------------------------------
# Electrum imports
# ---------------------------------------------------------------------------
from electrum.simple_config import SimpleConfig
from electrum.plugin import Plugins, Device, DeviceInfo
from electrum.wizard import KeystoreWizard, WizardViewState
from electrum.keystore import bip44_derivation

from electrum.plugins.satochip.tests.story_helpers import (
    TESTPIN,
    HUNGRY_MNEMONIC,
    create_gui_observer,
    set_status,
)
from electrum.plugins.satochip.tests.ui_workflows.mock_card import (
    MockCardConnector,
    MockCardConnectorFactory,
)

# ---------------------------------------------------------------------------
# Whether to show windows on screen
# ---------------------------------------------------------------------------
_OBSERVE_GUI = os.environ.get("SATOCHIP_OBSERVE_GUI", "0") == "1"

# How long (seconds) to keep windows open at the end in observe mode
_OBSERVE_LINGER_SECS = float(os.environ.get("SATOCHIP_OBSERVE_LINGER", "3"))


# ---------------------------------------------------------------------------
# _DaemonMock — minimal Daemon substitute
# ---------------------------------------------------------------------------

class _DaemonMock:
    """Minimal Daemon substitute for wizard construction."""
    def __init__(self, config: SimpleConfig):
        self.config = config
        self.network = None

    def get_wallet(self, path: str):
        """Called by QENewWalletWizard WCWalletName page."""
        return None


# ---------------------------------------------------------------------------
# _TKeystoreWizard — concrete KeystoreWizard for testing
# ---------------------------------------------------------------------------

class _TKeystoreWizard(KeystoreWizard):
    """Minimal concrete KeystoreWizard (mirrors test_wizard.py pattern)."""
    def is_single_password(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _record_event(log_path: Path, event_type: str, **kwargs) -> None:
    """Append a JSONL event to the log file."""
    entry = {"event": event_type, "ts": time.time(), **kwargs}
    with open(log_path, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _make_fake_device_and_info(initialized: bool = True):
    """Return (fake_device, fake_info) for a mock Satochip."""
    fake_device = Device(
        path="/satochip",
        interface_number=-1,
        id_="/satochip",
        product_key=(0, 0),
        usage_page=0,
        transport_ui_string="mock",
    )
    fake_info = DeviceInfo(
        device=fake_device,
        label="Mock Satochip",
        initialized=initialized,
        exception=None,
        plugin_name="satochip",
        soft_device_id="MOCK001",
        model_name="Satochip",
    )
    return fake_device, fake_info


def _mock_verify_pin(self, pin=None):
    """
    Replacement for SatochipClient.verify_PIN.
    Supplies TESTPIN directly so no PIN dialog appears.
    """
    self.cc.card_verify_PIN_simple(TESTPIN)
    return True


# ---------------------------------------------------------------------------
# Main test class
# ---------------------------------------------------------------------------

@pytest.mark.ui_workflow
class TestWalletSetupWizardWorkflow:
    """
    End-to-end UI workflow test: drive the Satochip wallet setup wizard
    using MockCardConnector — no physical card required.

    With SATOCHIP_OBSERVE_GUI=1 both the real QENewWalletWizard AND a step
    observer window are shown on screen so you can watch the flow.
    """

    @pytest.fixture(autouse=True)
    def setup_plugins(self, wallet_tmp_path):
        """Create Plugins with satochip loaded; tear down after test."""
        config = SimpleConfig({"electrum_path": str(wallet_tmp_path)})
        plugins = Plugins(config, gui_name="qt")
        plugins.load_plugin_by_name("satochip")

        # Extend the KeystoreWizard used in this test so the 'satochip_start'
        # and 'satochip_xpub' views are registered in its navmap.
        plugin = plugins.get_plugin("satochip")
        self._config = config
        self._plugins = plugins
        self._plugin = plugin
        yield
        plugins.stop()
        plugins.stopped_event.wait(timeout=10)

    def test_new_satochip_wallet_wizard(
        self,
        qtbot,
        wallet_tmp_path: Path,
        ui_artifact_root: Path,
        use_real_card: bool,
        real_card_connector,
    ):
        """
        Drive the Satochip wallet setup wizard from keystore_type through
        satochip_xpub using MockCardConnector.

        Flow:
            keystore_type (hardware)
            → choose_hardware_device  (inject fake DeviceInfo)
            → satochip_start          (select script type + derivation)
            → satochip_xpub           (call get_xpub on mock client)
            → done (result = Hardware_KeyStore with correct xpub)

        With SATOCHIP_OBSERVE_GUI=1:
            - QENewWalletWizard is shown on screen (initial page visible)
            - A step observer window displays each step as it executes
            - Windows stay open for SATOCHIP_OBSERVE_LINGER seconds (default 3)
        """
        log_path = ui_artifact_root / "wizard_events.jsonl"
        PREFIX = "ui-wizard"

        # --- Observer window setup -------------------------------------------
        # create_gui_observer checks SATOCHIP_OBSERVE_GUI internally.
        # Returns (None, None, None, False) in headless mode — all set_status
        # calls below become no-ops.
        _app, _obs_widget, _obs_label, _observe = create_gui_observer(
            "Satochip Wallet Setup Wizard Test"
        )

        def _status(text: str, shot_name: str | None = None) -> None:
            """Print step + update observer window if visible."""
            set_status(
                text, shot_name, PREFIX,
                _obs_widget, _obs_label, _app,
                ui_artifact_root / "screenshots",
                _observe,
            )

        # --- Step 0: Record launch --------------------------------------------
        _status("Launching wizard test...", "00_launch")
        _record_event(log_path, "wizard_launch")

        # --- Step 0b: Instantiate real QENewWalletWizard ----------------------
        # In observe mode: show the wizard so it's visible on screen.
        # In headless mode: don't call show() — no blocking window.
        from electrum.gui.qt.wizard.wallet import QENewWalletWizard

        app = QApplication.instance()
        assert app is not None, "pytest-qt should have created a QApplication"

        daemon = _DaemonMock(self._config)
        wallet_path = str(wallet_tmp_path / "test_satochip.wallet")

        qt_wizard = QENewWalletWizard(
            self._config,
            app,
            self._plugins,
            daemon,
            wallet_path,
        )
        qtbot.addWidget(qt_wizard)  # ensures Qt cleanup even if test fails

        if _observe:
            _status("QENewWalletWizard constructed — showing on screen", "00b_wizard_open")
            qt_wizard.show()
            app.processEvents()

        # --- Step 1: Set up wizard (logic layer) ------------------------------
        _status("Step 1: Setting up logic-layer wizard...", "01_setup")
        w = _TKeystoreWizard(self._plugins)

        # extend_wizard registers satochip_start / satochip_xpub in navmap
        self._plugin.extend_wizard(w)

        start_vs = WizardViewState("keystore_type", {"wallet_type": "standard"}, {})
        v = w.start(start_viewstate=start_vs)
        assert v.view == "keystore_type"

        d = v.wizard_data

        # --- Step 2: keystore_type → choose_hardware_device ------------------
        _status("Step 2: Selecting hardware wallet type...", "02_hw_type")
        d["keystore_type"] = "hardware"
        v = w.resolve_next(v.view, d)
        assert v.view == "choose_hardware_device", f"Expected choose_hardware_device, got {v.view}"
        _record_event(log_path, "hw_wallet_selected")
        if _observe:
            app.processEvents()

        # --- Step 3: choose_hardware_device → satochip_start -----------------
        if use_real_card:
            _status("Step 3: Selecting REAL Satochip device...", "03_device_select")
            if real_card_connector is None:
                pytest.skip("Real Satochip not available (check pcscd tunnel + card)")
            # Query real card status
            _, _, _, status = real_card_connector.card_get_status()
            if not status.get('is_seeded', False):
                pytest.skip("Real Satochip card is not seeded — cannot derive xpub")
            # Create DeviceInfo from real card
            real_device = Device(
                path="/satochip", interface_number=-1, id_="/satochip",
                product_key=(0, 0), usage_page=0, transport_ui_string="ccid",
            )
            real_info = DeviceInfo(
                device=real_device,
                label="Real Satochip",
                initialized=status.get('setup_done', True),
                exception=None,
                plugin_name="satochip",
                soft_device_id=None,
                model_name="Satochip",
            )
            d["hardware_device"] = ("satochip", real_info)
            _record_event(log_path, "device_selected", device="Real Satochip")
        else:
            _status("Step 3: Selecting Mock Satochip device...", "03_device_select")
            _, fake_info = _make_fake_device_and_info(initialized=True)
            d["hardware_device"] = ("satochip", fake_info)
            _record_event(log_path, "device_selected", device="Mock Satochip")
        v = w.resolve_next(v.view, d)
        assert v.view == "satochip_start", f"Expected satochip_start, got {v.view}"
        if _observe:
            app.processEvents()

        # --- Step 4: satochip_start → satochip_xpub --------------------------
        _status("Step 4: Setting script type p2wpkh (BIP84)...", "04_script_type")
        d["script_type"] = "p2wpkh"
        d["derivation_path"] = bip44_derivation(0, bip43_purpose=84)
        v = w.resolve_next(v.view, d)
        assert v.view == "satochip_xpub", f"Expected satochip_xpub, got {v.view}"
        if _observe:
            app.processEvents()

        # --- Step 5: derive xpub from client --------------------------------
        if use_real_card:
            _status("Step 5: Deriving xpub from Real Satochip...", "05_xpub_derive")
            from electrum.plugins.satochip.satochip import SatochipClient

            def _real_cc_factory(client=None, loglevel=0):
                return real_card_connector

            with patch(
                "electrum.plugins.satochip.satochip.CardConnector",
                side_effect=_real_cc_factory,
            ), patch(
                "electrum.plugins.satochip.satochip.SatochipClient._ensure_card_connection",
                return_value=True,
            ), patch(
                "electrum.plugins.satochip.satochip.SatochipClient.verify_PIN",
                _mock_verify_pin,
            ), patch(
                "electrum.hw_wallet.plugin.assert_runs_in_hwd_thread",
                return_value=None,
            ):
                real_client = SatochipClient(self._plugin, handler=None)

                # get_xpub is decorated with @runs_in_hwd_thread — call the
                # underlying function directly to avoid threading in tests.
                xpub = SatochipClient.get_xpub.__wrapped__(
                    real_client,
                    d["derivation_path"],
                    d["script_type"],
                )
        else:
            _status("Step 5: Deriving xpub from MockCardConnector...", "05_xpub_derive")
            from electrum.plugins.satochip.satochip import SatochipClient

            def _mock_cc_factory(client=None, loglevel=0):
                return MockCardConnectorFactory.create("SEEDED")

            with patch(
                "electrum.plugins.satochip.satochip.CardConnector",
                side_effect=_mock_cc_factory,
            ), patch(
                "electrum.plugins.satochip.satochip.SatochipClient._ensure_card_connection",
                return_value=True,
            ), patch(
                "electrum.plugins.satochip.satochip.SatochipClient.verify_PIN",
                _mock_verify_pin,
            ), patch(
                "electrum.hw_wallet.plugin.assert_runs_in_hwd_thread",
                return_value=None,
            ):
                mock_client = SatochipClient(self._plugin, handler=None)

                # get_xpub is decorated with @runs_in_hwd_thread — call the
                # underlying function directly to avoid threading in tests.
                xpub = SatochipClient.get_xpub.__wrapped__(
                    mock_client,
                    d["derivation_path"],
                    d["script_type"],
                )

        assert xpub is not None and xpub.startswith("z"), (
            f"Expected a zpub xpub (p2wpkh), got: {xpub!r}"
        )
        _record_event(log_path, "pin_entered")
        _record_event(log_path, "xpub_derived", xpub=xpub[:20] + "...")
        _status(f"xpub derived: {xpub[:24]}...", "05b_xpub_ok")
        if _observe:
            app.processEvents()

        # --- Step 6: inject xpub into wizard data, finalize ------------------
        _status("Step 6: Finalising keystore...", "06_finalize")
        if use_real_card:
            d.update({
                "hw_type": "satochip",
                "master_key": xpub,
                "root_fingerprint": "00000000",
                "label": "Real Satochip",
                "soft_device_id": None,
            })
        else:
            d.update({
                "hw_type": "satochip",
                "master_key": xpub,
                "root_fingerprint": "00000000",
                "label": "Mock Satochip",
                "soft_device_id": "MOCK001",
            })

        # The satochip_xpub 'accept' handler calls wizard.maybe_master_pubkey(d)
        # which calls update_keystore(d) → sets w._result.
        # is_last_view should return True for a single-password standard wallet.
        assert w.is_last_view(v.view, d), (
            "Expected satochip_xpub to be the last view for a standard single-sig wallet"
        )
        w.resolve_next(v.view, d)

        # --- Step 7: verify result --------------------------------------------
        assert w._result is not None, "Wizard did not produce a keystore result"
        ks, is_hww = w._result
        assert is_hww, "Expected is_hww=True for a hardware wallet keystore"
        assert ks is not None, "Keystore is None"
        # The keystore should reference the xpub we derived
        assert ks.get_master_public_key() == xpub, (
            f"Keystore xpub mismatch: {ks.get_master_public_key()!r} != {xpub!r}"
        )

        _record_event(log_path, "wizard_complete", xpub=xpub[:20] + "...")
        _status(
            f"DONE — keystore created successfully!\nxpub: {xpub[:32]}...",
            "07_complete",
        )
        if _observe:
            app.processEvents()

        # --- Step 8: verify JSONL log has all required events -----------------
        _verify_log_events(log_path)

        # --- Linger so you can see the windows --------------------------------
        if _observe and _OBSERVE_LINGER_SECS > 0:
            _status(
                f"Test PASSED ✓ — closing in {_OBSERVE_LINGER_SECS:.0f}s...",
                "08_linger",
            )
            deadline = time.time() + _OBSERVE_LINGER_SECS
            while time.time() < deadline:
                app.processEvents()
                time.sleep(0.05)


# ---------------------------------------------------------------------------
# Helper: verify JSONL log contains expected events
# ---------------------------------------------------------------------------

def _verify_log_events(log_path: Path) -> None:
    """Assert that the JSONL log contains the minimum required events."""
    if not log_path.exists():
        pytest.fail(f"JSONL log not found at {log_path}")

    found_events = set()
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                found_events.add(json.loads(line)["event"])

    required = {
        "wizard_launch",
        "hw_wallet_selected",
        "device_selected",
        "pin_entered",
        "xpub_derived",
        "wizard_complete",
    }
    missing = required - found_events
    assert not missing, (
        f"JSONL log missing required events: {missing}\n"
        f"Found events: {sorted(found_events)}"
    )
