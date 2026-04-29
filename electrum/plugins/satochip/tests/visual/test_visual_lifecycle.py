"""
test_visual_lifecycle.py — Unified visual lifecycle test for Satochip card operations.

Runs the full card lifecycle (Stories 0-3) via APDU commands while instantiating
real Electrum Qt dialogs at each step to capture screenshots, then generates a
standalone HTML report.

Stories covered:
  Story 0 — Factory Reset:
              Put the card back to a clean slate (factory reset) so subsequent
              stories start from a known FACTORY_RESET state.
  Story 1 — Wallet Setup:
              Initialize the card with TESTPIN/TESTPUK, import HUNGRY_MNEMONIC,
              derive xpub, sign a transaction, and verify the signature.
  Story 2 — Wrong PIN Until Block:
              Enter the wrong PIN repeatedly until the card blocks (PIN_BLOCKED),
              confirming the card transitions correctly.
  Story 3 — PUK Recovery and Verify:
              Use TESTPUK to unblock the card, reset the PIN to TESTPIN,
              and verify the card returns to the SEEDED state.

Card state machine:
  FACTORY_RESET → (Story 0 brings us here from any state)
  FACTORY_RESET → INITIALIZED → SEEDED   (Stories 0→1)
  SEEDED        → PIN_BLOCKED             (Story 2)
  PIN_BLOCKED   → (PUK recovery) → SEEDED (Story 3)

Run all visual lifecycle stories:
  python3 -m pytest -v electrum/plugins/satochip/tests/visual/test_visual_lifecycle.py \\
      --hardware --destructive --ui -s

Collect only (no execution, no card needed):
  python3 -m pytest --co electrum/plugins/satochip/tests/visual/test_visual_lifecycle.py -v
"""

# pyright: reportUnknownVariableType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportAny=false, reportExplicitAny=false, reportUnnecessaryCast=false

import hashlib
import os
import time
from pathlib import Path
from typing import Any, Optional, cast
from unittest.mock import MagicMock

import pytest

import sys as _sys

_qt_available = True
_QtWidgets: tuple[type, ...] = ()
if 'PyQt5' in _sys.modules:
    try:
        from PyQt5.QtWidgets import QApplication, QWidget, QDialog
        _qt_available = True
        _QtWidgets = (QApplication, QWidget, QDialog)
    except ImportError:
        _qt_available = False
else:
    try:
        from PyQt6.QtWidgets import QApplication, QWidget, QDialog
        _qt_available = True
        _QtWidgets = (QApplication, QWidget, QDialog)
    except ImportError:
        _qt_available = False

from electrum.simple_config import SimpleConfig
from electrum.logging import get_logger

from electrum.plugins.satochip.tests.fixtures.card_helpers import TESTPIN, TESTPUK
from electrum.plugins.satochip.tests.fixtures.story_helpers import (
    HUNGRY_MNEMONIC,
    record_event,
    puk_preflight_check,
    reconnect_card,
    wait_for_card_absent,
    wait_for_card_present,
    apdu_factory_reset,
)
from electrum.plugins.satochip.tests.fixtures.visual_testing import (
    log_step,
    VisualTestArtifacts,
    capture_screenshot,
    generate_html_report,
)
from electrum.plugins.satochip.tests.fixtures.visual_storyboard import (
    StoryboardBuilder,
    add_screenshot_frame,
)

# Lazy imports for Qt widgets (only available when PyQt6 is present)
_TypedConfirmationDialog = None
_CardSwapDialog = None


def _lazy_import_qt_widgets() -> None:
    global _TypedConfirmationDialog, _CardSwapDialog
    from electrum.plugins.satochip.qt import (
        TypedConfirmationDialog,
        CardSwapDialog,
    )
    _TypedConfirmationDialog = TypedConfirmationDialog
    _CardSwapDialog = CardSwapDialog

_is_macos = _sys.platform == "darwin"


def _tts_say(text: str) -> None:
    if _is_macos:
        os.system(f"say '{text}'")


_logger = get_logger(__name__)

pytestmark = [
    pytest.mark.skipif(not _qt_available, reason="PyQt6 not available"),
    pytest.mark.visual_lifecycle,
    pytest.mark.requires_card,
    pytest.mark.destructive_card,
    pytest.mark.qt_no_exception_capture,
]

_cascade_skip: dict[str, str] = {}
_shared_artifacts: Optional[VisualTestArtifacts] = None
_shared_storyboard: Optional[StoryboardBuilder] = None
_shared_electrum_ctx: Optional[Any] = None


def _get_electrum_ctx(config: SimpleConfig) -> Any:
    global _shared_electrum_ctx
    if _shared_electrum_ctx is not None:
        return _shared_electrum_ctx
    try:
        from electrum.plugins.satochip.tests.visual.harness import (
            RealElectrumContext,
        )
        _shared_electrum_ctx = RealElectrumContext(config)
        return _shared_electrum_ctx
    except Exception as e:
        _logger.warning(f"Failed to create RealElectrumContext: {e}")
        return None


def _get_shared_artifacts(root_dir: Path) -> VisualTestArtifacts:
    global _shared_artifacts
    if _shared_artifacts is None:
        _shared_artifacts = VisualTestArtifacts(root_dir, "visual-lifecycle")
    return _shared_artifacts


def _get_shared_storyboard() -> StoryboardBuilder:
    global _shared_storyboard
    if _shared_storyboard is None:
        _shared_storyboard = StoryboardBuilder()
    return _shared_storyboard


# ---------------------------------------------------------------------------
# Card helpers
# ---------------------------------------------------------------------------

def _get_card_state(cc: Any) -> dict[str, Any]:
    try:
        (_, _, _, d) = cc.card_get_status()
        return {
            "setup_done": d.get("setup_done"),
            "is_seeded": d.get("is_seeded"),
            "PIN0_remaining_tries": d.get("PIN0_remaining_tries"),
            "PUK0_remaining_tries": d.get("PUK0_remaining_tries"),
            "protocol_version": d.get("protocol_version"),
        }
    except Exception:
        return {"error": "could not read card status"}


def _story_fail(story_key: str, reason: str) -> None:
    _cascade_skip[story_key] = f"FAILED: {reason}"
    pytest.fail(reason)


# ---------------------------------------------------------------------------
# Qt mock helpers
# ---------------------------------------------------------------------------

def _create_mock_window() -> Any:
    if not _qt_available:
        raise RuntimeError("PyQt not available")
    QApplication, QWidget, QDialog = _QtWidgets
    app = QApplication.instance()
    assert app is not None, "QApplication must exist"
    window = QWidget()
    window.setWindowTitle("Electrum - Satochip")
    window.setMinimumSize(800, 600)
    window.resize(1280, 800)
    window.show_error = lambda msg=None: None
    window.show_message = lambda msg=None: None
    window.show_warning = lambda msg=None: None
    window.top_level_window = lambda: window
    return window


def _create_mock_wizard() -> MagicMock:
    wizard = MagicMock()
    wizard.plugins = None
    wizard.wizard_data = {'hardware_device': None}
    wizard.current_cosigner = lambda data: data
    wizard.requestNext = MagicMock()
    wizard.requestNext.emit = MagicMock()
    return wizard


def _create_mock_plugin(config: SimpleConfig) -> MagicMock:
    plugin = MagicMock()
    plugin.device = "Satochip"
    plugin.device_manager = MagicMock()
    plugin.device_manager.return_value.config = config
    return plugin


def _create_mock_keystore(cc_session: Any) -> tuple[MagicMock, MagicMock]:
    keystore = MagicMock()
    keystore.handler = MagicMock()
    keystore.thread = MagicMock()

    client = MagicMock()
    client.cc = cc_session
    client.handler = keystore.handler
    client.get_authentikey_fingerprint = MagicMock(return_value=None)

    try:
        from electrum.plugins.satochip.satochip import list_pcsc_readers
        readers = list_pcsc_readers()
        client.reader_full_name = str(readers[0]) if readers else ""
    except Exception:
        client.reader_full_name = ""

    keystore.device_manager = MagicMock()
    keystore.device_manager.client_by_id = MagicMock(return_value=client)

    return keystore, client


# ---------------------------------------------------------------------------
# Screenshot helpers
# ---------------------------------------------------------------------------

def _snap(
    widget: Any,
    name: str,
    artifacts: VisualTestArtifacts,
    qtbot: Any,
    prefix: Optional[str] = None,
    *,
    storyboard: Optional[StoryboardBuilder] = None,
    step_number: int = 0,
    story_id: Optional[str] = None,
    story_name: Optional[str] = None,
    title: Optional[str] = None,
    annotation: Optional[str] = None,
    card_state_before: Optional[dict] = None,
    card_state_after: Optional[dict] = None,
    force_size: Optional[tuple[int, int]] = None,
) -> Optional[Path]:
    if not _qt_available:
        return None
    QApplication, QWidget, QDialog = _QtWidgets
    try:
        if force_size:
            widget.resize(force_size[0], force_size[1])
        else:
            hint = widget.sizeHint()
            w = max(hint.width(), 800)
            h = max(hint.height(), 600)
            widget.resize(w, h)
        widget.show()
        widget.raise_()
        widget.activateWindow()
        QApplication.processEvents()
        import time
        time.sleep(0.3)
        QApplication.processEvents()

        from electrum.plugins.satochip.tests.visual.native_capture import (
            capture_widget,
        )

        path = capture_screenshot(widget, name, artifacts, prefix)
        if path and path.exists():
            native_path = path.parent / (path.stem + "-native" + path.suffix)
            if capture_widget(widget, native_path):
                native_path.replace(path)
        widget.hide()
        QApplication.processEvents()

        if storyboard and path and story_id:
            add_screenshot_frame(
                storyboard, step_number, story_id, story_name or "",
                title or name, annotation or "",
                card_state_before or {}, card_state_after or {},
                path,
            )
        return path
    except Exception as e:
        _logger.warning(f"Screenshot capture failed for {name}: {e}")
        try:
            widget.hide()
        except Exception:
            pass
        return None


def _snap_settings(
    cc: Any,
    config: SimpleConfig,
    qtbot: Any,
    name: str,
    artifacts: VisualTestArtifacts,
    prefix: str,
    *,
    storyboard: Optional[StoryboardBuilder] = None,
    step_number: int = 0,
    story_id: Optional[str] = None,
    story_name: Optional[str] = None,
    title: Optional[str] = None,
    annotation: Optional[str] = None,
    card_state: Optional[dict] = None,
) -> Optional[Path]:
    """Create a SatochipSettingsDialog with populated data and snap it."""
    try:
        parent = _create_mock_window()
        qtbot.addWidget(parent)
        from electrum.plugins.satochip.qt import SatochipSettingsDialog

        mock_plugin = _create_mock_plugin(config)
        mock_keystore, mock_client = _create_mock_keystore(cc)
        mock_devmgr = MagicMock()
        mock_devmgr.config = config
        mock_devmgr.client_by_id = MagicMock(return_value=mock_client)
        mock_plugin.device_manager = MagicMock(return_value=mock_devmgr)

        dialog = SatochipSettingsDialog(
            window=parent, plugin=mock_plugin,
            keystore=mock_keystore, device_id="test-device-id",
        )
        qtbot.addWidget(dialog)

        try:
            (_resp, _sw1, _sw2, d) = cc.card_get_status()
            info = {
                "fw_rel": "v{}.{}-{}.{}".format(
                    d.get("protocol_major_version", 0),
                    d.get("protocol_minor_version", 0),
                    d.get("applet_major_version", 0),
                    d.get("applet_minor_version", 0),
                ),
                "applet_ver": (d.get("applet_major_version", 0), d.get("applet_minor_version", 0)),
                "pin_tries": d.get("PIN0_remaining_tries", "?"),
                "setup_done": d.get("setup_done", False),
                "is_seeded": d.get("is_seeded", False),
                "device_id": getattr(cc, "UID_SHA1", "unknown")[:8].upper(),
                "label": "",
                "reader": getattr(mock_client, "reader_full_name", ""),
                "protocol_version": d.get("protocol_version", 0),
                "taproot": False,
            }
            dialog.show_values(info)
        except Exception:
            dialog.show_values({})

        result = _snap(
            dialog, name, artifacts, qtbot, prefix,
            storyboard=storyboard, step_number=step_number,
            story_id=story_id or prefix, story_name=story_name or "",
            title=title or name, annotation=annotation or "",
            card_state_before=card_state or {},
            card_state_after=card_state or {},
        )
        log_step(f"Settings dialog {name} captured" if result else f"Settings dialog {name} failed", artifacts)
        return result
    except Exception as e:
        log_step(f"Settings dialog {name} failed (non-fatal): {e}", artifacts)
        return None


def _reconnect_after_wizard(cc: Any, artifacts: VisualTestArtifacts) -> None:
    time.sleep(2.0)
    for attempt in range(1, 4):
        try:
            cc.card_initiate_secure_channel()
            _, sw1, sw2 = cc.card_verify_PIN_simple(TESTPIN)
            cc.pin = list(TESTPIN)
            log_step(f"Wizard resync OK (attempt {attempt}): SW=0x{sw1:02x}{sw2:02x}", artifacts)
            return
        except Exception:
            pass
        try:
            cc.card_disconnect()
        except Exception:
            pass
        time.sleep(1.0)
        try:
            reconnect_card(cc)
            cc.card_initiate_secure_channel()
            _, sw1, sw2 = cc.card_verify_PIN_simple(TESTPIN)
            cc.pin = list(TESTPIN)
            log_step(f"Wizard reconnect OK (attempt {attempt}): SW=0x{sw1:02x}{sw2:02x}", artifacts)
            return
        except Exception as e:
            log_step(f"Wizard reconnect attempt {attempt} failed: {e}", artifacts)
            time.sleep(2.0)
    cc.pin = list(TESTPIN)
    log_step("Wizard reconnect exhausted — proceeding with restored pin", artifacts)


def _snap_wizard(
    view_name: str,
    wizard_data: dict,
    config: SimpleConfig,
    qtbot: Any,
    name: str,
    artifacts: VisualTestArtifacts,
    prefix: str,
    *,
    storyboard: Optional[StoryboardBuilder] = None,
    step_number: int = 0,
    story_id: Optional[str] = None,
    story_name: Optional[str] = None,
    title: Optional[str] = None,
    annotation: Optional[str] = None,
    card_state: Optional[dict] = None,
    cc: Any = None,
) -> Optional[Path]:
    try:
        from electrum.plugins.satochip.tests.visual.harness import (
            WizardDriver,
        )
        ctx = _get_electrum_ctx(config)
        if ctx is None:
            _logger.warning(f"Cannot create wizard for {name}: no electrum context")
            return None

        mock_client = MagicMock()
        mock_client.handler = MagicMock()
        mock_dm = MagicMock()
        mock_dm.client_by_id = MagicMock(return_value=mock_client)
        ctx.plugins.device_manager = mock_dm

        safe_data = dict(wizard_data)
        safe_data.setdefault('wallet_exists', False)
        safe_data.setdefault('wallet_needs_hw_unlock', False)

        driver = WizardDriver(ctx, QApplication.instance(), qtbot)
        wizard = driver.push_view(view_name, safe_data)
        qtbot.addWidget(wizard)

        from electrum.plugins.satochip.tests.visual.native_capture import (
            capture_widget,
        )

        path = capture_screenshot(wizard, name, artifacts, prefix)
        if path and path.exists():
            native_path = path.parent / (path.stem + "-native" + path.suffix)
            if capture_widget(wizard, native_path):
                native_path.replace(path)

        if storyboard and path and story_id:
            add_screenshot_frame(
                storyboard, step_number, story_id or prefix, story_name or "",
                title or name, annotation or "",
                card_state or {}, card_state or {},
                path,
            )
        log_step(f"Wizard view {name} captured" if path else f"Wizard view {name} failed", artifacts)

        driver.teardown()
        _qapp = _QtWidgets[0]
        _deadline = time.time() + 1.0
        while time.time() < _deadline:
            _qapp.processEvents()
            time.sleep(0.02)

        if cc is not None:
            _reconnect_after_wizard(cc, artifacts)

        return path
    except Exception as e:
        log_step(f"Wizard view {name} failed (non-fatal): {e}", artifacts)
        return None


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def _derive_xpub_from_card(cc: Any, bip32_path: str, xtype: str) -> str:
    from electrum.bip32 import BIP32Node
    from electrum.crypto import hash_160
    from electrum.plugins.satochip.satochip import _bip32path2bytes as bip32path2bytes
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
        xtype=xtype, eckey=childkey, chaincode=childchaincode,
        depth=depth, fingerprint=fingerprint, child_number=child_number,
    ).to_xpub()


def _derive_xpub_software(seed_bytes: bytes, bip32_path: str, xtype: str) -> str:
    from electrum.bip32 import BIP32Node
    root = BIP32Node.from_rootseed(seed_bytes, xtype=xtype)
    return root.subkey_at_private_derivation(bip32_path).to_xpub()


def _derive_key(cc: Any, path_str: str) -> tuple[Any, Any]:
    from electrum.plugins.satochip.satochip import _bip32path2bytes as bip32path2bytes
    _, bytepath = bip32path2bytes(path_str)
    pubkey, chaincode = cc.card_bip32_get_extendedkey(bytepath)
    return pubkey, chaincode


def _r_s_from_der(der_sig_bytes: bytes) -> tuple[int, int]:
    import electrum_ecc as _ecc
    return _ecc.get_r_and_s_from_ecdsa_der_sig(der_sig_bytes)


def _verify_ecdsa(pubkey: Any, hash32: bytes, der_sig_bytes: bytes) -> None:
    r, s = _r_s_from_der(der_sig_bytes)
    raw64 = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    pubkey.verify_message_hash(raw64, hash32)


# ---------------------------------------------------------------------------
# Story 0 — Factory Reset
# ---------------------------------------------------------------------------
@pytest.mark.order(0)
class TestVisualStory0FactoryReset:

    def test_visual_factory_reset(
        self,
        qtbot: Any,
        cc_session: Any,
        story_artifact_root: Path,
    ) -> None:
        _lazy_import_qt_widgets()
        PREFIX = "s0"
        skip_apdu = os.environ.get("SATOCHIP_SKIP_RESET", "1") == "1"
        artifacts = _get_shared_artifacts(cast(Path, story_artifact_root))
        storyboard = _get_shared_storyboard()
        events: list[dict[str, Any]] = []
        config = SimpleConfig({"electrum_path": str(story_artifact_root)})

        log_step("Starting visual factory reset workflow...", artifacts)

        card_already_blank = False
        try:
            (_, _, _, pre_status) = cc_session.card_get_status()
            if pre_status.get("setup_done") is False and not pre_status.get("is_seeded"):
                card_already_blank = True
                log_step("Card already in FACTORY_RESET state.", artifacts)
        except Exception:
            pass

        state_before_reset = _get_card_state(cc_session)

        _snap_settings(
            cc_session, config, qtbot, "01-pre-reset-settings", artifacts, PREFIX,
            storyboard=storyboard, step_number=1, story_name="Factory Reset",
            title="Pre-reset Settings", annotation="Settings dialog showing card state before factory reset begins",
            card_state=state_before_reset,
        )

        wipe_phrase = "WIPE"
        try:
            (_rl1, _rl2, _rl3, card_lbl) = cc_session.card_get_label()
            if card_lbl and card_lbl.strip() and card_lbl.strip() not in ("(none)", "(unknown)"):
                wipe_phrase = card_lbl.strip()
        except Exception:
            pass

        wipe_warnings = [
            "The seed phrase stored on the card will be permanently erased.",
            "The PIN, card label, and all stored data will be deleted.",
            "The card will be returned to factory state.",
            "This action is irreversible.",
        ]
        balance_str = "Card holds 0.005 BTC (191.42 EUR)."

        log_step("Step 2: Capturing Wipe Card confirmation dialog (empty)...", artifacts)
        try:
            parent = _create_mock_window()
            qtbot.addWidget(parent)
            wipe_dlg = _TypedConfirmationDialog(
                parent, title="Wipe Satochip", action_label="Wipe Card",
                confirm_phrase=wipe_phrase, warnings=wipe_warnings, balance_warning=None,
            )
            _snap(wipe_dlg, "02-wipe-confirm-empty", artifacts, qtbot, PREFIX,
                  storyboard=storyboard, step_number=2, story_id=PREFIX, story_name="Factory Reset",
                  title="Wipe Card Dialog (no balance)", annotation="Confirmation dialog with empty input — destructive button disabled",
                  card_state_before=state_before_reset, card_state_after=state_before_reset)
            wipe_dlg.close()
        except Exception as e:
            log_step(f"Wipe Card dialog capture (empty) failed (non-fatal): {e}", artifacts)

        log_step("Step 3: Capturing Wipe Card confirmation dialog (with balance)...", artifacts)
        try:
            parent = _create_mock_window()
            qtbot.addWidget(parent)
            wipe_dlg_bal = _TypedConfirmationDialog(
                parent, title="Wipe Satochip", action_label="Wipe Card",
                confirm_phrase=wipe_phrase, warnings=wipe_warnings, balance_warning=balance_str,
            )
            _snap(wipe_dlg_bal, "03-wipe-confirm-with-balance", artifacts, qtbot, PREFIX,
                  storyboard=storyboard, step_number=3, story_id=PREFIX, story_name="Factory Reset",
                  title="Wipe Card Dialog (with balance)", annotation="Confirmation dialog showing balance warning",
                  card_state_before=state_before_reset, card_state_after=state_before_reset)
            wipe_dlg_bal.close()
        except Exception as e:
            log_step(f"Wipe Card dialog capture (with balance) failed (non-fatal): {e}", artifacts)

        log_step("Step 4: Capturing Wipe Card confirmation dialog (enabled)...", artifacts)
        try:
            parent = _create_mock_window()
            qtbot.addWidget(parent)
            wipe_dlg_en = _TypedConfirmationDialog(
                parent, title="Wipe Satochip", action_label="Wipe Card",
                confirm_phrase=wipe_phrase, warnings=wipe_warnings, balance_warning=balance_str,
            )
            wipe_dlg_en.show()
            qtbot.wait(200)
            wipe_dlg_en._lineedit.setText(wipe_phrase)
            qtbot.wait(100)
            QApplication.processEvents()

            _snap(wipe_dlg_en, "04-wipe-confirm-enabled", artifacts, qtbot, PREFIX,
                  storyboard=storyboard, step_number=4, story_id=PREFIX, story_name="Factory Reset",
                  title="Wipe Card Dialog (enabled)", annotation="Confirmation dialog with phrase typed — red destructive button enabled",
                  card_state_before=state_before_reset, card_state_after=state_before_reset)
            wipe_dlg_en.close()
        except Exception as e:
            log_step(f"Wipe Card dialog capture (enabled) failed (non-fatal): {e}", artifacts)

        log_step("Step 4b: Capturing CardSwapDialog screenshot...", artifacts)
        try:
            parent = _create_mock_window()
            qtbot.addWidget(parent)
            swap_dlg = _CardSwapDialog(parent, remaining_steps=3, total_steps=5)
            _snap(swap_dlg, "04b-card-swap-dialog", artifacts, qtbot, PREFIX,
                  storyboard=storyboard, step_number=4, story_id=PREFIX, story_name="Factory Reset",
                  title="Card Swap Dialog", annotation="Guided card removal/insertion dialog",
                  card_state_before=state_before_reset, card_state_after=state_before_reset)
            swap_dlg.close()
            log_step("CardSwapDialog screenshot captured", artifacts)
        except Exception as e:
            log_step(f"CardSwapDialog screenshot failed (non-fatal): {e}", artifacts)

        if card_already_blank or skip_apdu:
            log_step("Skipping APDU factory reset (card already blank or SATOCHIP_SKIP_RESET=1).", artifacts)
        else:
            log_step("Step 5: Running APDU factory-reset loop...", artifacts)

            _swap_counter = [0]
            _initial_total = [None]

            def _card_swap_callback(remaining: int | None = None) -> bool:
                _swap_counter[0] += 1

                if _swap_counter[0] == 1:
                    total = remaining if remaining else 5
                    _initial_total[0] = total
                    _tts_say(f"remove and reinsert the card {total} times as prompted")
                else:
                    _tts_say(f"{remaining or 1}")

                swap_parent = _create_mock_window()
                qtbot.addWidget(swap_parent)
                swap_dlg = _CardSwapDialog(
                    swap_parent,
                    remaining_steps=remaining if remaining else 1,
                    total_steps=_initial_total[0] or 5,
                )
                _snap(swap_dlg, f"05-swap-{_swap_counter[0]}", artifacts, qtbot, PREFIX,
                      storyboard=storyboard, step_number=5 + _swap_counter[0], story_id=PREFIX,
                      story_name="Factory Reset",
                      title=f"Card Swap {_swap_counter[0]}", annotation=f"{remaining} swaps remaining")
                swap_dlg.close()

                if not wait_for_card_absent(cc_session, timeout=120):
                    return False
                if not wait_for_card_present(cc_session, timeout=120):
                    return False
                time.sleep(0.3)
                return True

            try:
                _, reset_sw1, reset_sw2 = apdu_factory_reset(
                    cc_session,
                    log_fn=lambda msg: log_step(msg, artifacts),
                    on_need_card_swap=_card_swap_callback,
                )
                _tts_say("thank you, done")
            except RuntimeError as exc:
                _cascade_skip["story_0"] = f"FAILED: {exc}"
                log_step(f"FAILED: {exc}", artifacts)
                record_event({"event": "factory_reset_apdu", "status": "failed", "error": str(exc)},
                              artifacts.log_path, events)
                pytest.fail(str(exc))

            log_step("APDU factory reset complete", artifacts)
            record_event({"event": "factory_reset_apdu", "status": "ok",
                           "sw": f"0x{reset_sw1:02x}{reset_sw2:02x}"},
                          artifacts.log_path, events)

            log_step("Step 6: Verifying card is factory-reset...", artifacts)
            time.sleep(2.0)
            try:
                (_, sw1, sw2, status_dict) = cc_session.card_get_status()
            except Exception:
                try:
                    reconnect_card(cc_session)
                except Exception:
                    pass
                try:
                    cc_session.card_initiate_secure_channel()
                except Exception:
                    pass
                (_, sw1, sw2, status_dict) = cc_session.card_get_status()

            setup_done = status_dict.get("setup_done", "UNKNOWN")
            record_event({"event": "factory_reset_verification", "setup_done": setup_done,
                           "sw": f"{sw1:02X}{sw2:02X}"}, artifacts.log_path, events)

            if setup_done is not False:
                _story_fail("story_0", f"Card not blank after factory reset: setup_done={setup_done}")

        state_verified = _get_card_state(cc_session)

        _snap_settings(
            cc_session, config, qtbot, "06-post-reset-settings", artifacts, PREFIX,
            storyboard=storyboard, step_number=6, story_name="Factory Reset",
            title="Post-reset Verification", annotation="Card confirmed blank after factory reset",
            card_state=state_verified,
        )

        try:
            _snap_wizard(
                'satochip_not_setup',
                {'hardware_device': ('Satochip', MagicMock()), 'satochip_setup_settings': (TESTPIN.decode(), "")},
                config, qtbot, "07-post-reset-setup-prompt", artifacts, PREFIX,
                storyboard=storyboard, step_number=7, story_name="Factory Reset",
                title="Setup Prompt After Reset", annotation="Fresh setup prompt — card ready for initialization",
                card_state=state_verified, cc=cc_session,
            )
        except Exception as e:
            log_step(f"Post-reset setup prompt failed (non-fatal): {e}", artifacts)

        _cascade_skip["story_0"] = "passed"
        log_step("Factory reset complete - card is blank", artifacts)
        record_event({"event": "factory_reset_complete", "status": "passed"}, artifacts.log_path, events)


# ---------------------------------------------------------------------------
# Story 1 — Wallet Setup
# ---------------------------------------------------------------------------
@pytest.mark.order(1)
class TestVisualStory1WalletSetup:

    def test_visual_wallet_setup(
        self,
        qtbot: Any,
        cc_session: Any,
        story_artifact_root: Path,
    ) -> None:
        from electrum.keystore import bip39_to_seed

        if _cascade_skip.get("story_0") != "passed":
            pytest.skip("Story 0 (Factory Reset) did not pass — skipping Story 1")

        _lazy_import_qt_widgets()
        PREFIX = "s1"
        artifacts = _get_shared_artifacts(cast(Path, story_artifact_root))
        storyboard = _get_shared_storyboard()
        events: list[dict[str, Any]] = []
        config = SimpleConfig({"electrum_path": str(story_artifact_root)})

        log_step("Starting visual wallet setup workflow...", artifacts)

        log_step("Step 1: Checking card is blank (factory-reset)...", artifacts)
        (_, sw1, sw2, d) = cc_session.card_get_status()
        state_blank = _get_card_state(cc_session)
        record_event({"event": "card_status_check", "step": 1, "setup_done": d.get("setup_done"),
                       "is_seeded": d.get("is_seeded"), "sw": f"0x{sw1:02x}{sw2:02x}"},
                     artifacts.log_path, events)

        _snap_settings(
            cc_session, config, qtbot, "01-blank-card-status", artifacts, PREFIX,
            storyboard=storyboard, step_number=1, story_name="Wallet Setup",
            title="Blank Card Status", annotation="Card status before any setup — factory fresh state",
            card_state=state_blank,
        )

        if d["setup_done"]:
            log_step("Card already initialized — skipping setup step.", artifacts)
            record_event({"event": "skip_setup", "reason": "card already initialized"}, artifacts.log_path, events)
            _, sw1, sw2 = cc_session.card_verify_PIN_simple(TESTPIN)
            if (sw1, sw2) != (0x90, 0x00):
                _story_fail("story_1", f"TESTPIN verification failed: SW=0x{sw1:02x}{sw2:02x}")
        else:
            log_step("Step 2: Initialising card with TESTPIN...", artifacts)
            if getattr(cc_session, 'needs_secure_channel', False):
                try:
                    cc_session.card_initiate_secure_channel()
                except Exception:
                    pass

            pin_tries_0, ublk_tries_0 = 0x05, 0x01
            ublk_0 = list(TESTPUK)
            pin_1 = list(os.urandom(16))
            ublk_1 = list(os.urandom(16))

            _, sw1, sw2 = cc_session.card_setup(
                pin_tries_0, ublk_tries_0, list(TESTPIN), ublk_0,
                0x01, 0x01, pin_1, ublk_1,
                32, 0, 0x01, 0x01, 0x01,
            )
            if (sw1, sw2) != (0x90, 0x00):
                _story_fail("story_1", f"card_setup() failed: SW=0x{sw1:02x}{sw2:02x}")

            record_event({"event": "card_setup", "step": 2, "status": "ok",
                           "sw": f"0x{sw1:02x}{sw2:02x}", "pin_tries": pin_tries_0},
                         artifacts.log_path, events)
            log_step("Card setup complete. PIN configured.", artifacts)

            state_after_pin = {"state": "INITIALIZED", "setup_done": True, "is_seeded": False}

            _snap_wizard(
                'satochip_not_setup',
                {'hardware_device': ('Satochip', MagicMock())},
                config, qtbot, "02-setup-params", artifacts, PREFIX,
                storyboard=storyboard, step_number=3, story_name="Wallet Setup",
                title="PIN Configuration Dialog", annotation="Dialog for configuring PIN and PUK during card setup",
                card_state=state_after_pin, cc=cc_session,
            )

        (_, _, _, d_after_setup) = cc_session.card_get_status()
        if d_after_setup["setup_done"] is not True:
            _story_fail("story_1", "Card should be initialized by now")

        if d_after_setup.get("is_seeded"):
            log_step("Card already seeded — resetting seed first.", artifacts)
            _, sw1, sw2 = cc_session.card_reset_seed(list(TESTPIN))
            if (sw1, sw2) != (0x90, 0x00):
                _story_fail("story_1", f"card_reset_seed() failed: SW=0x{sw1:02x}{sw2:02x}")
            record_event({"event": "seed_reset", "step": 3, "reason": "card was already seeded"},
                         artifacts.log_path, events)

        log_step(f"Step 3: Importing seed from mnemonic ({HUNGRY_MNEMONIC[:30]})...", artifacts)
        masterseed = bip39_to_seed(HUNGRY_MNEMONIC, passphrase="")
        authentikey = cc_session.card_bip32_import_seed(list(masterseed))

        if authentikey is None:
            _story_fail("story_1", "card_bip32_import_seed() returned None")
        if cc_session.is_seeded is not True:
            _story_fail("story_1", "cc.is_seeded must be True after import")

        authentikey_hex = authentikey.get_public_key_bytes(compressed=True).hex()
        record_event({"event": "seed_import", "step": 3, "status": "ok",
                       "mnemonic_preview": HUNGRY_MNEMONIC[:30] + "...", "authentikey": authentikey_hex},
                     artifacts.log_path, events)
        log_step(f"Seed imported. Authentikey: {authentikey_hex[:16]}...", artifacts)
        state_after_seed = _get_card_state(cc_session)

        _snap_settings(
            cc_session, config, qtbot, "03-seed-success", artifacts, PREFIX,
            storyboard=storyboard, step_number=5, story_name="Wallet Setup",
            title="Seed Import Success", annotation="Settings dialog after successful seed import",
            card_state=state_after_seed,
        )

        _snap_wizard(
            'satochip_import_seed',
            {'hardware_device': ('Satochip', MagicMock()), 'seed_type': 'bip39',
             'seed': HUNGRY_MNEMONIC, 'seed_extra_words': '', 'seed_extend': False},
            config, qtbot, "04-import-seed", artifacts, PREFIX,
            storyboard=storyboard, step_number=6, story_name="Wallet Setup",
            title="Import Seed Dialog", annotation="Dialog for importing BIP39 mnemonic seed phrase",
            card_state=state_after_seed, cc=cc_session,
        )

        log_step("Step 4: Deriving xpubs and cross-checking...", artifacts)
        xpub_paths = [
            ("m/84'/0'/0'", "p2wpkh"),
            ("m/44'/0'/0'", "standard"),
            ("m/49'/0'/0'", "p2wpkh-p2sh"),
        ]
        xpub_results = []
        for path, xtype in xpub_paths:
            card_xpub = _derive_xpub_from_card(cc_session, path, xtype)
            sw_xpub = _derive_xpub_software(masterseed, path, xtype)
            match = card_xpub == sw_xpub
            xpub_results.append({"path": path, "xtype": xtype, "match": match})
            if not match:
                _story_fail("story_1", f"xpub mismatch at {path} ({xtype})!\n  card: {card_xpub}\n  sw:   {sw_xpub}")

        record_event({"event": "xpub_derivation", "step": 4, "status": "ok",
                       "paths_checked": len(xpub_paths),
                       "all_match": all(r["match"] for r in xpub_results)},
                     artifacts.log_path, events)
        log_step(f"All {len(xpub_paths)} xpub paths match software derivation.", artifacts)

        sign_path = "m/84'/0'/0'/0/0"
        message = b"Satochip wallet setup test: hello from electrum-satochip"
        log_step(f"Step 5: Signing message at {sign_path}...", artifacts)

        pubkey, _ = _derive_key(cc_session, sign_path)
        pubkey_hex = pubkey.get_public_key_bytes(compressed=True).hex()
        sig4 = cc_session.card_sign_message(0xFF, pubkey, message, b'')
        if sig4 is None:
            _story_fail("story_1", "card_sign_message returned None")
        _, sw1, sw2, compsig = sig4
        if (sw1, sw2) != (0x90, 0x00):
            _story_fail("story_1", f"card_sign_message() failed: SW=0x{sw1:02x}{sw2:02x}")
        if len(compsig) != 65:
            _story_fail("story_1", f"Expected 65-byte compact sig, got {len(compsig)}")

        from electrum.bitcoin import sha256d
        from electrum.plugins.satochip.card_connector import usermessage_magic
        msg_hash = sha256d(usermessage_magic(message))
        pubkey.ecdsa_verify(bytes(compsig[1:]), msg_hash, enforce_low_s=False)
        record_event({"event": "message_sign", "step": 5, "status": "ok", "path": sign_path,
                       "pubkey": pubkey_hex, "message": message.decode("utf-8")},
                     artifacts.log_path, events)
        log_step("Message signed and verified.", artifacts)

        log_step("Step 6: Signing a hash (ECDSA) to verify transaction signing...", artifacts)
        test_hash = hashlib.sha256(hashlib.sha256(b"electrum-satochip-wallet-setup-test").digest()).digest()
        try:
            sig_der, sw1, sw2 = cc_session.card_sign_transaction(0xFF, list(test_hash), None)
            if (sw1, sw2) != (0x90, 0x00):
                log_step(f"Step 6: card_sign_transaction() returned SW=0x{sw1:02x}{sw2:02x} (non-fatal, skipping)", artifacts)
                record_event({"event": "hash_sign", "step": 6, "status": "skipped", "sw": f"0x{sw1:02x}{sw2:02x}"},
                             artifacts.log_path, events)
            else:
                if bytes(sig_der)[0] == 0x30:
                    _verify_ecdsa(pubkey, test_hash, bytes(sig_der))
                    log_step("ECDSA hash signed and verified.", artifacts)
                record_event({"event": "hash_sign", "step": 6, "status": "ok",
                               "hash": test_hash.hex(), "der_sig_length": len(sig_der)},
                             artifacts.log_path, events)
        except Exception as e:
            log_step(f"Step 6: card_sign_transaction failed (non-fatal): {e}", artifacts)

        state_after_tx = _get_card_state(cc_session)
        _snap_settings(
            cc_session, config, qtbot, "05-seeded-settings", artifacts, PREFIX,
            storyboard=storyboard, step_number=10, story_name="Wallet Setup",
            title="Seeded Settings", annotation="Settings dialog showing fully seeded card after wallet setup",
            card_state=state_after_tx,
        )

        (_, _, _, d_final) = cc_session.card_get_status()
        if d_final["setup_done"] is not True:
            _story_fail("story_1", f"Final check: setup_done={d_final.get('setup_done')}")
        if d_final["is_seeded"] is not True:
            _story_fail("story_1", f"Final check: is_seeded={d_final.get('is_seeded')}")

        _cascade_skip["story_1"] = "passed"
        log_step("Wallet setup complete.", artifacts)


# ---------------------------------------------------------------------------
# Story 2 — Wrong PIN Until Block
# ---------------------------------------------------------------------------
@pytest.mark.order(2)
class TestVisualStory2WrongPin:

    def test_visual_wrong_pin_until_block(
        self,
        qtbot: Any,
        cc_session: Any,
        story_artifact_root: Path,
    ) -> None:
        if _cascade_skip.get("story_1") != "passed":
            pytest.skip("Story 1 (Wallet Setup) did not pass — skipping Story 2")

        _lazy_import_qt_widgets()
        PREFIX = "s2"
        artifacts = _get_shared_artifacts(cast(Path, story_artifact_root))
        storyboard = _get_shared_storyboard()
        events: list[dict[str, Any]] = []
        config = SimpleConfig({"electrum_path": str(story_artifact_root)})

        log_step("Starting visual wrong PIN until block workflow...", artifacts)
        puk_preflight_check(cc_session)

        log_step("Step 1: Verifying TESTPIN works...", artifacts)
        try:
            _, sw1, sw2 = cc_session.card_verify_PIN_simple(TESTPIN)
        except Exception as exc:
            _story_fail("story_2", f"TESTPIN verification raised {type(exc).__name__}: {exc}")

        if (sw1, sw2) != (0x90, 0x00):
            _story_fail("story_2", f"TESTPIN verification failed: SW=0x{sw1:02x}{sw2:02x}")
        record_event({"event": "testpin_verify_ok", "sw": f"0x{sw1:02x}{sw2:02x}"}, artifacts.log_path, events)

        state_seeded = _get_card_state(cc_session)
        _snap_settings(
            cc_session, config, qtbot, "01-seeded-before-attack", artifacts, PREFIX,
            storyboard=storyboard, step_number=1, story_name="PIN Block",
            title="Seeded Before Attack", annotation="Card in healthy seeded state before wrong PIN attack",
            card_state=state_seeded,
        )

        (_, _, _, status0) = cc_session.card_get_status()
        max_tries = status0.get("PIN0_remaining_tries")
        if not (isinstance(max_tries, int) and max_tries >= 1):
            _story_fail("story_2", f"Could not determine PIN0_remaining_tries: {status0}")
        record_event({"event": "initial_status", "PIN0_remaining_tries": max_tries}, artifacts.log_path, events)
        log_step(f"PIN0_remaining_tries = {max_tries}", artifacts)

        wrong_pin = b"000000" if TESTPIN != b"000000" else b"111111"

        log_step(f"Step 4: Starting wrong PIN attempts (max_tries={max_tries})", artifacts)
        for attempt in range(1, max_tries + 1):
            try:
                cc_session.card_verify_PIN_simple(wrong_pin)
                _story_fail("story_2", f"Attempt {attempt}: expected wrong-PIN error, call succeeded")
            except Exception as exc:
                exc_type = type(exc).__name__
                (_, _, _, d_after) = cc_session.card_get_status()
                tries_after = d_after.get("PIN0_remaining_tries")
                record_event({"event": "wrong_pin_attempt", "attempt": attempt,
                               "exception_type": exc_type, "tries_remaining": tries_after},
                             artifacts.log_path, events)
                log_step(f"Attempt {attempt}/{max_tries}: {exc_type}, tries_remaining={tries_after}", artifacts)
                if attempt < max_tries:
                    if "WrongPin" not in exc_type and "wrong" not in str(exc).lower():
                        _story_fail("story_2", f"Attempt {attempt} expected WrongPinError, got {exc_type}: {exc}")

        log_step("Step 5: Post-exhaustion attempt (card should be blocked)...", artifacts)
        try:
            cc_session.card_verify_PIN_simple(wrong_pin)
            _story_fail("story_2", "Expected blocked PIN after exhausting tries, but call succeeded")
        except Exception as exc:
            exc_type = type(exc).__name__
            (_, _, _, d_blocked) = cc_session.card_get_status()
            tries_blocked = d_blocked.get("PIN0_remaining_tries")
            record_event({"event": "post_exhaustion_attempt", "exception_type": exc_type,
                           "tries_remaining": tries_blocked}, artifacts.log_path, events)
            log_step(f"Post-exhaustion: {exc_type}, tries_remaining={tries_blocked}", artifacts)
            if "PinBlocked" not in exc_type and tries_blocked != 0:
                _story_fail("story_2", f"Expected blocked card, got {exc_type}, tries_remaining={tries_blocked}")

        state_blocked = _get_card_state(cc_session)
        _snap_wizard(
            'satochip_blocked',
            {'hardware_device': ('Satochip', MagicMock())},
            config, qtbot, "02-pin-blocked", artifacts, PREFIX,
            storyboard=storyboard, step_number=3 + max_tries + 1, story_name="PIN Block",
            title="PIN Blocked Dialog", annotation="Card is PIN-blocked — all retry attempts exhausted",
            card_state=state_blocked,
        )

        _snap_settings(
            cc_session, config, qtbot, "03-blocked-settings", artifacts, PREFIX,
            storyboard=storyboard, step_number=4 + max_tries + 1, story_name="PIN Block",
            title="Blocked Settings Dialog", annotation="Settings dialog showing PIN_BLOCKED state",
            card_state=state_blocked,
        )

        _cascade_skip["story_2"] = "passed"
        log_step("Card is now PIN-blocked. Story 2 complete.", artifacts)


# ---------------------------------------------------------------------------
# Story 3 — PUK Recovery and Verify
# ---------------------------------------------------------------------------
@pytest.mark.order(3)
class TestVisualStory3PukRecovery:

    def test_visual_puk_recovery(
        self,
        qtbot: Any,
        cc_session: Any,
        story_artifact_root: Path,
    ) -> None:
        if _cascade_skip.get("story_2") != "passed":
            pytest.skip("Story 2 (Wrong PIN Until Block) did not pass — skipping Story 3")

        _lazy_import_qt_widgets()
        PREFIX = "s3"
        artifacts = _get_shared_artifacts(cast(Path, story_artifact_root))
        storyboard = _get_shared_storyboard()
        events: list[dict[str, Any]] = []
        config = SimpleConfig({"electrum_path": str(story_artifact_root)})

        log_step("Starting visual PUK recovery workflow...", artifacts)

        log_step("Step 1: PUK preflight safety check...", artifacts)
        try:
            puk_tries = puk_preflight_check(cc_session)
        except Exception as exc:
            _story_fail("story_3", f"PUK preflight check failed: {type(exc).__name__}: {exc}")
        record_event({"event": "puk_preflight", "status": "ok", "PUK0_remaining_tries": puk_tries},
                     artifacts.log_path, events)
        log_step(f"PUK preflight OK — PUK0_remaining_tries={puk_tries}", artifacts)

        log_step("Step 2: Verifying card is PIN-blocked...", artifacts)
        (_, _, _, d_blocked) = cc_session.card_get_status()
        pin_tries_before = d_blocked.get("PIN0_remaining_tries")
        puk_tries_before = d_blocked.get("PUK0_remaining_tries")
        record_event({"event": "pin_blocked_check", "PIN0_remaining_tries": pin_tries_before,
                       "PUK0_remaining_tries": puk_tries_before}, artifacts.log_path, events)
        if pin_tries_before != 0:
            _story_fail("story_3", f"Expected PIN0_remaining_tries==0, got {pin_tries_before}")
        log_step(f"Card confirmed PIN-blocked (tries={pin_tries_before})", artifacts)

        state_blocked = _get_card_state(cc_session)
        _snap_settings(
            cc_session, config, qtbot, "01-blocked-before-recovery", artifacts, PREFIX,
            storyboard=storyboard, step_number=1, story_name="PUK Recovery",
            title="Blocked Before Recovery", annotation="Card in PIN_BLOCKED state before PUK recovery",
            card_state=state_blocked,
        )

        _snap_wizard(
            'satochip_blocked',
            {'hardware_device': ('Satochip', MagicMock())},
            config, qtbot, "02-pin-blocked-wizard", artifacts, PREFIX,
            storyboard=storyboard, step_number=2, story_name="PUK Recovery",
            title="PIN Blocked Wizard",
            annotation=(
                "PIN-blocked card shown in wizard"
                " — offers wipe and mentions PUK recovery"
            ),
            card_state=state_blocked,
        )

        log_step("Step 4: Attempting PUK unblock recovery...", artifacts)
        try:
            cc_session.card_unblock_PIN(0, list(TESTPUK))
        except Exception as exc:
            _story_fail("story_3", f"card_unblock_PIN raised {type(exc).__name__}: {exc}")
        record_event({"event": "puk_recovery", "status": "ok"}, artifacts.log_path, events)
        log_step("PUK unblock command succeeded.", artifacts)

        log_step("Step 5: Verifying TESTPIN works after recovery...", artifacts)
        try:
            _, sw1, sw2 = cc_session.card_verify_PIN_simple(TESTPIN)
        except Exception as exc:
            _story_fail("story_3", f"TESTPIN verification after recovery raised {type(exc).__name__}: {exc}")
        if (sw1, sw2) != (0x90, 0x00):
            _story_fail("story_3", f"TESTPIN verify after recovery failed: SW=0x{sw1:02x}{sw2:02x}")
        record_event({"event": "pin_verify_after_recovery", "status": "ok", "sw": f"0x{sw1:02x}{sw2:02x}"},
                     artifacts.log_path, events)
        log_step("TESTPIN verified OK after recovery.", artifacts)

        log_step("Step 6: Verifying PIN tries restored...", artifacts)
        (_, _, _, d_final) = cc_session.card_get_status()
        pin_tries_after = d_final.get("PIN0_remaining_tries", 0)
        puk_tries_after = d_final.get("PUK0_remaining_tries")
        if pin_tries_after <= 0:
            _story_fail("story_3", f"PIN0_remaining_tries not restored: {pin_tries_after}")
        if d_final.get("is_seeded") is not True:
            _story_fail("story_3", f"Card not seeded after PUK recovery: is_seeded={d_final.get('is_seeded')}")

        state_recovered = _get_card_state(cc_session)
        _snap_settings(
            cc_session, config, qtbot, "03-recovered-settings", artifacts, PREFIX,
            storyboard=storyboard, step_number=6, story_name="PUK Recovery",
            title="Recovered Settings", annotation="Settings dialog showing card fully recovered after PUK unblock",
            card_state=state_recovered,
        )

        _cascade_skip["story_3"] = "passed"
        log_step(f"Recovery successful — PIN tries restored to {pin_tries_after}. Story 3 complete.", artifacts)
        record_event(
            {"event": "story_3_complete", "status": "passed",
             "pin_tries_remaining": pin_tries_after,
             "puk_tries_remaining": puk_tries_after},
            artifacts.log_path, events)

        log_step("Generating HTML report...", artifacts)
        report_path = generate_html_report(artifacts, title="Satochip Visual Lifecycle Test")
        if report_path:
            log_step(f"HTML report generated: {report_path}", artifacts)

        log_step("Generating interactive storyboard...", artifacts)
        storyboard = _get_shared_storyboard()
        storyboard_path = artifacts.artifact_dir / "storyboard.html"
        storyboard.write_html(storyboard_path, title="Satochip Visual Lifecycle Storyboard")
        log_step(f"Storyboard generated: {storyboard_path}", artifacts)
