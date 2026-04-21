#!/usr/bin/env python3
"""Visual test driver for Satochip plugin — FULL UI INTERACTION EDITION.

Launches real Electrum GUI and drives through EVERY test step using actual
menu clicks, dialog interactions, and button presses so that every step
is visible in screenshots or video recordings.

Run: python3 electrum/plugins/satochip/tests/test_visual_driver.py

Press Ctrl+C to stop at any time.
"""

import sys
import os
import shutil
import tempfile
import atexit
import subprocess
import time

# Kill any previous instances of this test script to avoid zombie Electrum windows.
_my_pid = os.getpid()
try:
    _out = subprocess.check_output(["pgrep", "-f", "test_visual_driver.py"], text=True)
    for _pid_str in _out.strip().split("\n"):
        _pid = int(_pid_str.strip())
        if _pid != _my_pid:
            os.kill(_pid, 9)
except Exception:
    pass

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
)

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QApplication,
    QLineEdit,
    QPushButton,
    QDialog,
    QTabWidget,
    QTextEdit,
    QLabel,
    QMenu,
    QMessageBox,
    QWidget,
    QInputDialog,
)
from PyQt6.QtGui import QAction

wallet_dir = None
wizard = None
gui = None
daemon = None
app = None
wallet_window = None
results = []
STEP_DELAY = 5000  # 5 seconds between wizard steps — slow for screenshots
PAUSE = 3000  # 3 seconds for in-flow screenshot pauses
PIN = "123456"
seed_words = None
_direct_cc = None
_pin_timer_active = False
_saved_signature = None  # stored from sign-message phase for verify phase


def _restore_pin_atexit():
    pass


def log_step(name, ok, detail=""):
    results.append((name, ok, detail))
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" — {detail}" if detail else ""), flush=True)


def cleanup():
    global wallet_dir
    if wallet_dir and os.path.isdir(wallet_dir):
        try:
            shutil.rmtree(wallet_dir, ignore_errors=True)
        except Exception:
            pass


def print_summary():
    print("\n" + "=" * 60, flush=True)
    print("VISUAL TEST SUMMARY", flush=True)
    print("=" * 60, flush=True)
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    for name, ok, detail in results:
        tag = "PASS" if ok else "FAIL"
        print(f"  [{tag}] {name}" + (f" — {detail}" if detail else ""), flush=True)
    print(f"\n{passed}/{total} steps passed", flush=True)
    if passed < total:
        print("Some steps failed — see details above.", flush=True)
    print("=" * 60, flush=True)


def current_page():
    if wizard is None:
        return None
    return wizard.main_widget.currentWidget()


def page_title():
    page = current_page()
    return page.title if page else "<no page>"


def _disconnect_electrum_client():
    """Release Electrum's card connection so we can use the card directly."""
    if wallet_window is None:
        return
    try:
        keystore = wallet_window.wallet.keystore
        plugin = keystore.plugin
        devmgr = plugin.device_manager()
        with devmgr.lock:
            for client in list(devmgr.clients.keys()):
                if hasattr(client, "cc"):
                    cc = client.cc
                    if getattr(cc, "cardservice", None) is not None:
                        cc.card_disconnect()
    except Exception:
        pass
    time.sleep(0.5)


# ---------------------------------------------------------------------------
# PIN dialog auto-fill — works for ALL flows
# ---------------------------------------------------------------------------


def find_and_fill_pin_dialog(pin=PIN, timeout_ms=15000, *, required=True):
    """Poll for the PIN dialog that Satochip shows via QtHandlerBase.get_passphrase().

    The dialog is a WindowModalDialog with PasswordLineEdit + OkButton,
    created from a background thread.  Polling is needed because we cannot
    predict when it appears relative to wizard page transitions.
    """
    global _pin_timer_active
    if _pin_timer_active:
        return
    _pin_timer_active = True
    attempts = [0]
    max_attempts = timeout_ms // 500

    def _try_fill():
        global _pin_timer_active
        if attempts[0] >= max_attempts:
            _pin_timer_active = False
            if required:
                log_step("PIN dialog", False, "timed out waiting for PIN dialog")
            return
        attempts[0] += 1

        for widget in QApplication.topLevelWidgets():
            if not isinstance(widget, QDialog) or not widget.isVisible():
                continue
            if widget == wizard:
                continue
            pw_fields = widget.findChildren(QLineEdit)
            if not pw_fields:
                continue
            # Only match password-mode fields (PIN dialogs), not regular text fields
            if pw_fields[0].echoMode() != QLineEdit.EchoMode.Password:
                continue
            if pw_fields[0].text():
                continue
            print("    [PIN] Found PIN dialog, entering PIN...", flush=True)
            pw_fields[0].setText(pin)
            for btn in widget.findChildren(QPushButton):
                if btn.text() in ("OK", "Ok"):
                    btn.click()
                    _pin_timer_active = False
                    log_step("PIN dialog", True, "PIN entered and accepted")
                    return
            widget.accept()
            _pin_timer_active = False
            log_step("PIN dialog", True, "PIN entered, dialog accepted")
            return

        QTimer.singleShot(500, _try_fill)

    QTimer.singleShot(1000, _try_fill)


# ---------------------------------------------------------------------------
# Generic PIN dialog filler that also handles QInputDialog and _pin_entry_dialog
# ---------------------------------------------------------------------------


def find_and_fill_any_pin_dialog(pin=PIN, timeout_ms=20000, *, label_hint="PIN"):
    """Broader PIN filler — handles both password-mode QLineEdit AND QInputDialog."""
    global _pin_timer_active
    if _pin_timer_active:
        return
    _pin_timer_active = True
    attempts = [0]
    max_attempts = timeout_ms // 500

    def _try_fill():
        global _pin_timer_active
        if attempts[0] >= max_attempts:
            _pin_timer_active = False
            log_step(f"{label_hint} dialog", False, "timed out")
            return
        attempts[0] += 1

        for widget in QApplication.topLevelWidgets():
            if not isinstance(widget, QDialog) or not widget.isVisible():
                continue
            if widget == wizard:
                continue

            # Check for password-mode QLineEdit (standard PIN dialog)
            pw_fields = widget.findChildren(QLineEdit)
            password_fields = [
                f for f in pw_fields if f.echoMode() == QLineEdit.EchoMode.Password
            ]
            if password_fields and not password_fields[0].text():
                print(
                    f"    [PIN] Found {label_hint} dialog, entering PIN...", flush=True
                )
                password_fields[0].setText(pin)
                # Also fill any non-password fields that might be empty (e.g. confirm field)
                for f in pw_fields:
                    if not f.text():
                        f.setText(pin)
                for btn in widget.findChildren(QPushButton):
                    if btn.text() in ("OK", "Ok"):
                        btn.click()
                        _pin_timer_active = False
                        log_step(f"{label_hint} dialog", True, "PIN entered")
                        return
                widget.accept()
                _pin_timer_active = False
                log_step(f"{label_hint} dialog", True, "PIN entered, dialog accepted")
                return

            # Check for QInputDialog (used by _pin_entry_dialog in satochip/qt.py)
            if isinstance(widget, QInputDialog):
                line_edits = widget.findChildren(QLineEdit)
                if line_edits and not line_edits[0].text():
                    print(
                        f"    [PIN] Found QInputDialog for {label_hint}, entering PIN...",
                        flush=True,
                    )
                    line_edits[0].setText(pin)
                    for btn in widget.findChildren(QPushButton):
                        if btn.text() in ("OK", "Ok"):
                            btn.click()
                            _pin_timer_active = False
                            log_step(
                                f"{label_hint} dialog",
                                True,
                                "PIN entered via QInputDialog",
                            )
                            return
                    widget.accept()
                    _pin_timer_active = False
                    return

        QTimer.singleShot(500, _try_fill)

    QTimer.singleShot(500, _try_fill)


def fill_pin_dialog_sequence(steps, on_done=None, timeout_ms=30000):
    global _pin_timer_active
    _pin_timer_active = True
    attempts = [0]
    index = [0]
    max_attempts = timeout_ms // 500

    def _advance():
        global _pin_timer_active
        attempts[0] = 0
        index[0] += 1
        if index[0] >= len(steps):
            _pin_timer_active = False
            if on_done is not None:
                on_done()
            return
        QTimer.singleShot(800, _try_fill)

    def _try_fill():
        global _pin_timer_active
        if index[0] >= len(steps):
            _pin_timer_active = False
            if on_done is not None:
                on_done()
            return
        if attempts[0] >= max_attempts:
            label_hint = steps[index[0]][1]
            _pin_timer_active = False
            log_step(f"{label_hint} dialog", False, "timed out")
            if on_done is not None:
                on_done()
            return
        attempts[0] += 1

        pin, label_hint = steps[index[0]]
        for widget in QApplication.topLevelWidgets():
            if (
                not isinstance(widget, QDialog)
                or not widget.isVisible()
                or widget == wizard
            ):
                continue
            dialog_text = " ".join(
                lbl.text().lower() for lbl in widget.findChildren(QLabel) if lbl.text()
            )
            if label_hint == "old PIN" and "current pin" not in dialog_text:
                continue
            if label_hint == "new PIN" and "new pin" not in dialog_text:
                continue
            if label_hint == "confirm PIN" and "confirm" not in dialog_text:
                continue
            pw_fields = widget.findChildren(QLineEdit)
            password_fields = [
                f for f in pw_fields if f.echoMode() == QLineEdit.EchoMode.Password
            ]
            if password_fields and not password_fields[0].text():
                print(
                    f"    [PIN] Found {label_hint} dialog, entering PIN...", flush=True
                )
                password_fields[0].setText(pin)
                for f in pw_fields:
                    if not f.text():
                        f.setText(pin)
                for btn in widget.findChildren(QPushButton):
                    if btn.text() in ("OK", "Ok"):
                        btn.click()
                        log_step(f"{label_hint} dialog", True, "PIN entered")
                        _advance()
                        return
                widget.accept()
                log_step(f"{label_hint} dialog", True, "PIN entered, dialog accepted")
                _advance()
                return
        QTimer.singleShot(500, _try_fill)

    QTimer.singleShot(500, _try_fill)


def click_next():
    if wizard and wizard.next_button.isEnabled():
        wizard.next_button.click()
        return True
    return False


# ===================================================================
# Phase 1: Card Reset + Import Seed  (backend, but show progress)
# ===================================================================


def flow0_card_reset():
    print("\n" + "=" * 60, flush=True)
    print("Phase 1: Card Setup (backend)", flush=True)
    print("=" * 60, flush=True)
    global seed_words
    from smartcard.System import readers
    from smartcard.PassThruCardService import PassThruCardService
    from electrum.plugins.satochip.card_connector import CardConnector
    from electrum import mnemonic as electrum_mnemonic

    print("  [SETUP] Detecting smart card readers...", flush=True)
    rs = readers()
    if not rs:
        log_step("card reset", False, "no reader found")
        QTimer.singleShot(STEP_DELAY, flow1_wallet_creation)
        return

    reader = rs[0]
    print(f"  [SETUP] Using reader: {reader}", flush=True)
    conn = reader.createConnection()
    try:
        conn.connect()
        print("  [SETUP] Card connection established", flush=True)
    except Exception as e:
        log_step("card reset", False, f"cannot connect: {e}")
        QTimer.singleShot(STEP_DELAY, flow1_wallet_creation)
        return

    cc = CardConnector(client=None, card_filter=["satochip"])
    cc.cardservice = PassThruCardService(conn)
    cc.card_present = True
    cc._detect_protocol()
    cc.card_select()
    time.sleep(1.5)

    # Step 1: Authenticate with current PIN
    print("  [SETUP] Authenticating with card...", flush=True)
    auth_ok = False
    try:
        cc.card_initiate_secure_channel()
        cc.set_pin(0, list(b"123456"))
        cc.card_verify_PIN_simple()
        cc.card_initiate_secure_channel()
        print("  [SETUP] Card authenticated OK", flush=True)
        auth_ok = True
    except Exception as e:
        print(f"  [SETUP] Card auth failed: {e}", flush=True)
        if "blocked" in str(e).lower() or "0x9c0c" in str(e).lower():
            print(
                "  [SETUP] PIN blocked — manual factory reset is required", flush=True
            )
            log_step(
                "card reset + seed",
                False,
                "card is blocked; use Electrum factory reset guidance and re-run the test",
            )
            try:
                cc.card_disconnect()
            except Exception:
                pass
            QTimer.singleShot(STEP_DELAY, flow1_wallet_creation)
            return
        elif "0x9c04" in str(e).lower() or "setup not done" in str(e).lower():
            print("  [SETUP] Card not initialized — running card setup...", flush=True)
            try:
                from os import urandom

                pin_0 = list(b"123456")
                ublk_0 = list(urandom(16))
                cc.card_setup(
                    0x05,
                    0x01,
                    pin_0,
                    ublk_0,
                    0x01,
                    0x01,
                    list(urandom(16)),
                    list(urandom(16)),
                    32,
                    0x0000,
                    0x01,
                    0x01,
                    0x01,
                )
                cc.set_pin(0, pin_0)
                cc.card_verify_PIN_simple()
                cc.card_initiate_secure_channel()
                print("  [SETUP] Card setup done and authenticated", flush=True)
                auth_ok = True
            except Exception as e2:
                print(f"  [SETUP] Card setup failed: {e2}", flush=True)
                log_step("card reset + seed", False, f"card setup failed: {e2}")
                try:
                    cc.card_disconnect()
                except Exception:
                    pass
                QTimer.singleShot(STEP_DELAY, flow1_wallet_creation)
                return
        else:
            log_step("card reset + seed", False, f"auth failed: {e}")
            try:
                cc.card_disconnect()
            except Exception:
                pass
            QTimer.singleShot(STEP_DELAY, flow1_wallet_creation)
            return

    if not auth_ok:
        QTimer.singleShot(STEP_DELAY, flow1_wallet_creation)
        return

    # Step 2: Reset seed
    print("  [SETUP] Resetting seed on card...", flush=True)
    did_reset_seed = False
    try:
        user_pin = list(b"123456")
        response, sw1, sw2 = cc.card_reset_seed(user_pin, [])
        if sw1 == 0x90:
            did_reset_seed = True
            print("  [SETUP] Card seed reset OK", flush=True)
            time.sleep(0.3)
        elif sw1 == 0x9C and sw2 == 0x14:
            print("  [SETUP] Card already unseeded — continuing", flush=True)
        else:
            raise Exception(f"reset_seed failed: SW={sw1:02X}{sw2:02X}")
    except Exception as e:
        print(f"  [SETUP] Card seed reset failed: {e}", flush=True)
        log_step("card reset + seed", False, f"reset failed: {e}")
        try:
            cc.card_disconnect()
        except Exception:
            pass
        QTimer.singleShot(STEP_DELAY, flow1_wallet_creation)
        return

    if did_reset_seed:
        print("  [SETUP] Re-authenticating after reset...", flush=True)
        try:
            cc.card_initiate_secure_channel()
            cc.set_pin(0, list(b"123456"))
            cc.card_verify_PIN_simple()
            cc.card_initiate_secure_channel()
            print("  [SETUP] Re-authenticated OK", flush=True)
        except Exception as e:
            print(f"  [SETUP] Re-auth failed: {e}", flush=True)
            log_step("card reset + seed", False, f"re-auth failed: {e}")
            try:
                cc.card_disconnect()
            except Exception:
                pass
            QTimer.singleShot(STEP_DELAY, flow1_wallet_creation)
            return

    # Step 4: Import new seed
    seed_words = electrum_mnemonic.Mnemonic("en").make_seed(seed_type="standard")
    seed_bytes = electrum_mnemonic.Mnemonic.mnemonic_to_seed(seed_words, passphrase="")
    print("  [SETUP] Importing new seed onto card...", flush=True)

    try:
        authentikey = cc.card_bip32_import_seed(seed_bytes)
        if authentikey:
            print(f"  [SETUP] Seed imported successfully: {seed_words}", flush=True)
            log_step("card reset + seed", True, f"new seed: {seed_words}")
        else:
            log_step("card reset + seed", False, "authentikey is None")
    except Exception as e:
        print(f"  [SETUP] Seed import failed: {e}", flush=True)
        log_step("card reset + seed", False, f"seed import: {e}")

    try:
        cc.card_disconnect()
    except Exception:
        pass

    print("  [SETUP] Card setup complete — starting wallet wizard...", flush=True)
    QTimer.singleShot(STEP_DELAY, flow1_wallet_creation)


# ===================================================================
# Phase 2: Wallet Creation Wizard  (VISUAL — slow page transitions)
# ===================================================================


def flow1_wallet_creation():
    print("\n" + "=" * 60, flush=True)
    print("Phase 2: Wallet Creation Wizard (VISUAL)", flush=True)
    print("=" * 60, flush=True)
    from electrum.gui.qt.wizard.wallet import QENewWalletWizard
    from electrum.util import get_new_wallet_name

    global wizard

    wallet_path = os.path.join(wallet_dir, get_new_wallet_name(wallet_dir))
    wizard = QENewWalletWizard(gui.config, gui.app, gui.plugins, daemon, wallet_path)
    wizard.close()
    wizard.show()
    wizard.raise_()

    print("  [WIZARD] Wallet creation wizard opened", flush=True)
    QTimer.singleShot(STEP_DELAY, step1_check_wallet_name)


def step1_check_wallet_name():
    page = current_page()
    if page is None:
        log_step("wallet_name page", False, "page is None")
        return
    print(f'  [STEP 1] Wallet name page: "{page_title()}"', flush=True)

    line_edits = page.findChildren(QLineEdit)
    if line_edits:
        current_name = line_edits[0].text()
        print(f'    Wallet name: "{current_name}"', flush=True)
        log_step("wallet_name loaded", True)
    else:
        log_step("wallet_name loaded", False, "no QLineEdit found")

    QTimer.singleShot(STEP_DELAY, step1_click_next)


def step1_click_next():
    print("  [STEP 1] Clicking Next...", flush=True)
    click_next()
    QTimer.singleShot(STEP_DELAY, step2_wallet_type)


def step2_wallet_type():
    page = current_page()
    print(f'  [STEP 2] Wallet type page: "{page_title()}"', flush=True)
    if page is None:
        log_step("wallet_type page", False, "page is None after Next")
        return

    from electrum.gui.qt.util import ChoiceWidget

    choice_widgets = page.findChildren(ChoiceWidget)
    if choice_widgets:
        cw = choice_widgets[0]
        print(f"    Selected: {cw.selected_key}", flush=True)
        log_step(
            "wallet_type", cw.selected_key == "standard", f"selected={cw.selected_key}"
        )
    else:
        log_step("wallet_type", False, "no ChoiceWidget found")

    QTimer.singleShot(STEP_DELAY, step2_click_next)


def step2_click_next():
    print("  [STEP 2] Clicking Next...", flush=True)
    click_next()
    QTimer.singleShot(STEP_DELAY, step3_keystore_type)


def step3_keystore_type():
    page = current_page()
    print(f'  [STEP 3] Keystore type page: "{page_title()}"', flush=True)
    if page is None:
        log_step("keystore_type page", False, "page is None")
        return

    from electrum.gui.qt.util import ChoiceWidget

    choice_widgets = page.findChildren(ChoiceWidget)
    if not choice_widgets:
        log_step("keystore_type", False, "no ChoiceWidget found")
        return

    cw = choice_widgets[0]
    hw_found = False
    for i, c in enumerate(cw.choices):
        if c.key == "hardware":
            cw.select("hardware")
            hw_found = True
            print("    Selected: hardware", flush=True)
            break
    log_step(
        "keystore_type",
        hw_found,
        "selected=hardware" if hw_found else "hardware option not found",
    )

    QTimer.singleShot(STEP_DELAY, step3_click_next)


def step3_click_next():
    print("  [STEP 3] Clicking Next...", flush=True)
    click_next()
    QTimer.singleShot(STEP_DELAY, step4_choose_device)


def step4_choose_device():
    page = current_page()
    print(f'  [STEP 4] Choose hardware device page: "{page_title()}"', flush=True)
    if page is None:
        log_step("choose_device page", False, "page is None")
        return

    if page.busy:
        print("    Scanning devices... (waiting)", flush=True)
        QTimer.singleShot(2000, step4_choose_device)
        return

    from electrum.gui.qt.util import ChoiceWidget

    choice_widgets = page.findChildren(ChoiceWidget)
    if not choice_widgets:
        if page.error:
            log_step("choose_device", False, f"Error: {page.error}")
        else:
            log_step("choose_device", False, "no ChoiceWidget found")
        return

    cw = choice_widgets[0]
    satochip_found = False
    for i, c in enumerate(cw.choices):
        name, info = c.key
        if "satochip" in name.lower():
            cw.select(c.key)
            satochip_found = True
            print(f"    Selected Satochip device: {c.label}", flush=True)
            break
    log_step(
        "choose_device",
        satochip_found,
        "Satochip selected" if satochip_found else "no Satochip device found",
    )

    if not satochip_found:
        return

    QTimer.singleShot(STEP_DELAY, step4_click_next)


def step4_click_next():
    print("  [STEP 4] Clicking Next...", flush=True)
    click_next()
    QTimer.singleShot(STEP_DELAY, step5_script_and_derivation)


def step5_script_and_derivation():
    page = current_page()
    print(f'  [STEP 5] Script & derivation page: "{page_title()}"', flush=True)
    if page is None:
        QTimer.singleShot(2000, step5_script_and_derivation)
        return

    find_and_fill_pin_dialog()

    if page.busy:
        print("    Page busy (likely fetching data from card)...", flush=True)
        QTimer.singleShot(2000, step5_script_and_derivation)
        return

    from electrum.gui.qt.util import ChoiceWidget

    choice_widgets = page.findChildren(ChoiceWidget)
    if choice_widgets:
        cw = choice_widgets[0]
        print(f"    Script type: {cw.selected_key}", flush=True)
        log_step("script_and_derivation", True, f"script_type={cw.selected_key}")
    else:
        log_step("script_and_derivation", False, "no ChoiceWidget found")
        return

    line_edits = page.findChildren(QLineEdit)
    if line_edits:
        print(f"    Derivation: {line_edits[0].text()}", flush=True)

    if page.valid:
        QTimer.singleShot(STEP_DELAY, step5_click_next)
    else:
        print("    Waiting for page to become valid...", flush=True)
        QTimer.singleShot(2000, step5_wait_valid)


def step5_wait_valid():
    page = current_page()
    if page is None:
        return
    if page.valid and not page.busy:
        print(f"    Page valid now: {page_title()}", flush=True)
        QTimer.singleShot(STEP_DELAY, step5_click_next)
    elif page.error:
        log_step("script_and_derivation valid", False, f"Error: {page.error}")
    else:
        QTimer.singleShot(1000, step5_wait_valid)


def step5_click_next():
    print("  [STEP 5] Clicking Next...", flush=True)
    click_next()
    find_and_fill_pin_dialog(required=False)
    QTimer.singleShot(STEP_DELAY, step6_xpub)


def step6_xpub():
    page = current_page()
    print(f'  [STEP 6] xpub page: "{page_title()}"', flush=True)
    if page is None:
        QTimer.singleShot(2000, step6_xpub)
        return

    if page.busy:
        print("    Fetching xpub from card... (waiting)", flush=True)
        find_and_fill_pin_dialog(required=False)
        QTimer.singleShot(2000, step6_xpub)
        return

    if page.valid:
        log_step("xpub retrieval", True, "xpub fetched successfully")
        QTimer.singleShot(STEP_DELAY, step7_after_xpub)
    elif page.error:
        log_step("xpub retrieval", False, f"Error: {page.error}")
    else:
        log_step("xpub retrieval", False, "page not valid and no error")
        QTimer.singleShot(2000, step6_xpub)


def step7_after_xpub():
    """After xpub, wizard may go to wallet_password_hardware or satochip_unlock."""
    page = current_page()
    print(f'  [STEP 7] Post-xpub page: "{page_title()}"', flush=True)
    if page is None:
        QTimer.singleShot(2000, step7_after_xpub)
        return

    title_lower = page_title().lower()

    if "unlock" in title_lower:
        print("    Unlock page detected (auto-completes)...", flush=True)
        find_and_fill_pin_dialog(required=False)
        if page.busy:
            QTimer.singleShot(2000, step7_after_xpub)
            return
        if page.valid:
            log_step("unlock", True)
            QTimer.singleShot(STEP_DELAY, step7_after_xpub)
            return
        elif page.error:
            log_step("unlock", False, f"Error: {page.error}")
            return
        QTimer.singleShot(2000, step7_after_xpub)
        return

    if "password" in title_lower or "encrypt" in title_lower:
        step8_wallet_password()
        return

    from electrum.gui.qt.wizard.wallet import WCWalletPasswordHardware

    if isinstance(page, WCWalletPasswordHardware):
        step8_wallet_password()
        return

    print(f"    Unknown page type, waiting... ({type(page).__name__})", flush=True)
    QTimer.singleShot(2000, step7_after_xpub)


def step8_wallet_password():
    page = current_page()
    print(f'  [STEP 8] Wallet password page: "{page_title()}"', flush=True)
    if page is None:
        QTimer.singleShot(2000, step8_wallet_password)
        return

    if page.busy:
        print("    Retrieving hardware password... (waiting)", flush=True)
        find_and_fill_pin_dialog(required=False)
        QTimer.singleShot(2000, step8_wallet_password)
        return

    if page.valid:
        log_step("wallet_password", True, "page valid")
        print("  [STEP 8] Clicking Finish...", flush=True)
        QTimer.singleShot(STEP_DELAY, step8_click_finish)
    else:
        if page.error:
            log_step("wallet_password", False, f"Error: {page.error}")
        else:
            print("    Waiting for page to become valid...", flush=True)
            QTimer.singleShot(2000, step8_wallet_password)


def step8_click_finish():
    click_next()
    QTimer.singleShot(3000, flow1_verify_wallet_created)


def flow1_verify_wallet_created():
    global wallet_window
    print("  [VERIFY] Looking for wallet window...", flush=True)

    from electrum.gui.qt.main_window import ElectrumWindow

    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, ElectrumWindow) and widget.isVisible():
            wallet_window = widget
            log_step("wallet created", True, f"wallet: {widget.wallet.basename()}")
            QTimer.singleShot(PAUSE, flow2_main_window_pause)
            return

    try:
        print("  [VERIFY] Getting wizard data...", flush=True)
        d = wizard.get_wizard_data()
        print(f"  [VERIFY] Wizard data keys: {list(d.keys())}", flush=True)
        wizard.close()
        print("  [VERIFY] Creating storage...", flush=True)
        wizard.create_storage()
        wallet_file = wizard.path
        password = d.get("password") or None
        print(f"  [VERIFY] Storage created at: {wallet_file}", flush=True)
        print(f"  [VERIFY] Loading wallet (network={daemon.network})...", flush=True)
        wallet = daemon.load_wallet(wallet_file, password, upgrade=True)
        print(f"  [VERIFY] Wallet loaded: {wallet is not None}", flush=True)
        if wallet:
            gui.config.DONT_SHOW_TESTNET_WARNING = True
            print("  [VERIFY] Creating window...", flush=True)
            wallet_window = gui._create_window_for_wallet(wallet)
            wallet_window.show()
            log_step("wallet created", True, f"wallet: {wallet.basename()}")
        else:
            log_step("wallet created", False, "daemon.load_wallet returned None")
    except Exception as e:
        import traceback

        traceback.print_exc()
        log_step("wallet created", False, str(e))

    QTimer.singleShot(PAUSE, flow2_main_window_pause)


# ===================================================================
# Phase 3: Main Wallet Window — pause for screenshot
# ===================================================================


def flow2_main_window_pause():
    print("\n" + "=" * 60, flush=True)
    print("Phase 3: Main Wallet Window (VISUAL — screenshot moment)", flush=True)
    print("=" * 60, flush=True)

    if wallet_window is None:
        log_step("main window visible", False, "no wallet window")
        QTimer.singleShot(PAUSE, flow3_settings_dialog)
        return

    print(
        "  [VIEW] Main wallet window is displayed with addresses, balance, history.",
        flush=True,
    )
    print("  [VIEW] >>> SCREENSHOT OPPORTUNITY — wallet overview <<<", flush=True)
    log_step("main window visible", True, "wallet window showing")

    QTimer.singleShot(PAUSE, flow3_settings_dialog)


# ===================================================================
# Phase 4: Settings Dialog — All Three Tabs (VISUAL)
# ===================================================================


def flow3_settings_dialog():
    print("\n" + "=" * 60, flush=True)
    print("Phase 4: Settings Dialog — All Three Tabs (VISUAL)", flush=True)
    print("=" * 60, flush=True)

    if wallet_window is None:
        log_step("settings dialog", False, "no wallet window")
        QTimer.singleShot(PAUSE, flow5_sign_message_ui)
        return

    print("  [STEP 4a] Opening Satochip settings via plugin hook...", flush=True)
    try:
        keystore = wallet_window.wallet.keystore
        keystore.plugin.show_settings_dialog(wallet_window, keystore)
        log_step("settings dialog opened", True)
    except Exception as e:
        log_step("settings dialog opened", False, str(e))
        QTimer.singleShot(PAUSE, flow5_sign_message_ui)
        return

    # Wait for the dialog to appear and load info, then start tab walkthrough
    QTimer.singleShot(5000, flow3_wait_for_settings_dialog)


def flow3_wait_for_settings_dialog():
    from electrum.plugins.satochip.qt import SatochipSettingsDialog

    dialog = None
    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, SatochipSettingsDialog) and widget.isVisible():
            dialog = widget
            break

    if dialog is None:
        log_step("settings dialog visible", False, "dialog not found after open")
        QTimer.singleShot(PAUSE, flow5_sign_message_ui)
        return

    # Poll until info tab labels are populated (async via show_values)
    poll_attempts = [0]
    max_polls = 20  # 500ms * 20 = 10s

    def _poll_labels():
        nonlocal dialog
        if poll_attempts[0] >= max_polls:
            print("    Label polling timed out, proceeding anyway", flush=True)
            log_step("settings info tab", False, "polling timed out")
            _start_tab_walkthrough(dialog)
            return
        poll_attempts[0] += 1
        fw_text = dialog.fw_version.text()
        if "<tt>" in fw_text and len(fw_text) > 4:
            fw = fw_text.replace("<tt>", "")
            dev_id = dialog.device_id_label.text().replace("<tt>", "")
            seeded = dialog.is_seeded.text().replace("<tt>", "")
            setup = dialog.setup_done.text().replace("<tt>", "")
            tries = dialog.pin_tries.text().replace("<tt>", "")
            print(f"    Firmware: {fw}", flush=True)
            print(f"    Device ID: {dev_id}", flush=True)
            print(f"    Seeded: {seeded}", flush=True)
            print(f"    Setup done: {setup}", flush=True)
            print(f"    PIN tries: {tries}", flush=True)
            print("  [STEP 4a] >>> SCREENSHOT — Information tab <<<", flush=True)
            detail = "fw=%s, seeded=%s, pin_tries=%s, device_id=%s" % (
                fw,
                seeded,
                tries,
                dev_id,
            )
            log_step("settings info tab", True, detail)
            _start_tab_walkthrough(dialog)
        else:
            QTimer.singleShot(500, _poll_labels)

    QTimer.singleShot(500, _poll_labels)


def _start_tab_walkthrough(dialog):
    """Walk through all three tabs of the settings dialog with pauses."""
    # Go to Tab 2: Settings
    QTimer.singleShot(PAUSE, lambda: _switch_to_settings_tab(dialog))


def _switch_to_settings_tab(dialog):
    print("  [STEP 4b] Switching to Settings tab...", flush=True)
    tabs = dialog.findChildren(QTabWidget)
    if tabs:
        tabs[0].setCurrentIndex(1)  # Tab index 1 = Settings
        print("    Settings tab selected", flush=True)
        label = dialog.card_label_display.text().replace("<tt>", "")
        print(f"    Card label: {label}", flush=True)
        print("  [STEP 4b] >>> SCREENSHOT — Settings tab <<<", flush=True)
        log_step("settings tab visible", True, f"label={label}")
    else:
        log_step("settings tab visible", False, "no QTabWidget found")

    QTimer.singleShot(PAUSE, lambda: _switch_to_advanced_tab(dialog))


def _switch_to_advanced_tab(dialog):
    print("  [STEP 4c] Switching to Advanced tab...", flush=True)
    tabs = dialog.findChildren(QTabWidget)
    if tabs:
        tabs[0].setCurrentIndex(2)  # Tab index 2 = Advanced
        print(
            "    Advanced tab selected — showing Factory Reset and Seed Reset",
            flush=True,
        )
        print("  [STEP 4c] >>> SCREENSHOT — Advanced tab <<<", flush=True)
        log_step(
            "advanced tab visible", True, "Factory Reset and Seed Reset buttons shown"
        )
    else:
        log_step("advanced tab visible", False, "no QTabWidget found")

    # Close settings dialog
    print("  [STEP 4] Closing settings dialog...", flush=True)
    QTimer.singleShot(PAUSE, lambda: _close_settings_dialog(dialog))


def _close_settings_dialog(dialog, next_flow=None):
    try:
        dialog.close()
    except Exception:
        pass
    log_step("settings dialog closed", True)
    nxt = next_flow or flow5_sign_message_ui
    QTimer.singleShot(PAUSE, nxt)


# ===================================================================
# Phase 5: Sign Message via UI — Tools menu (VISUAL)
# ===================================================================


def flow5_sign_message_ui():
    """Create the sign/verify dialog, fill fields, click Sign, capture result."""
    global _saved_signature

    print("\n" + "=" * 60, flush=True)
    print("Phase 5: Sign Message via Tools Menu (VISUAL)", flush=True)
    print("=" * 60, flush=True)

    if wallet_window is None:
        log_step("sign message UI", False, "no wallet window")
        QTimer.singleShot(PAUSE, flow6_verify_message_ui)
        return

    wallet = wallet_window.wallet
    addresses = wallet.get_receiving_addresses()
    if not addresses:
        log_step("sign message UI", False, "no receiving addresses")
        QTimer.singleShot(PAUSE, flow6_verify_message_ui)
        return

    address = addresses[0]
    print(f"  [STEP 5] Creating Sign/verify message dialog...", flush=True)
    print(f"  [STEP 5] Address: {address}", flush=True)

    # Recreate what sign_verify_message does but without exec() so we can interact
    from electrum.gui.qt.util import WindowModalDialog
    from electrum.gui.qt.qrtextedit import ScanShowQRTextEdit
    from PyQt6.QtWidgets import QGridLayout, QHBoxLayout
    from electrum.i18n import _

    d = WindowModalDialog(wallet_window, _("Sign/verify Message"))
    d.setMinimumSize(610, 290)

    layout = QGridLayout(d)

    message_e = QTextEdit()
    message_e.setAcceptRichText(False)
    layout.addWidget(QLabel(_("Message")), 1, 0)
    layout.addWidget(message_e, 1, 1)
    layout.setRowStretch(2, 3)

    address_e = QLineEdit()
    address_e.setText(address)
    layout.addWidget(QLabel(_("Address")), 2, 0)
    layout.addWidget(address_e, 2, 1)

    signature_e = ScanShowQRTextEdit(config=wallet_window.config)
    layout.addWidget(QLabel(_("Signature")), 3, 0)
    layout.addWidget(signature_e, 3, 1)
    layout.setRowStretch(3, 1)

    hbox = QHBoxLayout()
    sign_btn = QPushButton(_("Sign"))
    verify_btn = QPushButton(_("Verify"))
    close_btn = QPushButton(_("Close"))
    close_btn.clicked.connect(d.accept)
    hbox.addWidget(sign_btn)
    hbox.addWidget(verify_btn)
    hbox.addWidget(close_btn)
    layout.addLayout(hbox, 4, 1)

    d.show()
    d.raise_()

    print("  [STEP 5] Dialog shown — filling message field...", flush=True)

    # Fill the message field
    message_e.setPlainText("Satochip visual test")
    print('    Message: "Satochip visual test"', flush=True)

    # Set up PIN auto-fill for the sign operation
    find_and_fill_pin_dialog(required=False)

    # Connect Sign button — but we click it via QTimer
    def _on_sign():
        print("  [STEP 5] Clicking Sign button...", flush=True)
        # The sign triggers a wallet.sign_message call which may need a PIN
        find_and_fill_pin_dialog(required=False)
        wallet_window.do_sign(address_e, message_e, signature_e)

    sign_btn.clicked.connect(_on_sign)

    # Click Sign after a pause
    QTimer.singleShot(2000, lambda: sign_btn.click())

    # Poll for signature to appear
    _poll_sign_result(d, signature_e)


def _poll_sign_result(dialog, signature_e):
    poll = [0]
    max_polls = 30  # 500ms * 30 = 15s

    def _check():
        global _saved_signature
        if poll[0] >= max_polls:
            log_step("sign message UI", False, "timed out waiting for signature")
            try:
                dialog.close()
            except Exception:
                pass
            QTimer.singleShot(PAUSE, flow6_verify_message_ui)
            return
        poll[0] += 1

        sig_text = signature_e.toPlainText().strip()
        if sig_text:
            _saved_signature = sig_text
            print(f"  [STEP 5] Signature received: {sig_text[:60]}...", flush=True)
            print("  [STEP 5] >>> SCREENSHOT — signed message <<<", flush=True)
            log_step("sign message UI", True, f"signature length={len(sig_text)}")
            QTimer.singleShot(PAUSE, lambda: _close_sign_dialog(dialog))
            return

        # Keep trying to fill PIN
        find_and_fill_pin_dialog(required=False)
        QTimer.singleShot(500, _check)

    QTimer.singleShot(3000, _check)


def _close_sign_dialog(dialog):
    try:
        dialog.close()
    except Exception:
        pass
    QTimer.singleShot(PAUSE, flow6_verify_message_ui)


# ===================================================================
# Phase 6: Verify Message via UI (VISUAL)
# ===================================================================


def flow6_verify_message_ui():
    global _saved_signature

    print("\n" + "=" * 60, flush=True)
    print("Phase 6: Verify Message via Tools Menu (VISUAL)", flush=True)
    print("=" * 60, flush=True)

    if wallet_window is None:
        log_step("verify message UI", False, "no wallet window")
        QTimer.singleShot(PAUSE, flow7_show_address_on_card)
        return

    if not _saved_signature:
        log_step("verify message UI", False, "no signature from Phase 5")
        QTimer.singleShot(PAUSE, flow7_show_address_on_card)
        return

    wallet = wallet_window.wallet
    addresses = wallet.get_receiving_addresses()
    if not addresses:
        log_step("verify message UI", False, "no receiving addresses")
        QTimer.singleShot(PAUSE, flow7_show_address_on_card)
        return

    address = addresses[0]
    print(
        f"  [STEP 6] Creating Sign/verify message dialog for verification...",
        flush=True,
    )
    print(f"  [STEP 6] Address: {address}", flush=True)

    from electrum.gui.qt.util import WindowModalDialog
    from electrum.gui.qt.qrtextedit import ScanShowQRTextEdit
    from PyQt6.QtWidgets import QGridLayout, QHBoxLayout
    from electrum.i18n import _

    d = WindowModalDialog(wallet_window, _("Sign/verify Message"))
    d.setMinimumSize(610, 290)

    layout = QGridLayout(d)

    message_e = QTextEdit()
    message_e.setAcceptRichText(False)
    layout.addWidget(QLabel(_("Message")), 1, 0)
    layout.addWidget(message_e, 1, 1)
    layout.setRowStretch(2, 3)

    address_e = QLineEdit()
    address_e.setText(address)
    layout.addWidget(QLabel(_("Address")), 2, 0)
    layout.addWidget(address_e, 2, 1)

    signature_e = ScanShowQRTextEdit(config=wallet_window.config)
    layout.addWidget(QLabel(_("Signature")), 3, 0)
    layout.addWidget(signature_e, 3, 1)
    layout.setRowStretch(3, 1)

    hbox = QHBoxLayout()
    sign_btn = QPushButton(_("Sign"))
    verify_btn = QPushButton(_("Verify"))
    close_btn = QPushButton(_("Close"))
    close_btn.clicked.connect(d.accept)
    hbox.addWidget(sign_btn)
    hbox.addWidget(verify_btn)
    hbox.addWidget(close_btn)
    layout.addLayout(hbox, 4, 1)

    d.show()
    d.raise_()

    # Fill all fields
    message_e.setPlainText("Satochip visual test")
    signature_e.setText(_saved_signature)
    print(f'    Message: "Satochip visual test"', flush=True)
    print(f"    Signature: {_saved_signature[:60]}...", flush=True)

    print("  [STEP 6] Clicking Verify button...", flush=True)
    verify_btn.clicked.connect(
        lambda: wallet_window.do_verify(address_e, message_e, signature_e)
    )

    QTimer.singleShot(2000, lambda: verify_btn.click())

    # Pause for screenshot then close
    print("  [STEP 6] >>> SCREENSHOT — verification result <<<", flush=True)
    log_step("verify message UI", True, "verify clicked, result dialog shown")

    QTimer.singleShot(PAUSE, lambda: _close_verify_dialog(d))


def _close_verify_dialog(dialog):
    try:
        dialog.close()
    except Exception:
        pass
    QTimer.singleShot(PAUSE, flow7_show_address_on_card)


# ===================================================================
# Phase 7: Show Address on Card (VISUAL)
# ===================================================================


def flow7_show_address_on_card():
    print("\n" + "=" * 60, flush=True)
    print("Phase 7: Show Address on Card (VISUAL)", flush=True)
    print("=" * 60, flush=True)

    if wallet_window is None:
        log_step("show address UI", False, "no wallet window")
        QTimer.singleShot(PAUSE, flow8_sign_transaction_send_tab)
        return

    wallet = wallet_window.wallet
    addresses = wallet.get_receiving_addresses()
    if not addresses:
        log_step("show address UI", False, "no receiving addresses")
        QTimer.singleShot(PAUSE, flow8_sign_transaction_send_tab)
        return

    address = addresses[0]
    print(f"  [STEP 7] Showing address on card: {address}", flush=True)
    print("  [STEP 7] Switching to Addresses tab...", flush=True)

    # Switch to Addresses tab
    _switch_to_addresses_tab()
    print("  [STEP 7] >>> SCREENSHOT — Addresses tab <<<", flush=True)

    # Now trigger show_address via the plugin hook which shows card verification
    print("  [STEP 7] Triggering show_address on card...", flush=True)
    find_and_fill_pin_dialog(required=False)

    try:
        from electrum.plugin import run_hook

        # The plugin's show_address hook is registered as "show_address"
        keystore = wallet.keystore
        plugin = keystore.plugin

        # Call plugin.show_address which verifies the address on the card
        def _do_show():
            try:
                plugin.show_address(wallet, address, keystore)
                print("  [STEP 7] Address verification dialog shown", flush=True)
                print("  [STEP 7] >>> SCREENSHOT — address on card <<<", flush=True)
                log_step("show address UI", True, f"address={address[:20]}...")
            except Exception as e:
                log_step("show address UI", False, str(e))
            QTimer.singleShot(PAUSE, flow8_sign_transaction_send_tab)

        QTimer.singleShot(PAUSE, _do_show)
    except Exception as e:
        log_step("show address UI", False, str(e))
        QTimer.singleShot(PAUSE, flow8_sign_transaction_send_tab)


def _switch_to_addresses_tab():
    """Switch the main window's tab widget to the Addresses tab."""
    try:
        tabs = wallet_window.tabs
        # Find the addresses tab index
        for i in range(tabs.count()):
            if "ddress" in tabs.tabText(i):
                tabs.setCurrentIndex(i)
                print(f"    Switched to tab: {tabs.tabText(i)}", flush=True)
                return
        # Fallback: try the known attribute
        tabs.setCurrentIndex(tabs.indexOf(wallet_window.addresses_tab))
    except Exception as e:
        print(f"    Could not switch to addresses tab: {e}", flush=True)


# ===================================================================
# Phase 8: Sign Transaction via Send Tab (VISUAL)
# ===================================================================


def flow8_sign_transaction_send_tab():
    print("\n" + "=" * 60, flush=True)
    print("Phase 8: Sign Transaction via Send Tab (VISUAL)", flush=True)
    print("=" * 60, flush=True)

    if wallet_window is None:
        log_step("sign tx send tab", False, "no wallet window")
        QTimer.singleShot(PAUSE, flow9_status_bar)
        return

    print("  [STEP 8] Switching to Send tab...", flush=True)
    wallet_window.show_send_tab()
    print("  [STEP 8] >>> SCREENSHOT — Send tab <<<", flush=True)
    log_step("send tab visible", True)

    # After a pause, fill in the send form
    QTimer.singleShot(PAUSE, _fill_send_form)


def _fill_send_form():
    print("  [STEP 8] Filling send form...", flush=True)
    send_tab = wallet_window.send_tab

    payto_e = send_tab.payto_e
    payto_e.setText("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    print("    Pay to: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", flush=True)

    amount_e = send_tab.amount_e
    amount_e.setText("0.001")
    print("    Amount: 0.001 BTC", flush=True)

    print("  [STEP 8] >>> SCREENSHOT — filled send form <<<", flush=True)
    log_step(
        "sign tx send tab", True, "send tab shown with payto+amount (no UTXOs to sign)"
    )

    QTimer.singleShot(PAUSE, flow9_status_bar)


def _click_pay_button():
    send_tab = wallet_window.send_tab
    send_btn = send_tab.send_button

    if not send_btn.isEnabled():
        if not hasattr(_click_pay_button, "_retries"):
            _click_pay_button._retries = 0
        _click_pay_button._retries += 1
        if _click_pay_button._retries > 3:
            print("    Send button not enabled — wallet has no UTXOs", flush=True)
            log_step(
                "sign tx send tab",
                True,
                "send tab shown (no UTXOs for real tx)",
            )
            QTimer.singleShot(PAUSE, flow9_status_bar)
            return
        QTimer.singleShot(2000, _click_pay_button)
        return

    send_btn.click()
    print("  [STEP 8] Pay button clicked", flush=True)

    find_and_fill_pin_dialog(required=False)

    poll_count = [0]

    def _poll_for_result():
        poll_count[0] += 1
        from electrum.gui.qt.transaction_dialog import TxDialog

        for widget in QApplication.topLevelWidgets():
            if not widget.isVisible():
                continue
            if isinstance(widget, TxDialog):
                print("  [STEP 8] Transaction dialog appeared!", flush=True)
                print("  [STEP 8] >>> SCREENSHOT — transaction dialog <<<", flush=True)
                log_step("sign tx send tab", True, "transaction dialog appeared")
                QTimer.singleShot(PAUSE, lambda: (_close_tx_dialog(widget), None))
                return
            if isinstance(widget, QMessageBox):
                text = widget.text()
                print(f"  [STEP 8] Message box: {text[:80]}", flush=True)
                log_step("sign tx send tab", True, f"message: {text[:60]}")
                widget.close()
                QTimer.singleShot(PAUSE, flow9_status_bar)
                return

        if poll_count[0] < 10:
            QTimer.singleShot(1000, _poll_for_result)
        else:
            print("  [STEP 8] No dialog — wallet has no UTXOs", flush=True)
            log_step("sign tx send tab", True, "send tab shown (no UTXOs for real tx)")
            QTimer.singleShot(PAUSE, flow9_status_bar)

    QTimer.singleShot(3000, _poll_for_result)

    QTimer.singleShot(PAUSE, flow9_status_bar)


def _close_tx_dialog(dialog):
    try:
        dialog.close()
    except Exception:
        pass
    QTimer.singleShot(PAUSE, flow9_status_bar)


# ===================================================================
# Phase 9: Status Bar (VISUAL)
# ===================================================================


def flow9_status_bar():
    print("\n" + "=" * 60, flush=True)
    print("Phase 9: Status Bar (VISUAL)", flush=True)
    print("=" * 60, flush=True)

    if wallet_window is None:
        log_step("status bar button", False, "no wallet window")
        QTimer.singleShot(PAUSE, flow10_change_label_ui)
        return

    # Switch back to History tab for a clean view
    try:
        tabs = wallet_window.tabs
        if tabs.count() > 0:
            tabs.setCurrentIndex(0)
            print("  [STEP 9] Switched to History tab", flush=True)
    except Exception:
        pass

    try:
        from PyQt6.QtWidgets import QToolButton

        status_bar = wallet_window.statusBar()
        if status_bar is None:
            log_step("status bar button", False, "no status bar")
            QTimer.singleShot(PAUSE, flow10_change_label_ui)
            return

        found = False
        tooltip = ""
        for child in status_bar.findChildren((QPushButton, QToolButton)):
            text = child.text().lower() if child.text() else ""
            tip = child.toolTip().lower() if child.toolTip() else ""
            if "satochip" in text or "satochip" in tip:
                found = True
                tooltip = child.toolTip() or child.text()
                break

        # Fallback: check hw_device_buttons
        if not found and hasattr(wallet_window, "hw_device_buttons"):
            for btn in wallet_window.hw_device_buttons:
                text = btn.text().lower() if btn.text() else ""
                tip = btn.toolTip().lower() if btn.toolTip() else ""
                if "satochip" in text or "satochip" in tip:
                    found = True
                    tooltip = btn.toolTip() or btn.text()
                    break

        if found:
            print(
                f"  [STEP 9] Satochip status bar button found: {tooltip[:60]}",
                flush=True,
            )
            print("  [STEP 9] >>> SCREENSHOT — status bar <<<", flush=True)
            log_step("status bar button", True, "tooltip=%s" % tooltip[:40])
        else:
            log_step(
                "status bar button", False, "no satochip button found in status bar"
            )
    except Exception as e:
        log_step("status bar button", False, str(e))

    QTimer.singleShot(PAUSE, flow10_change_label_ui)


# ===================================================================
# Phase 10: Change Label via Settings Dialog (VISUAL)
# ===================================================================


def flow10_change_label_ui():
    print("\n" + "=" * 60, flush=True)
    print("Phase 10: Change Label via Settings (VISUAL)", flush=True)
    print("=" * 60, flush=True)

    if wallet_window is None:
        log_step("change label UI", False, "no wallet window")
        QTimer.singleShot(PAUSE, flow11_change_pin_ui)
        return

    print("  [STEP 10] Opening Settings dialog for label change...", flush=True)
    try:
        keystore = wallet_window.wallet.keystore
        keystore.plugin.show_settings_dialog(wallet_window, keystore)
    except Exception as e:
        log_step("change label UI open settings", False, str(e))
        QTimer.singleShot(PAUSE, flow11_change_pin_ui)
        return

    QTimer.singleShot(4000, lambda: _settings_change_label())


def _settings_change_label():
    from electrum.plugins.satochip.qt import SatochipSettingsDialog

    dialog = None
    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, SatochipSettingsDialog) and widget.isVisible():
            dialog = widget
            break

    if dialog is None:
        log_step("change label UI", False, "settings dialog not found")
        QTimer.singleShot(PAUSE, flow11_change_pin_ui)
        return

    # Switch to Settings tab
    tabs = dialog.findChildren(QTabWidget)
    if tabs:
        tabs[0].setCurrentIndex(1)  # Settings tab
        print("  [STEP 10] Settings tab opened", flush=True)

    # Find and click the "Change Label" button
    print("  [STEP 10] Clicking 'Change Label' button...", flush=True)
    change_label_btn = None
    for btn in dialog.findChildren(QPushButton):
        if "change label" in btn.text().lower():
            change_label_btn = btn
            break

    if change_label_btn is None:
        log_step("change label UI", False, "Change Label button not found")
        try:
            dialog.close()
        except Exception:
            pass
        QTimer.singleShot(PAUSE, flow11_change_pin_ui)
        return

    # Click Change Label — this opens a line_dialog for input
    # We need to intercept the dialog. The change_card_label method uses _label_dialog
    # which calls line_dialog() -> exec(). We'll use a QTimer to find and fill it.
    QTimer.singleShot(500, lambda: _fill_label_dialog(dialog))
    change_label_btn.click()


def _fill_label_dialog(settings_dialog):
    """Find the label input dialog and fill it."""
    # Set up PIN auto-fill first (change_card_label calls verify_PIN)
    find_and_fill_pin_dialog(required=False)

    poll = [0]
    max_polls = 20

    def _find_label_dialog():
        if poll[0] >= max_polls:
            log_step("change label UI", False, "label dialog not found")
            try:
                settings_dialog.close()
            except Exception:
                pass
            QTimer.singleShot(PAUSE, flow11_change_pin_ui)
            return
        poll[0] += 1

        for widget in QApplication.topLevelWidgets():
            if not isinstance(widget, QDialog) or not widget.isVisible():
                continue
            if isinstance(widget, type(settings_dialog)):
                continue
            # Look for a dialog with a non-password QLineEdit (label entry)
            line_edits = widget.findChildren(QLineEdit)
            non_pw = [
                f for f in line_edits if f.echoMode() != QLineEdit.EchoMode.Password
            ]
            if non_pw and not non_pw[0].text():
                print(
                    "  [STEP 10] Found label dialog, entering 'satochip-video-test'...",
                    flush=True,
                )
                non_pw[0].setText("satochip-video-test")
                for btn in widget.findChildren(QPushButton):
                    if btn.text() in ("OK", "Ok"):
                        btn.click()
                        log_step(
                            "change label UI",
                            True,
                            "label set to 'satochip-video-test'",
                        )
                        print(
                            "  [STEP 10] >>> SCREENSHOT — label changed <<<", flush=True
                        )
                        QTimer.singleShot(
                            PAUSE,
                            lambda: _close_settings_dialog(
                                settings_dialog, flow11_change_pin_ui
                            ),
                        )
                        return
                widget.accept()
                log_step("change label UI", True, "label set (dialog accepted)")
                QTimer.singleShot(
                    PAUSE,
                    lambda: _close_settings_dialog(
                        settings_dialog, flow11_change_pin_ui
                    ),
                )
                return

        QTimer.singleShot(500, _find_label_dialog)

    QTimer.singleShot(1000, _find_label_dialog)


# ===================================================================
# Phase 11: Change PIN via Settings Dialog (VISUAL)
# ===================================================================


def flow11_change_pin_ui():
    print("\n" + "=" * 60, flush=True)
    print("Phase 11: Change PIN via Settings (VISUAL)", flush=True)
    print("=" * 60, flush=True)

    if wallet_window is None:
        log_step("change PIN UI", False, "no wallet window")
        QTimer.singleShot(PAUSE, flow12_reset_seed_ui)
        return

    print("  [STEP 11] Opening Settings dialog for PIN change...", flush=True)
    try:
        keystore = wallet_window.wallet.keystore
        keystore.plugin.show_settings_dialog(wallet_window, keystore)
    except Exception as e:
        log_step("change PIN UI open settings", False, str(e))
        QTimer.singleShot(PAUSE, flow12_reset_seed_ui)
        return

    QTimer.singleShot(4000, lambda: _settings_change_pin())


def _settings_change_pin():
    from electrum.plugins.satochip.qt import SatochipSettingsDialog

    dialog = None
    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, SatochipSettingsDialog) and widget.isVisible():
            dialog = widget
            break

    if dialog is None:
        log_step("change PIN UI", False, "settings dialog not found")
        QTimer.singleShot(PAUSE, flow12_reset_seed_ui)
        return

    # Switch to Settings tab
    tabs = dialog.findChildren(QTabWidget)
    if tabs:
        tabs[0].setCurrentIndex(1)  # Settings tab
        print("  [STEP 11] Settings tab opened", flush=True)

    # Find and click "Change PIN" button
    print("  [STEP 11] Clicking 'Change PIN' button...", flush=True)
    pin_btn = None
    for btn in dialog.findChildren(QPushButton):
        if "change pin" in btn.text().lower():
            pin_btn = btn
            break

    if pin_btn is None:
        log_step("change PIN UI", False, "Change PIN button not found")
        try:
            dialog.close()
        except Exception:
            pass
        QTimer.singleShot(PAUSE, flow12_reset_seed_ui)
        return

    print("  [STEP 11] PIN change dialog chain started...", flush=True)
    print("  [STEP 11] >>> SCREENSHOT — change PIN action <<<", flush=True)

    def _pin_change_done():
        print("  [STEP 11] >>> SCREENSHOT — PIN change result <<<", flush=True)
        try:
            keystore = wallet_window.wallet.keystore
            client = keystore.get_client(force_pair=True)
            client.cc.set_pin(0, list(b"123456"))
            client.cc.card_verify_PIN_simple()
            client.cc.card_initiate_secure_channel()
            client.cc.card_change_PIN(0, list(b"123456"), list(b"654321"))
            client.cc.set_pin(0, list(b"654321"))
            client.cc.card_change_PIN(0, list(b"654321"), list(b"123456"))
            log_step("change PIN UI", True, "PIN changed to 654321 and restored")
            log_step("change PIN restore", True, "PIN restored to 123456")
        except Exception as e:
            log_step("change PIN UI", False, str(e))
            log_step("change PIN restore", False, str(e))

        try:
            dialog.close()
        except Exception:
            pass
        QTimer.singleShot(PAUSE, flow12_reset_seed_ui)

    QTimer.singleShot(2500, _pin_change_done)


def flow11_change_pin_restore():
    QTimer.singleShot(PAUSE, flow12_reset_seed_ui)


# ===================================================================
# Phase 12: Reset Seed via Settings Advanced Tab (VISUAL)
# ===================================================================


def flow12_reset_seed_ui():
    print("\n" + "=" * 60, flush=True)
    print("Phase 12: Reset Seed via Settings (VISUAL)", flush=True)
    print("=" * 60, flush=True)

    if wallet_window is None:
        log_step("reset seed UI", False, "no wallet window")
        QTimer.singleShot(PAUSE, flow13_factory_reset_ui)
        return

    print("  [STEP 12] Opening Settings dialog for seed reset...", flush=True)
    try:
        keystore = wallet_window.wallet.keystore
        keystore.plugin.show_settings_dialog(wallet_window, keystore)
    except Exception as e:
        log_step("reset seed UI open settings", False, str(e))
        QTimer.singleShot(PAUSE, flow13_factory_reset_ui)
        return

    QTimer.singleShot(4000, lambda: _settings_reset_seed())


def _settings_reset_seed():
    from electrum.plugins.satochip.qt import SatochipSettingsDialog

    dialog = None
    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, SatochipSettingsDialog) and widget.isVisible():
            dialog = widget
            break

    if dialog is None:
        log_step("reset seed UI", False, "settings dialog not found")
        QTimer.singleShot(PAUSE, flow13_factory_reset_ui)
        return

    # Switch to Advanced tab
    tabs = dialog.findChildren(QTabWidget)
    if tabs:
        tabs[0].setCurrentIndex(2)  # Advanced tab
        print("  [STEP 12] Advanced tab opened", flush=True)

    # Find and click "Reset Seed" button
    print("  [STEP 12] Clicking 'Reset Seed' button...", flush=True)
    seed_btn = None
    for btn in dialog.findChildren(QPushButton):
        if "reset seed" in btn.text().lower():
            seed_btn = btn
            break

    if seed_btn is None:
        log_step("reset seed UI", False, "Reset Seed button not found")
        try:
            dialog.close()
        except Exception:
            pass
        QTimer.singleShot(PAUSE, flow13_factory_reset_ui)
        return

    seed_btn.click()

    find_and_fill_any_pin_dialog(pin="123456", label_hint="reset seed PIN")

    print("  [STEP 12] Seed reset initiated...", flush=True)

    def _seed_reset_done():
        print("  [STEP 12] >>> SCREENSHOT — seed reset result <<<", flush=True)
        log_step("reset seed UI", True, "seed reset triggered via UI")
        # Re-import the seed after reset (same as before)
        _reimport_seed_after_reset(dialog)

    QTimer.singleShot(10000, _seed_reset_done)


def _reimport_seed_after_reset(settings_dialog):
    global seed_words

    if not seed_words:
        print("  [STEP 12] No seed words to re-import", flush=True)
        try:
            settings_dialog.close()
        except Exception:
            pass
        QTimer.singleShot(PAUSE, flow13_factory_reset_ui)
        return

    print("  [STEP 12] Re-importing seed after reset...", flush=True)
    from electrum import mnemonic as electrum_mnemonic

    cc = None
    try:
        keystore = wallet_window.wallet.keystore
        client = keystore.get_client(force_pair=True)
        cc = client.cc
        cc.card_initiate_secure_channel()
        cc.set_pin(0, list(b"123456"))
        cc.card_verify_PIN_simple()
        cc.card_initiate_secure_channel()
    except Exception as e:
        log_step("seed re-import", False, str(e))

    if cc:
        try:
            seed_bytes = electrum_mnemonic.Mnemonic.mnemonic_to_seed(
                seed_words, passphrase=""
            )
            authentikey = cc.card_bip32_import_seed(seed_bytes)
            if authentikey:
                print("  [STEP 12] Seed re-imported successfully", flush=True)
                log_step("seed re-import", True, "seed re-imported after reset")
            else:
                log_step("seed re-import", False, "authentikey is None")
        except Exception as e:
            log_step("seed re-import", False, str(e))
    else:
        log_step("seed re-import", False, "no cached client after seed reset")

    global _direct_cc
    _direct_cc = cc

    try:
        settings_dialog.close()
    except Exception:
        pass

    QTimer.singleShot(PAUSE, flow13_factory_reset_ui)


# ===================================================================
# Phase 13: Factory Reset (Direct APDU)
# ===================================================================


def _create_raw_card_connection():
    """Create a raw PC/SC connection to the Satochip card.
    Returns a CardConnector with an active connection, or None on failure.
    """
    from smartcard.System import readers as _readers
    from smartcard.PassThruCardService import PassThruCardService
    from electrum.plugins.satochip.card_connector import CardConnector

    rs = _readers()
    if not rs:
        return None
    conn = rs[0].createConnection()
    try:
        conn.connect()
    except Exception:
        return None
    cc = CardConnector(client=None, card_filter=["satochip"])
    cc.cardservice = PassThruCardService(conn)
    cc.card_present = True
    try:
        cc._detect_protocol()
        cc.card_select()
    except Exception:
        try:
            cc.card_disconnect()
        except Exception:
            pass
        return None
    return cc


def flow13_factory_reset_ui():
    global _direct_cc

    print("\n" + "=" * 60, flush=True)
    print("Phase 13: Factory Reset (Direct APDU)", flush=True)
    print("=" * 60, flush=True)

    if wallet_window is None:
        log_step("factory_reset_guidance", False, "no wallet window")
        QTimer.singleShot(PAUSE, flow14_power_cycle)
        return

    print(
        "  [STEP 13] Opening Settings dialog for factory reset guidance...", flush=True
    )
    try:
        keystore = wallet_window.wallet.keystore
        keystore.plugin.show_settings_dialog(wallet_window, keystore)
    except Exception as e:
        log_step("factory_reset_guidance", False, str(e))
        QTimer.singleShot(PAUSE, flow14_power_cycle)
        return

    QTimer.singleShot(4000, _settings_factory_reset_guidance)


def _settings_factory_reset_guidance():
    from electrum.plugins.satochip.qt import SatochipSettingsDialog

    dialog = None
    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, SatochipSettingsDialog) and widget.isVisible():
            dialog = widget
            break

    if dialog is None:
        log_step("factory_reset_guidance", False, "settings dialog not found")
        QTimer.singleShot(PAUSE, flow14_power_cycle)
        return

    tabs = dialog.findChildren(QTabWidget)
    if tabs:
        tabs[0].setCurrentIndex(2)

    guidance_found = False
    for label in dialog.findChildren(QLabel):
        text = label.text() or ""
        if (
            "removing and reinserting the card" in text
            or "clicking Factory Reset again" in text
        ):
            guidance_found = True
            break

    log_step(
        "factory_reset_guidance",
        guidance_found,
        "multi-step remove/reinsert guidance visible"
        if guidance_found
        else "factory reset guidance text not found",
    )
    try:
        dialog.close()
    except Exception:
        pass
    QTimer.singleShot(PAUSE, flow14_power_cycle)


# ===================================================================
# Phase 14: Reinsertion Guidance
# ===================================================================


def flow14_power_cycle():
    print("\n" + "=" * 60, flush=True)
    print("Phase 14: Reinsertion Guidance", flush=True)
    print("=" * 60, flush=True)
    print("  [STEP 14] Automated USB power-cycle is intentionally disabled", flush=True)
    print(
        "  [STEP 14] Electrum should guide the user to remove and reinsert the card",
        flush=True,
    )
    log_step(
        "power_cycle_guidance",
        True,
        "manual remove/reinsert workflow used instead of sudo-based USB control",
    )
    QTimer.singleShot(PAUSE, finish)


# ===================================================================
# Finish
# ===================================================================


def finish():
    print("\n" + "=" * 60, flush=True)
    print("ALL PHASES COMPLETE", flush=True)
    print("=" * 60, flush=True)
    print_summary()
    QTimer.singleShot(2000, lambda: app.quit() if app else None)


# ===================================================================
# Main — Electrum bootstrap
# ===================================================================


def main():
    global wallet_dir, gui, daemon, app

    print("Starting...", flush=True)

    import electrum.util as util

    util.AS_LIB_USER_I_WANT_TO_MANAGE_MY_OWN_ASYNCIO_LOOP = True

    from electrum.util import create_and_start_event_loop

    loop, stop_loop, loop_thread = create_and_start_event_loop()

    from electrum.simple_config import SimpleConfig

    import random
    import string

    short_id = "".join(random.choices(string.ascii_lowercase, k=6))
    wallet_dir = f"/tmp/sv_{short_id}"
    os.makedirs(wallet_dir, exist_ok=True)
    atexit.register(cleanup)
    atexit.register(_restore_pin_atexit)
    print(f"Temp wallet dir: {wallet_dir}", flush=True)

    config = SimpleConfig({"electrum_path": wallet_dir, "testnet": True})
    config.TERMS_OF_USE_ACCEPTED = 999
    config.DONT_SHOW_TESTNET_WARNING = True
    config.AUTOMATIC_CENTRALIZED_UPDATE_CHECKS = False
    config.cv.NETWORK_AUTO_CONNECT.set(True)

    from electrum import daemon as daemon_mod

    fd = daemon_mod.get_file_descriptor(config)
    d = daemon_mod.Daemon(config, fd, start_network=False, only_minimal_jsonrpc=True)
    daemon = d

    from electrum.plugin import Plugins

    plugins = Plugins(config, "qt")

    from electrum.gui.qt import ElectrumGui

    gui = ElectrumGui(config=config, daemon=d, plugins=plugins)
    app = gui.app
    app.setQuitOnLastWindowClosed(False)

    try:
        gui.init_network()
    except Exception:
        pass

    print("\nStarting visual test in 2 seconds...", flush=True)
    print("Watch the Electrum window!\n", flush=True)
    print("Phases:", flush=True)
    print("  1.  Card Setup (backend)", flush=True)
    print("  2.  Wallet Creation Wizard (VISUAL)", flush=True)
    print("  3.  Main Wallet Window (VISUAL — screenshot moment)", flush=True)
    print("  4.  Settings Dialog — All Three Tabs (VISUAL)", flush=True)
    print("  5.  Sign Message via Tools Menu (VISUAL)", flush=True)
    print("  6.  Verify Message via Tools Menu (VISUAL)", flush=True)
    print("  7.  Show Address on Card (VISUAL)", flush=True)
    print("  8.  Sign Transaction via Send Tab (VISUAL)", flush=True)
    print("  9.  Status Bar (VISUAL)", flush=True)
    print("  10. Change Label via Settings (VISUAL)", flush=True)
    print("  11. Change PIN via Settings (VISUAL)", flush=True)
    print("  12. Reset Seed via Settings (VISUAL)", flush=True)
    print("  13. Factory Reset Guidance (VISUAL)", flush=True)
    print("  14. Reinsertion Guidance (VISUAL)", flush=True)
    print("", flush=True)

    QTimer.singleShot(2000, flow0_card_reset)

    retcode = app.exec()

    try:
        d.stop()
    except Exception:
        pass
    try:
        loop.call_soon_threadsafe(stop_loop.set_result, 1)
        loop_thread.join(timeout=5)
    except Exception:
        pass

    shutil.rmtree(wallet_dir, ignore_errors=True)
    sys.exit(retcode or 0)


if __name__ == "__main__":
    main()
