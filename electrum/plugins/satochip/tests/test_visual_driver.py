#!/usr/bin/env python3
"""Visual test driver for Satochip plugin.

Launches real Electrum GUI and drives through wallet creation.
Run: python3 electrum/plugins/satochip/tests/test_visual_driver.py

Press Ctrl+C to stop at any time.
"""

import sys
import os
import shutil
import tempfile
import atexit
import subprocess

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
from PyQt6.QtWidgets import QApplication, QLineEdit, QPushButton, QDialog

wallet_dir = None
wizard = None
gui = None
daemon = None
app = None
wallet_window = None
results = []
STEP_DELAY = 2500
PIN = "123456"
seed_words = None
_pin_timer_active = False
_pin_restore_client = None


def _restore_pin_atexit():
    global _pin_restore_client
    if _pin_restore_client:
        try:
            _pin_restore_client.cc.card_change_PIN(0, list(b"654321"), list(b"123456"))
        except Exception:
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


def find_and_fill_pin_dialog(pin=PIN, timeout_ms=15000):
    """Poll for the PIN dialog that Satochip shows via QtHandlerBase.get_passphrase().

    The dialog is a WindowModalDialog with PasswordLineEdit + OkButton,
    created from a background thread. Polling is needed because we cannot
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


def click_next():
    if wizard and wizard.next_button.isEnabled():
        wizard.next_button.click()
        return True
    return False


# -- Flow 0: Card Reset + New Seed --


def flow0_card_reset():
    print("\n--- Flow 0: Card Reset + New Seed ---", flush=True)
    global seed_words
    import time
    from smartcard.System import readers
    from smartcard.PassThruCardService import PassThruCardService
    from electrum.plugins.satochip.card_connector import CardConnector
    from electrum import mnemonic as electrum_mnemonic

    rs = readers()
    if not rs:
        log_step("card reset", False, "no reader found")
        QTimer.singleShot(STEP_DELAY, flow1_wallet_creation)
        return

    reader = rs[0]
    conn = reader.createConnection()
    try:
        conn.connect()
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
    try:
        cc.card_initiate_secure_channel()
        cc.set_pin(0, list(b"123456"))
        cc.card_verify_PIN_simple()
        cc.card_initiate_secure_channel()
        print("    Card authenticated OK", flush=True)
    except Exception as e:
        print(f"    Card auth failed: {e}", flush=True)
        log_step("card reset + seed", False, f"auth failed: {e}")
        try:
            cc.card_disconnect()
        except Exception:
            pass
        QTimer.singleShot(STEP_DELAY, flow1_wallet_creation)
        return

    # Step 2: Reset seed (card calls LogOutAll internally)
    try:
        user_pin = list(b"123456")
        response, sw1, sw2 = cc.card_reset_seed(user_pin, [])
        if sw1 != 0x90:
            raise Exception(f"reset_seed failed: SW={sw1:02X}{sw2:02X}")
        print("    Card seed reset OK", flush=True)
        time.sleep(0.3)
    except Exception as e:
        print(f"    Card seed reset failed: {e}", flush=True)
        log_step("card reset + seed", False, f"reset failed: {e}")
        try:
            cc.card_disconnect()
        except Exception:
            pass
        QTimer.singleShot(STEP_DELAY, flow1_wallet_creation)
        return

    # Step 3: Re-authenticate (card logged out after reset)
    try:
        cc.card_initiate_secure_channel()
        cc.set_pin(0, list(b"123456"))
        cc.card_verify_PIN_simple()
        cc.card_initiate_secure_channel()
        print("    Re-authenticated OK", flush=True)
    except Exception as e:
        print(f"    Re-auth failed: {e}", flush=True)
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

    try:
        authentikey = cc.card_bip32_import_seed(seed_bytes)
        if authentikey:
            print(f"    Seed imported: {seed_words}", flush=True)
            log_step("card reset + seed", True, f"new seed: {seed_words}")
        else:
            log_step("card reset + seed", False, "authentikey is None")
    except Exception as e:
        print(f"    Seed import failed: {e}", flush=True)
        log_step("card reset + seed", False, f"seed import: {e}")

    try:
        cc.card_disconnect()
    except Exception:
        pass

    QTimer.singleShot(STEP_DELAY, flow1_wallet_creation)


# -- Flow 1: Wallet Creation --


def flow1_wallet_creation():
    print("\n--- Flow 1: Wallet Creation ---", flush=True)
    print("  [STEP] Creating wallet wizard...", flush=True)
    from electrum.gui.qt.wizard.wallet import QENewWalletWizard
    from electrum.util import get_new_wallet_name

    global wizard

    wallet_path = os.path.join(wallet_dir, get_new_wallet_name(wallet_dir))
    wizard = QENewWalletWizard(gui.config, gui.app, gui.plugins, daemon, wallet_path)
    # QEAbstractWizard.__init__ calls show() then QMetaObject.invokeMethod(strt) which
    # calls exec()-style loading. Close and re-show to avoid the modal event loop.
    wizard.close()
    wizard.show()
    wizard.raise_()

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
    find_and_fill_pin_dialog()
    QTimer.singleShot(STEP_DELAY, step6_xpub)


def step6_xpub():
    page = current_page()
    print(f'  [STEP 6] xpub page: "{page_title()}"', flush=True)
    if page is None:
        QTimer.singleShot(2000, step6_xpub)
        return

    if page.busy:
        print("    Fetching xpub from card... (waiting)", flush=True)
        find_and_fill_pin_dialog()
        QTimer.singleShot(2000, step6_xpub)
        return

    if page.valid:
        log_step("xpub retrieval", True, "xpub fetched successfully")
        # WCHWXPub auto-advances via wizard.requestNext.emit() but timing varies
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
        find_and_fill_pin_dialog()
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
        find_and_fill_pin_dialog()
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
    print("  [VERIFY] Creating wallet from wizard data...", flush=True)

    from electrum.gui.qt.main_window import ElectrumWindow

    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, ElectrumWindow) and widget.isVisible():
            wallet_window = widget
            log_step("wallet created", True, f"wallet: {widget.wallet.basename()}")
            QTimer.singleShot(STEP_DELAY, flow2_settings_dialog)
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

    QTimer.singleShot(STEP_DELAY, flow2_settings_dialog)


# -- Flow 2: Settings Dialog --


def flow2_settings_dialog():
    print("\n--- Flow 2: Settings Dialog ---", flush=True)
    if wallet_window is None:
        log_step("settings dialog", False, "no wallet window")
        QTimer.singleShot(STEP_DELAY, flow3_sign_message)
        return

    from electrum.plugin import run_hook

    try:
        keystore = wallet_window.wallet.keystore
        print("  [STEP] Opening Satochip settings...", flush=True)
        run_hook("show_settings_dialog", wallet_window, keystore)
        log_step("settings dialog opened", True)
    except Exception as e:
        log_step("settings dialog opened", False, str(e))

    QTimer.singleShot(5000, flow2_close_settings)


def flow2_close_settings():
    from electrum.plugins.satochip.qt import SatochipSettingsDialog

    dialog = None
    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, SatochipSettingsDialog) and widget.isVisible():
            dialog = widget
            break

    if dialog is None:
        log_step("settings dialog content", False, "dialog not found")
        QTimer.singleShot(STEP_DELAY, flow3_sign_message)
        return

    # Poll until info tab QLabels are populated (async via show_values)
    poll_attempts = [0]
    max_polls = 20  # 500ms * 20 = 10s

    def _poll_labels():
        if poll_attempts[0] >= max_polls:
            print("    Label polling timed out, closing anyway", flush=True)
            dialog.close()
            log_step("settings info", False, "polling timed out")
            QTimer.singleShot(STEP_DELAY, flow3_sign_message)
            return
        poll_attempts[0] += 1
        fw_text = dialog.fw_version.text()
        if "<tt>" in fw_text and len(fw_text) > 4:
            fw = dialog.fw_version.text().replace("<tt>", "")
            dev_id = dialog.device_id_label.text().replace("<tt>", "")
            seeded = dialog.is_seeded.text().replace("<tt>", "")
            setup = dialog.setup_done.text().replace("<tt>", "")
            tries = dialog.pin_tries.text().replace("<tt>", "")
            detail = "fw=%s, seeded=%s, pin_tries=%s, device_id=%s" % (
                fw,
                seeded,
                tries,
                dev_id,
            )
            log_step("settings info", True, detail)
            dialog.close()
            QTimer.singleShot(STEP_DELAY, flow3_sign_message)
        else:
            QTimer.singleShot(500, _poll_labels)

    QTimer.singleShot(500, _poll_labels)


# -- Flow 3: Sign Message --


def flow3_sign_message():
    print("\n--- Flow 3: Sign Message ---", flush=True)
    if wallet_window is None:
        log_step("sign message", False, "no wallet window")
        QTimer.singleShot(STEP_DELAY, flow4_show_address)
        return

    try:
        from electrum import bitcoin
        from electrum import constants as electrum_constants

        wallet = wallet_window.wallet
        keystore = wallet.keystore
        addresses = wallet.get_receiving_addresses()
        if not addresses:
            log_step("sign message", False, "no receiving addresses")
            QTimer.singleShot(STEP_DELAY, flow4_show_address)
            return

        address = addresses[0]
        sequence = wallet.get_address_index(address)
        message = b"Satochip visual test"

        find_and_fill_pin_dialog()
        sig_bytes = keystore.sign_message(sequence, "Satochip visual test", None)

        if not sig_bytes:
            log_step("sign message", False, "sign_message returned empty")
            QTimer.singleShot(STEP_DELAY, flow4_show_address)
            return

        # Diagnostics
        print(
            "    [DIAG] sig len=%d hex=%s" % (len(sig_bytes), sig_bytes.hex()),
            flush=True,
        )
        print("    [DIAG] address=%s msg=%s" % (address, message), flush=True)
        try:
            from electrum_ecc import ECPubkey
            from electrum.crypto import sha256d
            from electrum.bitcoin import usermessage_magic, pubkey_to_address

            h = sha256d(usermessage_magic(message))
            pub, comp, tt = ECPubkey.from_ecdsa_sig65(sig_bytes, h)
            pk = pub.get_public_key_hex(comp)
            print(
                "    [DIAG] rec_pk=%s comp=%s tt=%s" % (pk[:30], comp, tt), flush=True
            )
            for t in ["p2wpkh", "p2wpkh-p2sh", "p2pkh"]:
                a = pubkey_to_address(t, pk, net=electrum_constants.BitcoinMainnet)
                print(
                    "    [DIAG] %s mainnet=%s match=%s" % (t, a, a == address),
                    flush=True,
                )
            sig64 = bytes(sig_bytes[1:])
            ev = pub.ecdsa_verify(sig64, h, enforce_low_s=False)
            print("    [DIAG] ecdsa_verify=%s" % ev, flush=True)
        except Exception as de:
            print("    [DIAG] recovery failed: %s" % de, flush=True)
            import traceback

            traceback.print_exc()

        # Try mainnet first (card uses m/84h/0h/0h = mainnet), then testnet
        verified_mainnet = bitcoin.verify_usermessage_with_address(
            address, sig_bytes, message, net=electrum_constants.BitcoinMainnet
        )
        verified_testnet = False
        if not verified_mainnet:
            verified_testnet = bitcoin.verify_usermessage_with_address(
                address, sig_bytes, message, net=electrum_constants.BitcoinTestnet
            )
        verified = verified_mainnet or verified_testnet
        net_label = (
            "mainnet" if verified_mainnet else "testnet" if verified_testnet else "none"
        )
        if verified:
            log_step(
                "sign message",
                True,
                "signature verified (%s) for address %s" % (net_label, address[:12]),
            )
        else:
            log_step(
                "sign message",
                False,
                "verification failed (%s) for address %s" % (net_label, address[:12]),
            )
    except Exception as e:
        log_step("sign message", False, str(e))

    QTimer.singleShot(STEP_DELAY, flow4_show_address)


# -- Flow 4: Show Address --


def flow4_show_address():
    print("\n--- Flow 4: Show Address ---", flush=True)
    if wallet_window is None:
        log_step("show address", False, "no wallet window")
        QTimer.singleShot(STEP_DELAY, flow8_sign_transaction)
        return

    try:
        from electrum import bitcoin
        from electrum.plugins.satochip.satochip import _bip32path2bytes

        wallet = wallet_window.wallet
        keystore = wallet.keystore
        addresses = wallet.get_receiving_addresses()
        if not addresses:
            log_step("show address", False, "no receiving addresses")
            QTimer.singleShot(STEP_DELAY, flow8_sign_transaction)
            return

        address = addresses[0]
        sequence = wallet.get_address_index(address)
        derivation_prefix = keystore.get_derivation_prefix()
        address_path = derivation_prefix + "/%d/%d" % sequence

        (depth, bytepath) = _bip32path2bytes(address_path)
        client = keystore.get_client()
        (pubkey, chaincode) = client.cc.card_bip32_get_extendedkey(bytepath)
        pubkey_hex = pubkey.get_public_key_bytes(compressed=True).hex()
        txin_type = wallet.get_txin_type(address)
        card_address = bitcoin.pubkey_to_address(txin_type, pubkey_hex)

        if card_address == address:
            log_step("show address", True, "card address matches wallet")
        else:
            log_step(
                "show address",
                False,
                "card=%s wallet=%s" % (card_address[:12], address[:12]),
            )
    except Exception as e:
        log_step("show address", False, str(e))

    QTimer.singleShot(STEP_DELAY, flow8_sign_transaction)


# -- Flow 8: Sign Transaction --


def flow8_sign_transaction():
    print("\n--- Flow 8: Sign Transaction ---", flush=True)
    if wallet_window is None:
        log_step("sign transaction", False, "no wallet window")
        QTimer.singleShot(STEP_DELAY, flow9_status_bar)
        return

    try:
        import struct
        import hashlib
        from electrum.plugins.satochip.satochip import _bip32path2bytes
        from electrum.crypto import hash_160

        wallet = wallet_window.wallet
        keystore = wallet.keystore
        client = keystore.get_client()
        addresses = wallet.get_receiving_addresses()
        if not addresses:
            log_step("sign transaction", False, "no receiving addresses")
            QTimer.singleShot(STEP_DELAY, flow9_status_bar)
            return

        address = addresses[0]
        sequence = wallet.get_address_index(address)
        derivation_prefix = keystore.get_derivation_prefix()

        # Build BIP32 bytepath for the input key
        bytepath = _bip32path2bytes(derivation_prefix + "/%d/%d" % sequence)[1]
        (pubkey, _chaincode) = client.cc.card_bip32_get_extendedkey(bytepath)

        # Construct BIP-143 segwit preimage (what card_parse_transaction expects)
        pubkey_bytes = pubkey.get_public_key_bytes(compressed=True)
        pkh = hash_160(pubkey_bytes)
        # p2wpkh scriptcode: OP_DUP OP_HASH160 OP_PUSH20 <hash160> OP_EQUALVERIFY OP_CHECKSIG
        scriptcode = bytes([0x76, 0xA9, 0x14]) + pkh + bytes([0x88, 0xAC])

        hash_prevouts = hashlib.sha256(hashlib.sha256(b"\x00" * 36).digest()).digest()
        hash_sequence = hashlib.sha256(
            hashlib.sha256(struct.pack("<I", 0xFFFFFFFF)).digest()
        ).digest()
        output_script = bytes([0x00, 0x14]) + pkh
        output_entry = (
            struct.pack("<Q", 100000000) + bytes([len(output_script)]) + output_script
        )
        hash_outputs = hashlib.sha256(hashlib.sha256(output_entry).digest()).digest()

        raw_tx = b""
        raw_tx += struct.pack("<I", 1)  # version
        raw_tx += hash_prevouts  # hashPrevouts (32)
        raw_tx += hash_sequence  # hashSequence (32)
        raw_tx += b"\x00" * 32  # prevout txid (fake)
        raw_tx += struct.pack("<I", 0)  # prevout index
        raw_tx += bytes([len(scriptcode)])  # scriptcode varint
        raw_tx += scriptcode  # scriptcode
        raw_tx += struct.pack("<Q", 100000000)  # amount (1 BTC)
        raw_tx += struct.pack("<I", 0xFFFFFFFF)  # nSequence
        raw_tx += hash_outputs  # hashOutputs (32)
        raw_tx += struct.pack("<I", 0)  # nLocktime
        raw_tx += struct.pack("<I", 1)  # nHashType: SIGHASH_ALL

        # Parse tx on card to get tx_hash
        (response, sw1, sw2, tx_hash, needs_2fa) = client.cc.card_parse_transaction(
            raw_tx, is_segwit=True
        )

        # Verify tx_hash matches local double-SHA256
        local_hash = hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()
        card_hash = bytes(tx_hash)
        hash_match = local_hash == card_hash

        if not hash_match:
            log_step(
                "sign transaction hash",
                False,
                "local=%s card=%s" % (local_hash.hex()[:16], card_hash.hex()[:16]),
            )
            QTimer.singleShot(STEP_DELAY, flow9_status_bar)
            return

        # Sign with card (PIN already verified from earlier flows)
        (tx_sig_der, sw1, sw2) = client.cc.card_sign_transaction(0xFF, tx_hash)

        if sw1 != 0x90 or sw2 != 0x00:
            log_step(
                "sign transaction",
                False,
                "card_sign_transaction SW=%02X%02X" % (sw1, sw2),
            )
            QTimer.singleShot(STEP_DELAY, flow9_status_bar)
            return

        # Verify DER signature validity
        from electrum_ecc import get_r_and_s_from_ecdsa_der_sig, CURVE_ORDER

        der_bytes = bytes(tx_sig_der)
        r, s = get_r_and_s_from_ecdsa_der_sig(der_bytes)
        sig_valid = 0 < s < CURVE_ORDER and 0 < r < CURVE_ORDER

        if sig_valid and hash_match:
            log_step(
                "sign transaction",
                True,
                "DER sig valid, hash match, len=%d" % len(der_bytes),
            )
        else:
            log_step(
                "sign transaction",
                False,
                "sig_valid=%s hash_match=%s" % (sig_valid, hash_match),
            )
    except Exception as e:
        import traceback

        traceback.print_exc()
        log_step("sign transaction", False, str(e))

    QTimer.singleShot(STEP_DELAY, flow9_status_bar)


# -- Flow 9: Status Bar Button --


def flow9_status_bar():
    print("\n--- Flow 9: Status Bar Button ---", flush=True)
    if wallet_window is None:
        log_step("status bar button", False, "no wallet window")
        QTimer.singleShot(STEP_DELAY, flow5_change_label)
        return

    try:
        from PyQt6.QtWidgets import QToolButton

        status_bar = wallet_window.statusBar()
        if status_bar is None:
            log_step("status bar button", False, "no status bar")
            QTimer.singleShot(STEP_DELAY, flow5_change_label)
            return

        # Look for satochip button in status bar children
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
            log_step("status bar button", True, "tooltip=%s" % tooltip[:40])
        else:
            log_step(
                "status bar button", False, "no satochip button found in status bar"
            )
    except Exception as e:
        log_step("status bar button", False, str(e))

    QTimer.singleShot(STEP_DELAY, flow5_change_label)


def finish():
    print_summary()
    cleanup()
    QTimer.singleShot(2000, lambda: app.quit() if app else None)


# -- Flow 5: Change Card Label --


def flow5_change_label():
    print("\n--- Flow 5: Change Card Label ---", flush=True)
    if wallet_window is None:
        log_step("change label", False, "no wallet window")
        QTimer.singleShot(STEP_DELAY, flow6_change_pin)
        return

    try:
        keystore = wallet_window.wallet.keystore
        client = keystore.get_client()
        (_, _, _, old_label) = client.cc.card_get_label()

        try:
            client.cc.card_set_label("visual-test")
            (_, _, _, new_label) = client.cc.card_get_label()
            if new_label == "visual-test":
                log_step("change label", True, "round-trip OK")
            else:
                log_step(
                    "change label", False, "expected visual-test got %s" % new_label
                )
        finally:
            restore = old_label if old_label not in ("(none)", "(unknown)") else ""
            client.cc.card_set_label(restore)
    except Exception as e:
        log_step("change label", False, str(e))

    QTimer.singleShot(STEP_DELAY, flow6_change_pin)


# -- Flow 6: Change PIN --


def flow6_change_pin():
    print("\n--- Flow 6: Change PIN ---", flush=True)
    global _pin_restore_client

    if wallet_window is None:
        log_step("change PIN", False, "no wallet window")
        QTimer.singleShot(STEP_DELAY, flow7_wizard_views)
        return

    try:
        keystore = wallet_window.wallet.keystore
        client = keystore.get_client()
        _pin_restore_client = client

        client.cc.card_change_PIN(0, list(b"123456"), list(b"654321"))
        verified = client.verify_PIN()
        if verified:
            log_step("change PIN", True, "round-trip OK")
        else:
            log_step("change PIN", False, "verify_PIN returned False after change")

        try:
            client.cc.card_change_PIN(0, list(b"654321"), list(b"123456"))
        except Exception as e:
            log_step("change PIN restore", False, str(e))
    except Exception as e:
        log_step("change PIN", False, str(e))
    finally:
        _pin_restore_client = None

    QTimer.singleShot(STEP_DELAY, flow7_wizard_views)


# -- Flow 7: Wizard Edge Case Views --


def flow7_wizard_views():
    print("\n--- Flow 7: Wizard Edge Case Views ---", flush=True)

    try:
        from electrum.plugins.satochip.qt import WCSatochipBlocked, WCSatochipWrongCard

        log_step(
            "blocked card view",
            WCSatochipBlocked is not None,
            "WCSatochipBlocked importable",
        )
        log_step(
            "wrong card view",
            WCSatochipWrongCard is not None,
            "WCSatochipWrongCard importable",
        )
    except Exception as e:
        log_step("wizard views", False, str(e))

    QTimer.singleShot(STEP_DELAY, finish)


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
    QTimer.singleShot(2000, flow1_wallet_creation)

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
