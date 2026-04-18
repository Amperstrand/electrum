import hashlib
import secrets
import threading
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QVBoxLayout,
    QLabel,
    QGridLayout,
    QPushButton,
    QHBoxLayout,
    QGroupBox,
    QLineEdit,
    QSlider,
    QWidget,
    QMessageBox,
    QRadioButton,
    QTabWidget,
)

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.plugin import hook
from electrum.util import ChoiceItem

from electrum.hw_wallet.qt import QtHandlerBase, QtPluginBase
from electrum.hw_wallet.plugin import only_hook_if_libraries_available

from electrum.gui.qt.util import (
    WindowModalDialog,
    WWLabel,
    Buttons,
    CancelButton,
    OkButton,
    CloseButton,
    PasswordLineEdit,
    ColorScheme,
    ChoiceWidget,
    EnterButton,
    line_dialog,
    icon_path,
)
from electrum.gui.qt.wizard.wallet import (
    WCScriptAndDerivation,
    WCHWUnlock,
    WCHWXPub,
    WalletWizardComponent,
    WCHaveSeed,
    WCEnterExt,
)

from .satochip import SatochipPlugin

if TYPE_CHECKING:
    from electrum.gui.qt.wizard.wallet import QENewWalletWizard

_logger = get_logger(__name__)

RECOMMEND_PIN = _(
    "PIN protection is strongly recommended.  A PIN is your only protection "
    "against someone stealing your bitcoins if they obtain physical "
    "access to your Satochip."
)

MSG_SEED_IMPORT = [
    _("Your Satochip is currently unseeded. "),
    _("To use it, you need to import a BIP39 Seed. "),
    _("To do so, select BIP39 in the options in the next screen. "),
    _("Note that Electrum seeds are not supported by hardware wallets. "),
    " ",
    _("Optionally, you can also enable a passphrase in the options. "),
    _(
        "A passphrase is an optional feature that allows you to extend your seed with additional entropy. "
    ),
    _("A passphrase is not a PIN. "),
    _(
        "If set, you will need your passphrase along with your BIP39 seed to restore your wallet from a backup. "
    ),
]


# ---------------------------------------------------------------------------
# QtHandler
# ---------------------------------------------------------------------------


class QtHandler(QtHandlerBase):
    """Qt handler for Satochip device interactions (PIN dialog, messages)."""

    def __init__(self, win, device):
        super().__init__(win, device)

    def message_dialog(self, msg, on_cancel=None):
        """Override the base handler message dialog to include an explicit OK
        button so users can dismiss informational messages with Enter or by
        clicking OK."""
        self.clear_dialog()

        parent = self.top_level_window()
        self.dialog = dialog = WindowModalDialog(parent, _("Satochip"))

        label = QLabel(msg)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        vbox = QVBoxLayout(dialog)
        vbox.addWidget(label)

        buttons = []
        if on_cancel is not None:
            dialog.rejected.connect(on_cancel)
            buttons.append(CancelButton(dialog))
        buttons.append(OkButton(dialog))
        vbox.addLayout(Buttons(*buttons))

        dialog.show()


# ---------------------------------------------------------------------------
# Plugin  (SatochipPlugin + QtPluginBase)
# ---------------------------------------------------------------------------


class Plugin(SatochipPlugin, QtPluginBase):
    icon_unpaired = "satochip_unpaired.png"
    icon_paired = "satochip.png"

    def create_handler(self, window):
        return QtHandler(window, self.device)

    @only_hook_if_libraries_available
    @hook
    def show_settings_dialog(self, window, keystore):
        def connect():
            device_id = self.choose_device(window, keystore)
            return device_id

        def show_dialog(device_id):
            if device_id:
                SatochipSettingsDialog(window, self, keystore, device_id).exec()

        keystore.thread.add(connect, on_success=show_dialog)

    @hook
    def init_wallet_wizard(self, wizard: "QENewWalletWizard"):
        self.extend_wizard(wizard)

    def extend_wizard(self, wizard: "QENewWalletWizard"):
        super().extend_wizard(wizard)
        views = {
            "satochip_start": {"gui": WCScriptAndDerivation},
            "satochip_xpub": {"gui": WCHWXPub},
            "satochip_not_setup": {"gui": WCSatochipSetupParams},
            "satochip_do_setup": {"gui": WCSatochipSetup},
            "satochip_not_seeded": {
                "gui": WCSeedMethodChoice,
                "next": lambda d: (
                    "satochip_have_seed"
                    if d.get("satochip_seed_method") == "import"
                    else "satochip_generate_seed"
                ),
            },
            "satochip_generate_seed": {
                "gui": WCSatochipGenerateSeed,
                "next": lambda d: (
                    "satochip_have_ext"
                    if wizard.wants_ext(d)
                    else "satochip_import_seed"
                ),
            },
            "satochip_have_seed": {
                "gui": WCHaveSeed,
                "next": lambda d: (
                    "satochip_have_ext"
                    if wizard.wants_ext(d)
                    else "satochip_import_seed"
                ),
                "params": {"seed_options": ["ext", "bip39"]},
            },
            "satochip_have_ext": {
                "gui": WCEnterExt,
                "next": "satochip_import_seed",
            },
            "satochip_import_seed": {
                "gui": WCSatochipImportSeed,
                "next": "satochip_success_seed",
            },
            "satochip_success_seed": {
                "gui": WCSeedSuccess,
            },
            "satochip_unlock": {"gui": WCSatochipUnlock},
            "satochip_blocked": {
                "gui": WCSatochipBlocked,
                "next": "choose_hardware_device",
            },
            "satochip_wrong_card": {
                "gui": WCSatochipWrongCard,
                "next": "choose_hardware_device",
            },
            "satochip_recover_setup": {
                "gui": WCSatochipRecoverSetup,
                "next": "satochip_recover_seed",
            },
            "satochip_recover_seed": {
                "gui": WCSatochipRecoverSeed,
                "next": "satochip_unlock",
            },
        }
        wizard.navmap_merge(views)


# ---------------------------------------------------------------------------
# Settings Dialog
# ---------------------------------------------------------------------------


class SatochipSettingsDialog(WindowModalDialog):
    """Tabbed settings dialog for Satochip device.

    Tab 1 - Information: Device status, firmware version, card info
    Tab 2 - Settings: Label edit, PIN change, session timeout
    Tab 3 - Advanced: Factory reset, seed reset
    """

    def __init__(self, window, plugin, keystore, device_id):
        title = _("{} Settings").format(plugin.device)
        super().__init__(window, title)
        self.setMaximumWidth(600)
        self.setMinimumHeight(400)

        devmgr = plugin.device_manager()
        self.config = devmgr.config
        handler = keystore.handler
        self.thread = thread = keystore.thread
        self.window = window
        self.device_id = device_id
        self.devmgr = devmgr

        def connect_and_doit():
            client = devmgr.client_by_id(device_id)
            if not client:
                raise RuntimeError("Device not connected")
            return client

        # ===========================================================
        # TAB 1: Information
        # ===========================================================
        info_tab = QWidget()
        info_layout = QVBoxLayout(info_tab)
        info_glayout = QGridLayout()
        info_glayout.setColumnStretch(2, 1)

        header_label = QLabel(
            '<center><span style="font-size: x-large">Satochip</span>'
            '<br><a href="https://satochip.io">satochip.io</a></center>'
        )
        header_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.LinksAccessibleByMouse
        )
        header_label.setOpenExternalLinks(True)
        info_glayout.addWidget(header_label, 0, 0, 1, 2, Qt.AlignmentFlag.AlignHCenter)

        y = 2
        rows = [
            ("fw_version", _("Firmware Version:")),
            ("device_id_label", _("Device ID:")),
            ("is_seeded", _("Wallet seeded:")),
            ("setup_done", _("Setup completed:")),
            ("pin_tries", _("PIN tries remaining:")),
        ]
        for _row_num, (member_name, label_text) in enumerate(rows):
            widget = QLabel("<tt>")
            widget.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
                | Qt.TextInteractionFlag.TextSelectableByKeyboard
            )
            info_glayout.addWidget(
                QLabel(label_text), y, 0, 1, 1, Qt.AlignmentFlag.AlignRight
            )
            info_glayout.addWidget(widget, y, 1, 1, 1, Qt.AlignmentFlag.AlignLeft)
            setattr(self, member_name, widget)
            y += 1

        info_layout.addLayout(info_glayout)
        info_layout.addStretch(1)

        # ===========================================================
        # TAB 2: Settings
        # ===========================================================
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)

        # -- Session Timeout --
        timeout_group = QGroupBox(_("Session Timeout"))
        timeout_vbox = QVBoxLayout(timeout_group)
        timeout_msg = QLabel(
            _(
                "Automatically lock the device after a period of inactivity. "
                "Once locked, you will need to enter your PIN again to use the device."
            )
        )
        timeout_msg.setWordWrap(True)
        timeout_vbox.addWidget(timeout_msg)

        timeout_hbox = QHBoxLayout()
        self.timeout_label = QLabel(_("5 minutes"))
        self.timeout_label.setMinimumWidth(80)
        timeout_slider = QSlider(Qt.Orientation.Horizontal)
        timeout_slider.setRange(1, 60)
        timeout_slider.setSingleStep(1)
        timeout_slider.setTickInterval(5)
        timeout_slider.setTickPosition(QSlider.TickPosition.TicksBelow)

        current_timeout = self.config.get("satochip_session_timeout", 300) // 60
        timeout_slider.setValue(current_timeout)
        self.timeout_label.setText(_("{:d} minutes").format(current_timeout))

        def timeout_changed(value):
            self.timeout_label.setText(_("{:d} minutes").format(value))

        def timeout_released():
            mins = timeout_slider.value()
            self.config.set_key("satochip_session_timeout", mins * 60, save=True)
            _logger.info(f"Session timeout set to {mins} minutes")

        timeout_slider.valueChanged.connect(timeout_changed)
        timeout_slider.sliderReleased.connect(timeout_released)

        timeout_hbox.addWidget(timeout_slider)
        timeout_hbox.addWidget(self.timeout_label)
        timeout_vbox.addLayout(timeout_hbox)
        settings_layout.addWidget(timeout_group)

        # -- Card Label --
        label_group = QGroupBox(_("Card Label"))
        label_vbox = QVBoxLayout(label_group)

        self.card_label_display = QLabel("<tt>(none)")
        label_vbox.addWidget(self.card_label_display)

        change_label_btn = QPushButton(_("Change Label"))
        change_label_btn.clicked.connect(
            lambda: thread.add(connect_and_doit, on_success=self.change_card_label)
        )
        label_vbox.addWidget(change_label_btn)

        label_msg = QLabel(_("The label is stored on the card and helps identify it."))
        label_msg.setWordWrap(True)
        label_msg.setStyleSheet(ColorScheme.GRAY.as_stylesheet())
        label_vbox.addWidget(label_msg)
        settings_layout.addWidget(label_group)

        # -- PIN Management --
        pin_group = QGroupBox(_("PIN Management"))
        pin_vbox = QVBoxLayout(pin_group)

        pin_btn = QPushButton(_("Change PIN"))
        pin_btn.clicked.connect(
            lambda: thread.add(connect_and_doit, on_success=self.change_pin)
        )
        pin_vbox.addWidget(pin_btn)

        pin_msg = QLabel(RECOMMEND_PIN)
        pin_msg.setWordWrap(True)
        pin_msg.setStyleSheet(ColorScheme.GRAY.as_stylesheet())
        pin_vbox.addWidget(pin_msg)
        settings_layout.addWidget(pin_group)
        settings_layout.addStretch(1)

        # ===========================================================
        # TAB 3: Advanced
        # ===========================================================
        advanced_tab = QWidget()
        advanced_layout = QVBoxLayout(advanced_tab)

        # -- Factory Reset --
        reset_group = QGroupBox(_("Factory Reset"))
        reset_vbox = QVBoxLayout(reset_group)

        factory_reset_btn = QPushButton(_("Factory Reset"))
        factory_reset_btn.clicked.connect(
            lambda: thread.add(connect_and_doit, on_success=self.factory_reset)
        )
        reset_vbox.addWidget(factory_reset_btn)

        reset_warning = QLabel(
            _(
                "WARNING: Factory reset erases ALL data from the card including "
                "the seed and PIN. Make sure you have a backup of your seed before "
                "proceeding!"
            )
        )
        reset_warning.setWordWrap(True)
        reset_warning.setStyleSheet(ColorScheme.RED.as_stylesheet())
        reset_vbox.addWidget(reset_warning)
        advanced_layout.addWidget(reset_group)

        # -- Seed Reset --
        seed_group = QGroupBox(_("Seed Management"))
        seed_vbox = QVBoxLayout(seed_group)

        seed_btn = QPushButton(_("Reset Seed"))
        seed_btn.clicked.connect(
            lambda: thread.add(connect_and_doit, on_success=self.reset_seed)
        )
        seed_btn.clicked.connect(
            lambda: thread.add(connect_and_doit, on_success=self.show_values)
        )
        seed_vbox.addWidget(seed_btn)

        seed_warning = QLabel(
            _(
                "WARNING: Resetting the seed will erase all keys from the card. "
                "Make sure you have a backup of your seed before proceeding!"
            )
        )
        seed_warning.setWordWrap(True)
        seed_warning.setStyleSheet(ColorScheme.RED.as_stylesheet())
        seed_vbox.addWidget(seed_warning)
        advanced_layout.addWidget(seed_group)
        advanced_layout.addStretch(1)

        # ===========================================================
        # Assemble tabs
        # ===========================================================
        tabs = QTabWidget(self)
        tabs.addTab(info_tab, _("Information"))
        tabs.addTab(settings_tab, _("Settings"))
        tabs.addTab(advanced_tab, _("Advanced"))

        dialog_vbox = QVBoxLayout(self)
        dialog_vbox.addWidget(tabs)
        dialog_vbox.addLayout(Buttons(CloseButton(self)))

        # Fetch initial values
        thread.add(connect_and_doit, on_success=self.show_values)

    # ------------------------------------------------------------------
    # Dialog helpers
    # ------------------------------------------------------------------

    def closeEvent(self, event):
        self.thread.stop()
        self.thread.wait(2000)
        super().closeEvent(event)

    def _pin_entry_dialog(self, msg):
        """Show a PIN entry dialog and return the entered text or None."""
        parent = self.top_level_window()
        d = WindowModalDialog(parent, _("Enter PIN"))
        pw = PasswordLineEdit()
        pw.setMinimumWidth(200)
        vbox = QVBoxLayout()
        vbox.addWidget(WWLabel(msg))
        vbox.addWidget(pw)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        d.setLayout(vbox)
        return pw.text() if d.exec() else None

    def _label_dialog(self, msg):
        """Show a label entry dialog and return the entered text or None."""
        parent = self.top_level_window()
        while True:
            label = line_dialog(
                parent=parent,
                title=_("Enter Label"),
                label=msg,
                ok_label=_("OK"),
            )
            if label is None or len(label.encode("utf-8")) <= 64:
                return label
            self.window.show_error(_("Label must be 64 characters or less!"))

    # ------------------------------------------------------------------
    # Tab data loading
    # ------------------------------------------------------------------

    def show_values(self, client):
        """Refresh the Information tab with card data."""
        try:
            is_ok = client.verify_PIN()
            if not is_ok:
                self.window.show_error(_("Action cancelled by user"))
                return
        except Exception as e:
            self.window.show_error(str(e))
            return

        try:
            (response, sw1, sw2, d) = client.cc.card_get_status()
        except Exception as e:
            self.window.show_error(str(e))
            return

        if sw1 == 0x90 and sw2 == 0x00:
            # Firmware version
            fw_rel = "v{}.{}-{}.{}".format(
                d["protocol_major_version"],
                d["protocol_minor_version"],
                d["applet_major_version"],
                d["applet_minor_version"],
            )
            self.fw_version.setText("<tt>%s" % fw_rel)

            # Device ID (from authentikey fingerprint)
            try:
                authentikey = client.cc.card_export_authentikey()
                if authentikey:
                    from electrum.crypto import hash_160

                    pubkey = authentikey.get_public_key_bytes(compressed=True)
                    device_id_str = hash_160(pubkey)[:4].hex()
                    self.device_id_label.setText("<tt>%s" % device_id_str.upper())
            except Exception:
                self.device_id_label.setText("<tt>(unavailable)")

            # Setup status
            self.setup_done.setText("<tt>%s" % ("yes" if d.get("setup_done") else "no"))

            # PIN tries
            pin_tries = d.get("PIN0_remaining_tries", "?")
            self.pin_tries.setText("<tt>%s" % pin_tries)

            # Seeded status
            if len(response) >= 10:
                is_seeded = d["is_seeded"]
            else:
                try:
                    client.cc.card_bip32_get_authentikey()
                    is_seeded = True
                except Exception:
                    is_seeded = False
            self.is_seeded.setText("<tt>%s" % ("yes" if is_seeded else "no"))

            # Card label
            try:
                (_d1, _d2, _d3, label) = client.cc.card_get_label()
                if label == "":
                    label = "(none)"
                self.card_label_display.setText("<tt>%s" % label)
            except Exception:
                self.card_label_display.setText("<tt>(error)")
        else:
            # Uninitialized card
            self.fw_version.setText("<tt>(uninitialized)")
            self.device_id_label.setText("<tt>(none)")
            self.setup_done.setText("<tt>no")
            self.is_seeded.setText("<tt>no")
            self.card_label_display.setText("<tt>(none)")

    # ------------------------------------------------------------------
    # Settings actions
    # ------------------------------------------------------------------

    def change_pin(self, client):
        _logger.info("In change_pin")
        msg_oldpin = _("Enter the current PIN for your Satochip:")
        msg_newpin = _("Enter a new PIN for your Satochip:")
        msg_confirm = _("Please confirm the new PIN for your Satochip:")
        msg_error = _("The PIN values do not match! Please type PIN again!")
        msg_cancel = _("PIN Change cancelled!")

        try:
            (is_pin, oldpin, newpin) = client.PIN_change_dialog(
                msg_oldpin, msg_newpin, msg_confirm, msg_error, msg_cancel
            )
            if not is_pin:
                return

            oldpin = list(oldpin)
            newpin = list(newpin)
            (response, sw1, sw2) = client.cc.card_change_PIN(0, oldpin, newpin)
            if sw1 == 0x90 and sw2 == 0x00:
                self.window.show_message(_("PIN changed successfully!"))
            else:
                self.window.show_error(
                    _("Failed to change PIN! Error: {}{}").format(hex(sw1), hex(sw2))
                )
        except Exception as ex:
            self.window.show_error(_("Failed to change PIN: {}").format(str(ex)))

    def change_card_label(self, client):
        msg = _("Enter a label for your Satochip (max 64 characters):")

        is_ok = client.verify_PIN()
        if not is_ok:
            return

        label = self._label_dialog(msg)
        if label is None:
            self.window.show_message(_("Operation cancelled."))
            return

        try:
            (response, sw1, sw2) = client.cc.card_set_label(label)
            if sw1 == 0x90 and sw2 == 0x00:
                self.window.show_message(_("Card label changed successfully!"))
                self.card_label_display.setText(
                    "<tt>%s" % (label if label else "(none)")
                )
            elif sw1 == 0x6D and sw2 == 0x00:
                self.window.show_error(
                    _("This card does not support labels (requires v0.12+).")
                )
            else:
                self.window.show_error(
                    _("Failed to change label. Error: {}{}").format(hex(sw1), hex(sw2))
                )
        except Exception as ex:
            self.window.show_error(_("Failed to change label: {}").format(str(ex)))

    # ------------------------------------------------------------------
    # Advanced actions
    # ------------------------------------------------------------------

    def factory_reset(self, client):
        wallet = self.window.wallet
        if wallet and sum(wallet.get_balance()):
            title = _("Confirm Factory Reset")
            msg = _(
                "Are you SURE you want to factory reset the device?\n"
                "Your wallet still has bitcoins in it!"
            )
            if not self.question(msg, title=title, icon=QMessageBox.Icon.Critical):
                return
        else:
            title = _("Confirm Factory Reset")
            msg = _(
                "Are you sure you want to factory reset the device?\n"
                "All data will be erased."
            )
            if not self.question(msg, title=title):
                return

        try:
            client.perform_factory_reset()
            self.window.show_message(_("Factory reset completed successfully."))
        except Exception as ex:
            self.window.show_error(_("Factory reset failed: {}").format(str(ex)))

    def reset_seed(self, client):
        _logger.info("In reset_seed")

        msg = "".join(
            [
                _("WARNING!\n\n"),
                _("You are about to reset the seed of your Satochip.\n"),
                _("This process is irreversible!\n\n"),
                _(
                    "Please be sure that your wallet is empty and that you have a "
                    "backup of the seed as a precaution.\n\n"
                ),
                _("To proceed, enter the PIN for your Satochip:"),
            ]
        )
        password = self._pin_entry_dialog(msg)
        if password is None:
            return
        pin = list(password.encode("utf8"))

        try:
            (response, sw1, sw2) = client.cc.card_reset_seed(pin, [])
            if sw1 == 0x90 and sw2 == 0x00:
                self.window.show_message(
                    _(
                        "Seed reset successfully!\n"
                        "You should close this wallet and launch the wizard to "
                        "generate a new wallet."
                    )
                )
            else:
                self.window.show_error(
                    _("Failed to reset seed. Error: {}{}").format(hex(sw1), hex(sw2))
                )
        except Exception as ex:
            self.window.show_error(_("Failed to reset seed: {}").format(str(ex)))


# ===================================================================
# Wizard Components
# ===================================================================


class WCSatochipBlocked(WalletWizardComponent):
    """Wizard page shown when the Satochip is blocked (PIN tries exhausted).
    Offers a Factory Reset button with automatic card presence detection.
    """

    statusUpdated = pyqtSignal(str)

    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_("Satochip blocked")
        )
        self._busy = False
        self._reset_done = False
        self.statusUpdated.connect(self._on_status_updated)

    def _on_status_updated(self, text):
        self.status_label.setText(text)

    def on_ready(self):
        _name, _info = self.wizard_data["hardware_device"]
        self.plugin = self.wizard.plugins.get_plugin(_info.plugin_name)
        device_id = _info.device.id_
        self.device_id = device_id

        msg = WWLabel(
            "".join(
                [
                    _(
                        "Your Satochip is blocked due to too many failed PIN attempts.\n\n"
                    ),
                    _("The only recovery is a factory reset, which will:\n"),
                    _("  \u2022 Erase all data from the card\n"),
                    _("  \u2022 Delete your wallet seed from the card\n"),
                    _("  \u2022 Return the card to factory state\n\n"),
                    _("Ensure you have a seed backup before proceeding!\n\n"),
                    _(
                        "Click below to start the reset. Remove and reinsert the card "
                        "when prompted \u2014 detection is automatic."
                    ),
                ]
            )
        )
        msg.setWordWrap(True)
        self.layout().addWidget(msg)

        self.reset_btn = QPushButton(_("Factory Reset"))
        self.reset_btn.clicked.connect(self._on_factory_reset)
        self.layout().addWidget(self.reset_btn)
        self.layout().addStretch(1)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.layout().addWidget(self.status_label)

    def _on_factory_reset(self):
        if self._busy:
            return
        self._busy = True
        self.reset_btn.setEnabled(False)
        self.statusUpdated.emit(_("Starting factory reset..."))

        handler = self.plugin.create_handler(self.wizard)
        devmgr = self.plugin.device_manager()
        client = devmgr.client_by_id(self.device_id, scan_now=False)
        if not client:
            self.statusUpdated.emit(_("Device not found. Please rescan."))
            self._busy = False
            self.reset_btn.setEnabled(True)
            return
        client.handler = handler

        def do_reset():
            try:
                client.perform_factory_reset()
                self._reset_done = True
                self.statusUpdated.emit(
                    _(
                        "Factory reset complete! Click Next to rescan devices, "
                        "then select your Satochip again to set it up."
                    )
                )
                self.valid = True
            except Exception as e:
                self.statusUpdated.emit(_("Reset failed: {}").format(str(e)))
                _logger.exception("Factory reset failed")
            finally:
                self._busy = False
                self.reset_btn.setEnabled(True)

        t = threading.Thread(target=do_reset, daemon=True)
        t.start()

    def apply(self):
        pass


class WCSatochipWrongCard(WalletWizardComponent):
    """Wizard page shown when the selected Satochip cannot be used with the
    wallet (authentikey mismatch)."""

    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(self, parent, wizard, title=_("Wrong Satochip"))
        self._busy = False

    def on_ready(self):
        _name, _info = self.wizard_data["hardware_device"]
        device_label = _info.label if _info else "Unknown"

        msg = WWLabel(
            "".join(
                [
                    _("This Satochip cannot be used with this wallet.\n\n"),
                    _(
                        "The card ({}) does not contain the seed that was used to "
                        "create this wallet.\n\n"
                    ).format(device_label),
                    _(
                        "To use a Satochip with an existing wallet, the card must "
                        "already have the SAME seed that created the wallet.\n\n"
                    ),
                    _("Options:\n"),
                    _(
                        "  \u2022 Use a different Satochip that contains the wallet's seed\n"
                    ),
                    _(
                        "  \u2022 Use Satochip-Utils to import the correct seed onto this card\n"
                    ),
                    _("  \u2022 Create a new wallet with this card instead\n\n"),
                    _("Click 'Back' to choose a different device."),
                ]
            )
        )
        msg.setWordWrap(True)
        self.layout().addWidget(msg)
        self.layout().addStretch(1)
        self.valid = True

    def apply(self):
        pass


class WCSatochipRecoverSetup(WalletWizardComponent):
    """Wizard page for setting up PIN on a factory-fresh Satochip for
    existing wallet recovery."""

    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_("Set Up Satochip for Existing Wallet")
        )
        self._busy = False
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin("satochip")

    def on_ready(self):
        _name, _info = self.wizard_data["hardware_device"]
        device_label = _info.label if _info else "Unknown"

        msg = WWLabel(
            "".join(
                [
                    _("This Satochip ({}) is not yet initialized.\n\n").format(
                        device_label
                    ),
                    _(
                        "To use this card with your existing wallet, you must first set "
                        "a PIN, then import the seed phrase that was used to create this "
                        "wallet.\n\n"
                    ),
                    _("Enter a new PIN for this card below (4-16 characters).\n"),
                ]
            )
        )
        msg.setWordWrap(True)
        self.layout().addWidget(msg)

        self.pw = PasswordLineEdit()
        self.pw.setMinimumWidth(32)
        self.layout().addWidget(WWLabel(_("Enter new PIN:")))
        self.layout().addWidget(self.pw)

        self.pw2 = PasswordLineEdit()
        self.pw2.setMinimumWidth(32)
        self.layout().addWidget(WWLabel(_("Confirm new PIN:")))
        self.layout().addWidget(self.pw2)

        self.layout().addStretch(1)

        def validate():
            is_valid = True
            if self.pw.text() != self.pw2.text():
                is_valid = False
            pw_bytes = self.pw.text().encode("utf-8")
            if len(pw_bytes) < 4 or len(pw_bytes) > 16:
                is_valid = False
            pw2_bytes = self.pw2.text().encode("utf-8")
            if len(pw2_bytes) < 4 or len(pw2_bytes) > 16:
                is_valid = False
            self.valid = is_valid

        self.pw2.textChanged.connect(validate)
        self.pw.textChanged.connect(validate)

    def apply(self):
        pin = self.pw.text()
        _name, _info = self.wizard_data["hardware_device"]
        device_id = _info.device.id_

        client = self.plugins.device_manager.client_by_id(device_id, scan_now=False)
        client.handler = self.plugin.create_handler(self.wizard)

        try:
            self.plugin._setup_device(pin, device_id, client)
            _logger.info("[WCSatochipRecoverSetup] Card setup completed")
            self.valid = True
        except Exception as e:
            _logger.exception("[WCSatochipRecoverSetup] Failed to set up card")
            self.error = str(e)
            self.valid = False


class WCSatochipRecoverSeed(WalletWizardComponent):
    """Wizard page for recovering an existing wallet by importing the seed
    onto an unseeded Satochip."""

    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_("Import Seed for Existing Wallet")
        )
        self._busy = False
        self._seed_widget = None
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin("satochip")

    def on_ready(self):
        from electrum.gui.qt.seed_dialog import SeedWidget
        from electrum.keystore import bip39_is_checksum_valid

        _name, _info = self.wizard_data["hardware_device"]
        device_label = _info.label if _info else "Unknown"

        msg = WWLabel(
            "".join(
                [
                    _("This Satochip ({}) is not yet seeded.\n\n").format(device_label),
                    _(
                        "To use this card with your existing wallet, you must import "
                        "the seed phrase that was used to create this wallet.\n\n"
                    ),
                    _(
                        "Enter your BIP39 seed phrase below. It must be the SAME seed "
                        "that was used to create this wallet.\n\n"
                    ),
                    _(
                        "If you enter the wrong seed, the wallet will not open correctly.\n"
                    ),
                ]
            )
        )
        msg.setWordWrap(True)
        self.layout().addWidget(msg)

        def _is_valid_bip39_seed(text):
            is_checksum_valid, is_wordlist_valid = bip39_is_checksum_valid(text)
            return is_checksum_valid and is_wordlist_valid

        self._seed_widget = SeedWidget(
            is_seed=_is_valid_bip39_seed,
            options=["ext", "bip39"],
            config=self.wizard.config,
        )

        def seed_valid_changed(valid):
            self.valid = valid

        self._seed_widget.validChanged.connect(seed_valid_changed)
        self.layout().addWidget(self._seed_widget)
        self.layout().addStretch(1)

    def apply(self):
        if not self._seed_widget:
            return

        seed = self._seed_widget.get_seed()
        passphrase = ""

        cosigner_data = self.wizard.current_cosigner(self.wizard_data)
        cosigner_data["seed"] = seed
        cosigner_data["seed_variant"] = "bip39"
        cosigner_data["seed_type"] = "bip39"
        cosigner_data["seed_extend"] = bool(passphrase)
        cosigner_data["seed_extra_words"] = passphrase

        _name, _info = self.wizard_data["hardware_device"]
        device_id = _info.device.id_

        settings = ("bip39", seed, passphrase)
        handler = self.plugin.create_handler(self.wizard)

        try:
            self.plugin._import_seed(settings, device_id, handler)
            _logger.info("[WCSatochipRecoverSeed] Seed imported successfully")
            self.valid = True
        except Exception as e:
            _logger.exception("[WCSatochipRecoverSeed] Failed to import seed")
            self.error = str(e)
            self.valid = False


class WCSatochipUnlock(WCHWUnlock):
    """Satochip-specific unlock page with clean error messages and
    navigation to satochip_wrong_card on authentikey mismatch."""

    _navigate_to = pyqtSignal(str)

    def __init__(self, parent, wizard):
        super().__init__(parent, wizard)
        self._navigate_to.connect(self._do_navigate)

    def _do_navigate(self, view_key):
        """Navigate to a named page (called via signal for GUI thread)."""
        self.wizard.load_next_component(view_key, self.wizard_data)

    def on_ready(self):
        _name, _info = self.wizard_data["hardware_device"]
        self.plugin = self.plugins.get_plugin(_info.plugin_name)
        self.title = _("Unlocking {} ({})").format(_info.model_name, _info.label)

        device_id = _info.device.id_
        client = self.plugins.device_manager.client_by_id(device_id, scan_now=False)
        if client is None:
            self.error = _("The device was disconnected.")
            self.busy = False
            self.validate()
            return
        client.handler = self.plugin.create_handler(self.wizard)

        def unlock_task(client):
            from electrum.util import UserFacingException

            try:
                self.password = client.get_password_for_storage_encryption()
            except UserFacingException as e:
                msg = str(e)
                if "wrong satochip" in msg.lower() or "does not match" in msg.lower():
                    self.busy = False
                    self._navigate_to.emit("satochip_wrong_card")
                    return
                self.error = msg
            except Exception as e:
                self.error = str(e)
                self.logger.exception(str(e))
            self.busy = False
            self.validate()

        t = threading.Thread(target=unlock_task, args=(client,), daemon=True)
        t.start()


# ===================================================================
# Setup PIN / Seed wizard components
# ===================================================================


class SatochipSetupLayout(QVBoxLayout):
    """PIN setup layout for a new Satochip card."""

    validChanged = pyqtSignal([bool], arguments=["valid"])

    def __init__(self, device):
        QVBoxLayout.__init__(self)

        vbox = QVBoxLayout()
        msg_setup = WWLabel(
            _(
                "Please take a moment to set up your Satochip. "
                "This must be done only once."
            )
        )
        vbox.addWidget(msg_setup)

        self.pw = PasswordLineEdit()
        self.pw.setMinimumWidth(32)
        vbox.addWidget(WWLabel("Enter new PIN:"))
        vbox.addWidget(self.pw)
        self.addLayout(vbox)

        self.pw2 = PasswordLineEdit()
        self.pw2.setMinimumWidth(32)
        vbox2 = QVBoxLayout()
        vbox2.addWidget(WWLabel("Confirm new PIN:"))
        vbox2.addWidget(self.pw2)
        self.addLayout(vbox2)

        if self.pw.text() == "" or self.pw.text() is None:
            self.validChanged.emit(False)

        def set_enabled():
            is_valid = True
            if self.pw.text() != self.pw2.text():
                is_valid = False
            pw_bytes = self.pw.text().encode("utf-8")
            if len(pw_bytes) < 4 or len(pw_bytes) > 16:
                is_valid = False
            pw2_bytes = self.pw2.text().encode("utf-8")
            if len(pw2_bytes) < 4 or len(pw2_bytes) > 16:
                is_valid = False
            self.validChanged.emit(is_valid)

        self.pw2.textChanged.connect(set_enabled)
        self.pw.textChanged.connect(set_enabled)

    def get_settings(self):
        return self.pw.text()


class WCSatochipSetupParams(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(self, parent, wizard, title=_("Satochip Setup"))
        self.plugins = wizard.plugins
        self._busy = True

    def on_ready(self):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        _name, _info = current_cosigner["hardware_device"]
        self.settings_layout = SatochipSetupLayout(_info.device.id_)
        self.settings_layout.validChanged.connect(self.on_settings_valid_changed)
        self.layout().addLayout(self.settings_layout)
        self.layout().addStretch(1)

        self.valid = True
        self.busy = False

    def on_settings_valid_changed(self, is_valid: bool):
        self.valid = is_valid

    def apply(self):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        current_cosigner["satochip_setup_settings"] = (
            self.settings_layout.get_settings()
        )


class WCSatochipSetup(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(self, parent, wizard, title=_("Satochip Setup"))
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin("satochip")

        self.layout().addWidget(WWLabel("Done"))

        self._busy = True

    def on_ready(self):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        settings = current_cosigner["satochip_setup_settings"]
        _name, _info = current_cosigner["hardware_device"]
        device_id = _info.device.id_

        client = self.plugins.device_manager.client_by_id(device_id, scan_now=False)
        client.handler = self.plugin.create_handler(self.wizard)

        def initialize_device_task(settings, device_id, client):
            try:
                self.plugin._setup_device(settings, device_id, client)
                _logger.info("[WCSatochipSetup] Done initialize device")
                self.valid = True
                self.wizard.requestNext.emit()
            except Exception as e:
                self.valid = False
                self.error = str(e)
                _logger.exception(str(e))
            finally:
                self.busy = False

        t = threading.Thread(
            target=initialize_device_task,
            args=(settings, device_id, client),
            daemon=True,
        )
        t.start()

    def apply(self):
        pass


class WCSeedMethodChoice(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_("Satochip needs a seed")
        )

        intro = WWLabel("\n".join(MSG_SEED_IMPORT))
        intro.setWordWrap(True)
        self.layout().addWidget(intro)

        message = _("How do you want to provide a seed for this Satochip card?")
        choices = [
            ChoiceItem(key="import", label=_("I already have a seed phrase")),
            ChoiceItem(key="generate", label=_("Generate a new BIP39 seed phrase")),
        ]
        self.choice_w = ChoiceWidget(
            message=message, choices=choices, default_key="import"
        )
        self.layout().addWidget(self.choice_w)
        self.layout().addStretch(1)

        self._valid = True

    def apply(self):
        self.wizard_data["satochip_seed_method"] = self.choice_w.selected_key


class WCSatochipGenerateSeed(WalletWizardComponent):
    """Display a freshly generated BIP39 seed phrase for the user to write
    down, with 12/24-word selector and regenerate button."""

    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_("Your new BIP39 seed phrase")
        )
        self._seed = None
        self.seed_widget = None

        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel(_("Seed length:")))
        self.radio_12 = QRadioButton(_("12 words"))
        self.radio_24 = QRadioButton(_("24 words"))
        self.radio_24.setChecked(True)
        self.radio_12.toggled.connect(self._on_length_changed)
        self.radio_24.toggled.connect(self._on_length_changed)
        length_layout.addWidget(self.radio_12)
        length_layout.addWidget(self.radio_24)
        self.regen_btn = QPushButton(_("Regenerate"))
        self.regen_btn.clicked.connect(self._on_regenerate_clicked)
        length_layout.addWidget(self.regen_btn)
        length_layout.addStretch(1)
        self.layout().addLayout(length_layout)

        self._busy = True

    def on_ready(self):
        QTimer.singleShot(1, self._create_seed)

    def _current_length(self) -> int:
        return 12 if self.radio_12.isChecked() else 24

    def _create_seed(self):
        self.busy = True
        self._seed = _generate_bip39_mnemonic(self._current_length())

        from electrum.gui.qt.seed_dialog import SeedWidget

        self.seed_widget = SeedWidget(
            title=_("Your wallet generation seed is:"),
            seed=self._seed,
            options=["ext", "bip39"],
            msg=True,
            parent=self,
            config=self.wizard.config,
        )
        self.layout().addWidget(self.seed_widget)
        self.layout().addStretch(1)

        self.busy = False
        self.valid = True

    def _refresh_seed(self):
        self._seed = _generate_bip39_mnemonic(self._current_length())
        if self.seed_widget is not None:
            self.seed_widget.seed_e.setText(self._seed)

    def _on_length_changed(self, checked: bool) -> None:
        if checked:
            self._refresh_seed()

    def _on_regenerate_clicked(self) -> None:
        self._refresh_seed()

    def apply(self):
        cosigner_data = self.wizard.current_cosigner(self.wizard_data)
        cosigner_data["seed"] = self._seed
        cosigner_data["seed_type"] = "bip39"
        cosigner_data["seed_variant"] = "bip39"
        cosigner_data["seed_extend"] = bool(
            self.seed_widget and self.seed_widget.is_ext
        )


class WCSeedSuccess(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(self, parent, wizard, title=_("Success!"))

    def on_ready(self):
        w_icon = QLabel()
        w_icon.setPixmap(
            QPixmap(icon_path("confirmed.png")).scaledToWidth(
                48, mode=Qt.TransformationMode.SmoothTransformation
            )
        )
        w_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label = WWLabel(_("Seed imported successfully!"))
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout().addStretch(1)
        self.layout().addWidget(w_icon)
        self.layout().addWidget(label)
        self.layout().addStretch(1)
        self._valid = True

    def apply(self):
        pass


class WCSatochipImportSeed(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(self, parent, wizard, title=_("Satochip Setup"))
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin("satochip")

        self.layout().addWidget(WWLabel("Done"))

        self._busy = True

    def on_ready(self):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)

        settings = (
            current_cosigner["seed_type"],
            current_cosigner["seed"],
            current_cosigner["seed_extra_words"]
            if current_cosigner.get("seed_extend")
            else "",
        )

        _name, _info = current_cosigner["hardware_device"]
        device_id = _info.device.id_
        client = self.plugins.device_manager.client_by_id(device_id, scan_now=False)
        client.handler = self.plugin.create_handler(self.wizard)

        def initialize_device_task(settings, device_id, handler):
            try:
                self.plugin._import_seed(settings, device_id, handler)
                _logger.info("[WCSatochipImportSeed] Done initialize device")
                self.valid = True
                self.wizard.requestNext.emit()
            except Exception as e:
                self.valid = False
                self.error = str(e)
                _logger.exception(str(e))
            finally:
                self.busy = False

        t = threading.Thread(
            target=initialize_device_task,
            args=(settings, device_id, client.handler),
            daemon=True,
        )
        t.start()

    def apply(self):
        pass


# ===================================================================
# Helpers
# ===================================================================


def _generate_bip39_mnemonic(num_words: int) -> str:
    """Generate a BIP39 mnemonic using only Electrum's bundled wordlist.

    Implements the BIP39 algorithm directly:
      entropy -> sha256 checksum -> concatenate -> split into 11-bit
      indices -> words.

    Uses only Python stdlib and Electrum's english.txt wordlist.
    *num_words* must be 12 (128-bit entropy) or 24 (256-bit entropy).
    """
    assert num_words in (12, 24), f"num_words must be 12 or 24, got {num_words}"

    entropy_bits = 128 if num_words == 12 else 256
    entropy_bytes = secrets.token_bytes(entropy_bits // 8)

    # BIP39: checksum = first (entropy_bits / 32) bits of sha256(entropy)
    checksum_bits = entropy_bits // 32
    digest = hashlib.sha256(entropy_bytes).digest()
    checksum = digest[0] >> (8 - checksum_bits)

    # Pack entropy + checksum into one big integer
    entropy_int = int.from_bytes(entropy_bytes, "big")
    combined = (entropy_int << checksum_bits) | checksum

    # Split into 11-bit groups and look up words
    from electrum.mnemonic import Wordlist

    wordlist = Wordlist.from_file("english.txt")
    words = [
        wordlist[(combined >> (11 * i)) & 0x7FF] for i in range(num_words - 1, -1, -1)
    ]
    return " ".join(words)
