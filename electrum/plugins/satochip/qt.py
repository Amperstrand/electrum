from functools import partial
from os import urandom
import secrets
import textwrap
import threading

from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (QPushButton, QLabel, QVBoxLayout, QHBoxLayout,
                             QWidget, QGridLayout, QComboBox, QTabWidget,
                             QGroupBox, QSpinBox, QRadioButton, QSlider,
                             QMessageBox)
from electrum.i18n import _
from electrum.logging import get_logger
from electrum.util import UserFacingException, ChoiceItem
from electrum.simple_config import SimpleConfig
from electrum.gui.qt.util import (EnterButton, Buttons, CloseButton, icon_path,
                                  OkButton, CancelButton, WindowModalDialog, WWLabel,
                                  PasswordLineEdit, ChoiceWidget, ColorScheme,
                                  line_dialog)
from electrum.mnemonic import Wordlist
from electrum.gui.qt.seed_dialog import SeedWidget
from electrum.gui.qt.qrcodewidget import QRCodeWidget
from electrum.gui.qt.wizard.wallet import (WCHaveSeed, WCEnterExt, WCScriptAndDerivation,
                                           WCHWUnlock, WCHWXPub, WalletWizardComponent, QENewWalletWizard)
from electrum.plugin import hook
from electrum.hw_wallet.qt import QtHandlerBase, QtPluginBase

# satochip
from .satochip import SatochipPlugin

# pysatochip
from pysatochip.CardConnector import UnexpectedSW12Error, CardError, CardNotPresentError, WrongPinError
from pysatochip.Satochip2FA import Satochip2FA, SERVER_LIST
from pysatochip.version import SATOCHIP_PROTOCOL_MAJOR_VERSION, SATOCHIP_PROTOCOL_MINOR_VERSION
from .logging_utils import instrument_module_function_entries

_logger = get_logger(__name__)


# Error message mapping for user-friendly messages
def get_user_friendly_error(error: Exception, context: str = '') -> str:
    """Map technical errors to user-friendly messages."""
    error_type = type(error).__name__
    error_str = str(error).lower()
    
    # Card connection errors
    if 'card not present' in error_str or 'CardNotPresentError' in error_type:
        return _("No Satochip card detected. Please insert your card and try again.")
    
    # PIN errors
    if 'WrongPinError' in error_type:
        tries = getattr(error, 'pin_left', getattr(error, 'tries_left', 'unknown'))
        if tries == 0 or 'blocked' in error_str:
            return _("PIN is blocked! You must use the PUK to unblock the card.")
        return _(f"Wrong PIN! {tries} tries remaining before the card is blocked.")
    if 'wrong pin' in error_str or 'invalid pin' in error_str:
        return _("Incorrect PIN. Please try again.")
    
    # Card errors
    if 'CardError' in error_type:
        return _("The card encountered an error. Please try again or reinsert the card.")
    
    # Secure channel errors
    if 'secure channel' in error_str or 'encryption' in error_str:
        return _("Secure channel error. The card may need to be reinitialized.")
    
    # 2FA errors
    if '2fa' in error_str or 'challenge' in error_str:
        return _("Two-factor authentication error. Please check your 2FA device.")
    if 'rejected by 2fa' in error_str or '0x9c0b' in error_str:
        return _("Transaction rejected by your 2FA device.")
    
    # Seed errors
    if 'not seeded' in error_str or 'unseeded' in error_str:
        return _("The card does not have a seed. Please import a seed first.")
    if 'already seeded' in error_str:
        return _("The card already has a seed. Reset the seed first to import a new one.")
    
    # APDU status word errors (common ones)
    if '0x6982' in error_str:
        return _("Security condition not satisfied. PIN verification may be required.")
    if '0x6983' in error_str:
        return _("Authentication method blocked. The PIN or PUK has been exhausted.")
    if '0x6a80' in error_str:
        return _("Invalid data sent to card. Please check your inputs.")
    if '0x6d00' in error_str:
        return _("Command not supported. The card firmware may need to be updated.")
    if '0x6e00' in error_str:
        return _("Card does not support this command.")
    
    # User-facing exceptions (already user-friendly)
    if isinstance(error, UserFacingException):
        return str(error)
    
    # Default fallback with context
    if context:
        return _(f"Error during {context}: {error}")
    return _(f"An error occurred: {error}")


MSG_USE_2FA = _(
    "Do you want to use 2-Factor-Authentication (2FA)?"
    "\n\nWith 2FA, any transaction must be confirmed on a second device such as your smartphone. "
    "First you have to install the Satochip-2FA android app on google play. "
    "Then you have to pair your 2FA device with your Satochip by scanning the qr-code on the next screen. "
    "\n\nWARNING: be sure to backup a copy of the qr-code in a safe place, in case you have to reinstall the app!"
)

def _generate_bip39_mnemonic(num_words: int) -> str:
    """Generate a BIP39 mnemonic using only Electrum's bundled wordlist.

    Implements the BIP39 algorithm directly:
      entropy  → sha256 checksum → concatenate → split into 11-bit indices → words.

    Uses only Python stdlib (os.urandom, hashlib) and the english.txt wordlist
    that Electrum already ships.  No external 'mnemonic' (python-mnemonic) package
    is required.

    num_words must be 12 (128-bit entropy) or 24 (256-bit entropy).
    """
    import hashlib as _hashlib

    assert num_words in (12, 24), f"num_words must be 12 or 24, got {num_words}"

    entropy_bits = 128 if num_words == 12 else 256
    entropy_bytes = secrets.token_bytes(entropy_bits // 8)

    # BIP39: checksum = first (entropy_bits / 32) bits of sha256(entropy)
    checksum_bits = entropy_bits // 32
    digest = _hashlib.sha256(entropy_bytes).digest()
    checksum = digest[0] >> (8 - checksum_bits)

    # Pack entropy + checksum into one big integer
    entropy_int = int.from_bytes(entropy_bytes, 'big')
    combined = (entropy_int << checksum_bits) | checksum

    # Split into 11-bit groups and look up words
    wordlist = Wordlist.from_file('english.txt')
    words = [
        wordlist[(combined >> (11 * i)) & 0x7FF]
        for i in range(num_words - 1, -1, -1)
    ]
    return ' '.join(words)


MSG_SEED_IMPORT = [
    _("Your Satochip is currently unseeded. "),
    _("To use it, you need to import a BIP39 Seed. "),
    _("To do so, select BIP39 in the options in the next screen. "),
    _("Note that Electrum seeds are not supported by hardware wallets. "),
    " ",
    _("Optionally, you can also enable a passphrase in the options. "),
    _("A passphrase is an optional feature that allows you to extend your seed with additional entropy. "),
    _("A passphrase is not a PIN. "),
    _("If set, you will need your passphrase along with your BIP39 seed to restore your wallet from a backup. "),
]


class Plugin(SatochipPlugin, QtPluginBase):
    icon_unpaired = "satochip_unpaired.png"
    icon_paired = "satochip.png"

    def create_handler(self, window):
        return Satochip_Handler(window)

    def requires_settings(self):
        # Return True to add a Settings button.
        return True

    def settings_widget(self, window):
        # Return a button that when pressed presents a settings dialog.
        return EnterButton(_('Settings'), partial(self.settings_dialog, window))

    def settings_dialog(self, window):
        # Return a settings dialog.
        d = WindowModalDialog(window, _("Email settings"))
        vbox = QVBoxLayout(d)

        d.setMinimumSize(500, 200)
        vbox.addStretch()
        vbox.addLayout(Buttons(CloseButton(d), OkButton(d)))
        d.show()

    def show_settings_dialog(self, window, keystore):
        # When they click on the icon for Satochip we come here.
        def connect():
            device_id = self.choose_device(window, keystore)
            return device_id

        def show_dialog(device_id):
            if device_id:
                SatochipSettingsDialog(
                    window, self, keystore, device_id).exec()
        keystore.thread.add(connect, on_success=show_dialog)

    @hook
    def init_wallet_wizard(self, wizard: 'QENewWalletWizard'):
        self.extend_wizard(wizard)

    # insert satochip pages in new wallet wizard
    def extend_wizard(self, wizard: 'QENewWalletWizard'):
        super().extend_wizard(wizard)
        views = {
            'satochip_start': {'gui': WCScriptAndDerivation},
            'satochip_xpub': {'gui': WCHWXPub},
            'satochip_not_setup': {'gui': WCSatochipSetupParams},
            'satochip_do_setup': {'gui': WCSatochipSetup},
            'satochip_not_seeded': {
                'gui': WCSeedMethodChoice,
                'next': lambda d: 'satochip_have_seed' if d.get('satochip_seed_method') == 'import'
                                  else 'satochip_generate_seed',
            },
            'satochip_generate_seed': {
                'gui': WCSatochipGenerateSeed,
                'next': lambda d: 'satochip_have_ext' if wizard.wants_ext(d) else 'satochip_import_seed',
            },
            'satochip_have_seed': {
                'gui': WCHaveSeed,
                'next': lambda d: 'satochip_have_ext' if wizard.wants_ext(d) else 'satochip_import_seed',
                'params': {'seed_options': ['ext', 'bip39']}
            },
            'satochip_have_ext': {
                'gui': WCEnterExt,
                'next': 'satochip_import_seed',
            },
            'satochip_import_seed': {
                'gui': WCSatochipImportSeed,
                'next': 'satochip_success_seed',
            },
            'satochip_success_seed': {
                'gui': WCSeedSuccess,
            },
            'satochip_unlock': {'gui': WCSatochipUnlock},
            'satochip_blocked': {
                'gui': WCSatochipBlocked,
                'next': 'choose_hardware_device',  # After reset, go back to device selection to rescan
            },
            'satochip_wrong_card': {
                'gui': WCSatochipWrongCard,
                'next': 'choose_hardware_device',  # Go back to device selection
            },
            # Seed recovery for existing wallets
            'satochip_recover_setup': {
                'gui': WCSatochipRecoverSetup,
                'next': 'satochip_recover_seed',
            },
            'satochip_recover_seed': {
                'gui': WCSatochipRecoverSeed,
                'next': 'satochip_unlock',  # After seed import, unlock wallet
            },
        }
        wizard.navmap_merge(views)


class WCSatochipBlocked(WalletWizardComponent):
    """Wizard page shown when the selected Satochip is blocked (PIN tries exhausted).
    Offers a Factory Reset button.  Reset runs automatically with card presence detection
    — no manual OK clicks between steps.
    """
    statusUpdated = pyqtSignal(str)

    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_('Satochip blocked'))
        self._busy = False
        self._reset_done = False
        self.statusUpdated.connect(self._on_status_updated)

    def _on_status_updated(self, text):
        self.status_label.setText(text)

    def on_ready(self):
        _name, _info = self.wizard_data['hardware_device']
        self.plugin = self.wizard.plugins.get_plugin(_info.plugin_name)
        device_id = _info.device.id_
        self.device_id = device_id

        msg = WWLabel(''.join([
            _("Your Satochip is blocked due to too many failed PIN attempts.\n\n"),
            _("The only recovery is a factory reset, which will:\n"),
            _("  • Erase all data from the card\n"),
            _("  • Delete your wallet seed from the card\n"),
            _("  • Return the card to factory state\n\n"),
            _("⚠️  Ensure you have a seed backup before proceeding!\n\n"),
            _("Click below to start the reset. Remove and reinsert the card when "
              "prompted — detection is automatic."),
        ]))
        msg.setWordWrap(True)
        self.layout().addWidget(msg)

        self.reset_btn = EnterButton(_("Factory Reset"), self._on_factory_reset)
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

        # create_handler() must be called from the GUI thread (QtHandlerBase assertion).
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
                self.statusUpdated.emit(_(
                    "Factory reset complete! Click Next to rescan devices, "
                    "then select your Satochip again to set it up."))
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
    """Wizard page shown when the selected Satochip cannot be used with the wallet.
    
    This happens when:
    - Card is factory-fresh (no PIN set) and user tries to open existing wallet
    - Card has PIN but no seed and user tries to open existing wallet
    
    The card MUST be seeded to work with an existing wallet.
    """
    
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_('Wrong Satochip'))
        self._busy = False

    def on_ready(self):
        _name, _info = self.wizard_data['hardware_device']
        device_label = _info.label if _info else 'Unknown'
        
        msg = WWLabel(''.join([
            _("This Satochip cannot be used with this wallet.\n\n"),
            _("The card ({}) does not contain the seed that was used to create this wallet.\n\n").format(device_label),
            _("To use a Satochip with an existing wallet, the card must already have "
              "the SAME seed that created the wallet.\n\n"),
            _("Options:\n"),
            _("  • Use a different Satochip that contains the wallet's seed\n"),
            _("  • Use Satochip-Utils to import the correct seed onto this card\n"),
            _("  • Create a new wallet with this card instead\n\n"),
            _("Click 'Back' to choose a different device."),
        ]))
        msg.setWordWrap(True)
        self.layout().addWidget(msg)
        self.layout().addStretch(1)
        self.valid = True

    def apply(self):
        pass


class WCSatochipRecoverSetup(WalletWizardComponent):
    """Wizard page for setting up PIN on a factory-fresh Satochip for existing wallet recovery.
    
    This happens when:
    - Card is factory-fresh (no PIN set) and user tries to open existing wallet
    
    User must set a PIN on the card, then proceed to seed recovery.
    """
    
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_('Set Up Satochip for Existing Wallet'))
        self._busy = False
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin('satochip')

    def on_ready(self):
        _name, _info = self.wizard_data['hardware_device']
        device_label = _info.label if _info else 'Unknown'
        
        # Explanation message
        msg = WWLabel(''.join([
            _("This Satochip ({}) is not yet initialized.\n\n").format(device_label),
            _("To use this card with your existing wallet, you must first set a PIN, "
              "then import the seed phrase that was used to create this wallet.\n\n"),
            _("Enter a new PIN for this card below (4-16 characters).\n"),
        ]))
        msg.setWordWrap(True)
        self.layout().addWidget(msg)
        
        # PIN input
        self.pw = PasswordLineEdit()
        self.pw.setMinimumWidth(32)
        self.layout().addWidget(WWLabel(_("Enter new PIN:")))
        self.layout().addWidget(self.pw)
        
        self.pw2 = PasswordLineEdit()
        self.pw2.setMinimumWidth(32)
        self.layout().addWidget(WWLabel(_("Confirm new PIN:")))
        self.layout().addWidget(self.pw2)
        
        self.layout().addStretch(1)
        
        # PIN validation
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
        # Set up the card with the PIN
        pin = self.pw.text()
        _name, _info = self.wizard_data['hardware_device']
        device_id = _info.device.id_
        
        client = self.plugins.device_manager.client_by_id(device_id, scan_now=False)
        client.handler = self.plugin.create_handler(self.wizard)
        
        try:
            self.plugin._setup_device(pin, device_id, client)
            _logger.info('[WCSatochipRecoverSetup] Card setup completed')
            self.valid = True
        except Exception as e:
            _logger.exception('[WCSatochipRecoverSetup] Failed to set up card')
            self.error = str(e)
            self.valid = False


class WCSatochipRecoverSeed(WalletWizardComponent):
    """Wizard page for recovering an existing wallet by importing the seed onto an unseeded Satochip.
    
    This happens when:
    - Card has PIN set but no seed and user tries to open existing wallet
    
    User must enter the seed phrase that matches the wallet, which will be imported onto the card.
    """
    
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_('Import Seed for Existing Wallet'))
        self._busy = False
        self._seed_widget = None
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin('satochip')

    def on_ready(self):
        _name, _info = self.wizard_data['hardware_device']
        device_label = _info.label if _info else 'Unknown'
        
        # Explanation message
        msg = WWLabel(''.join([
            _("This Satochip ({}) is not yet seeded.\n\n").format(device_label),
            _("To use this card with your existing wallet, you must import the seed phrase "
              "that was used to create this wallet.\n\n"),
            _("Enter your BIP39 seed phrase below. It must be the SAME seed that was used "
              "to create this wallet.\n\n"),
            _("⚠️ If you enter the wrong seed, the wallet will not open correctly.\n"),
        ]))
        msg.setWordWrap(True)
        self.layout().addWidget(msg)
        
        # Seed input widget - only allow BIP39
        self._seed_widget = SeedWidget(
            is_seed=self._is_valid_bip39_seed,
            options=['ext', 'bip39'],  # Only BIP39 with optional passphrase
            config=self.wizard.config,
        )
        
        def seed_valid_changed(valid):
            self.valid = valid
            
        self._seed_widget.validChanged.connect(seed_valid_changed)
        self.layout().addWidget(self._seed_widget)
        self.layout().addStretch(1)

    def _is_valid_bip39_seed(self, text: str) -> bool:
        """Check if text is a valid BIP39 seed."""
        from electrum.keystore import bip39_is_checksum_valid
        is_checksum_valid, is_wordlist_valid = bip39_is_checksum_valid(text)
        return is_checksum_valid and is_wordlist_valid

    def apply(self):
        if not self._seed_widget:
            return
        
        seed = self._seed_widget.get_seed()
        # Note: Passphrase support not included in this recovery flow.
        # Users with passphrase-protected seeds should use Satochip-Utils.
        passphrase = ''
        
        # Store in wizard_data for use by the unlock step
        cosigner_data = self.wizard.current_cosigner(self.wizard_data)
        cosigner_data['seed'] = seed
        cosigner_data['seed_variant'] = 'bip39'
        cosigner_data['seed_type'] = 'bip39'
        cosigner_data['seed_extend'] = bool(passphrase)
        cosigner_data['seed_extra_words'] = passphrase
        
        # Import seed onto the card
        _name, _info = self.wizard_data['hardware_device']
        device_id = _info.device.id_
        
        settings = ('bip39', seed, passphrase)
        handler = self.plugin.create_handler(self.wizard)
        
        try:
            self.plugin._import_seed(settings, device_id, handler)
            _logger.info('[WCSatochipRecoverSeed] Seed imported successfully')
            # Now set up to proceed to unlock
            self.valid = True
        except Exception as e:
            _logger.exception('[WCSatochipRecoverSeed] Failed to import seed')
            self.error = str(e)
            self.valid = False


class Satochip_Handler(QtHandlerBase):

    def __init__(self, win):
        super(Satochip_Handler, self).__init__(win, 'Satochip')

    def message_dialog(self, msg, on_cancel=None):
        """
        Override the base handler message dialog to include an explicit OK button.

        The default hardware handler shows a window without buttons that can only
        be dismissed via ESC/close. For Satochip we want a clearer UX so users
        can dismiss informational messages (like factory-reset success) with
        Enter or by clicking OK.
        """
        # Close any previous dialog managed by this handler.
        self.clear_dialog()

        title = self.MESSAGE_DIALOG_TITLE
        if title is None:
            title = _('Satochip')

        parent = self.top_level_window()
        self.dialog = dialog = WindowModalDialog(parent, title)

        label = QLabel(msg)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        vbox = QVBoxLayout(dialog)
        vbox.addWidget(label)

        buttons = []
        if on_cancel is not None:
            dialog.rejected.connect(on_cancel)
            buttons.append(CancelButton(dialog))
        # Add an OK button and make it the default so Enter works.
        buttons.append(OkButton(dialog))
        vbox.addLayout(Buttons(*buttons))

        dialog.show()

class WCSatochipUnlock(WCHWUnlock):
    """Satochip-specific unlock page.
    
    Provides clean str(e) error messages instead of repr(e), and emits
    a Qt signal to navigate to satochip_wrong_card when an authentikey
    mismatch (wrong card) is detected.
    """
    _navigate_to = pyqtSignal(str)  # page key to navigate to

    def __init__(self, parent, wizard):
        super().__init__(parent, wizard)
        self._navigate_to.connect(self._do_navigate)

    def _do_navigate(self, view_key):
        """Navigate to a named page. Must run on GUI thread (connected via signal)."""
        self.wizard.load_next_component(view_key, self.wizard_data)

    def on_ready(self):
        _name, _info = self.wizard_data['hardware_device']
        device_id = _info.device.id_
        client = self.plugins.device_manager.client_by_id(device_id, scan_now=False)
        if client is None:
            self.error = _('The device was disconnected.')
            self.busy = False
            self.validate()
            return
        client.handler = self.plugin.create_handler(self.wizard)

        def unlock_task(client):
            try:
                self.password = client.get_password_for_storage_encryption()
            except UserFacingException as e:
                msg = str(e)
                if 'wrong satochip' in msg.lower() or 'does not match' in msg.lower():
                    self.busy = False
                    self._navigate_to.emit('satochip_wrong_card')
                    return
                self.error = msg
            except Exception as e:
                self.error = str(e)
                self.logger.exception(str(e))
            self.busy = False
            self.validate()

        t = threading.Thread(target=unlock_task, args=(client,), daemon=True)
        t.start()

    """Tabbed settings dialog for Satochip device.
    
    Tab 1 - Information: Device status, versions, card info
    Tab 2 - Settings: PIN change, label, session timeout  
    Tab 3 - Advanced: 2FA, seed reset, card verification
    """

    def __init__(self, window, plugin, keystore, device_id):
        title = _("{} Settings").format(plugin.device)
        super(SatochipSettingsDialog, self).__init__(window, title)
        self.setMaximumWidth(600)
        self.setMinimumHeight(400)

        devmgr = plugin.device_manager()
        self.config = devmgr.config
        handler = keystore.handler
        self.thread = thread = keystore.thread
        self.window = window
        self.device_id = device_id
        self.devmgr = devmgr
        
        # Store feature values for display
        self.features = {}

        def connect_and_doit():
            client = devmgr.client_by_id(device_id)
            if not client:
                raise RuntimeError("Device not connected")
            return client

        # Create tab widget
        tabs = QTabWidget()
        
        # =====================================
        # TAB 1: Information
        # =====================================
        info_tab = QWidget()
        info_layout = QVBoxLayout(info_tab)
        info_glayout = QGridLayout()
        info_glayout.setColumnStretch(2, 1)

        # Header with logo
        header_label = QLabel('''<center>
<span style="font-size: x-large">Satochip</span>
<br><a href="https://satochip.io">satochip.io</a>
</center>''')
        header_label.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse)
        header_label.setOpenExternalLinks(True)
        info_glayout.addWidget(header_label, 0, 0, 1, 2, Qt.AlignmentFlag.AlignHCenter)
        
        y = 2
        rows = [
            ('fw_version', _("Firmware Version:")),
            ('sw_version', _("Electrum Support:")),
            ('device_id_label', _("Device ID:")),
            ('is_seeded', _("Wallet seeded:")),
            ('setup_done', _("Setup completed:")),
            ('pin_tries', _("PIN tries remaining:")),
        ]
        for row_num, (member_name, label) in enumerate(rows):
            widget = QLabel('<tt>')
            widget.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
            info_glayout.addWidget(QLabel(label), y, 0, 1, 1, Qt.AlignmentFlag.AlignRight)
            info_glayout.addWidget(widget, y, 1, 1, 1, Qt.AlignmentFlag.AlignLeft)
            setattr(self, member_name, widget)
            y += 1

        info_layout.addLayout(info_glayout)
        info_layout.addStretch(1)

        # =====================================
        # TAB 2: Settings
        # =====================================
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)
        settings_glayout = QGridLayout()
        settings_glayout.setColumnStretch(2, 1)

        y = 0
        
        # Session Timeout Section
        timeout_group = QGroupBox(_("Session Timeout"))
        timeout_vbox = QVBoxLayout(timeout_group)
        
        timeout_msg = QLabel(
            _("Automatically lock the device after a period of inactivity. "
              "Once locked, you will need to enter your PIN again to use the device."))
        timeout_msg.setWordWrap(True)
        timeout_vbox.addWidget(timeout_msg)
        
        timeout_hbox = QHBoxLayout()
        self.timeout_label = QLabel(_("5 minutes"))
        self.timeout_label.setMinimumWidth(80)
        timeout_slider = QSlider(Qt.Orientation.Horizontal)
        timeout_slider.setRange(1, 60)  # 1-60 minutes
        timeout_slider.setSingleStep(1)
        timeout_slider.setTickInterval(5)
        timeout_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        
        # Load current timeout (default 5 minutes)
        current_timeout = self.config.get('satochip_session_timeout', 300) // 60
        timeout_slider.setValue(current_timeout)
        self.timeout_label.setText(_("{:d} minutes").format(current_timeout))
        
        def timeout_changed(value):
            self.timeout_label.setText(_("{:d} minutes").format(value))
            
        def timeout_released():
            mins = timeout_slider.value()
            self.config.set_key('satochip_session_timeout', mins * 60, save=True)
            _logger.info(f"Session timeout set to {mins} minutes")
            
        timeout_slider.valueChanged.connect(timeout_changed)
        timeout_slider.sliderReleased.connect(timeout_released)
        
        timeout_hbox.addWidget(timeout_slider)
        timeout_hbox.addWidget(self.timeout_label)
        timeout_vbox.addLayout(timeout_hbox)
        
        settings_layout.addWidget(timeout_group)
        
        # Card Label Section
        label_group = QGroupBox(_("Card Label"))
        label_vbox = QVBoxLayout(label_group)
        
        self.card_label_display = QLabel('<tt>(none)')
        label_vbox.addWidget(self.card_label_display)
        
        change_label_btn = QPushButton(_("Change Label"))
        change_label_btn.clicked.connect(lambda: thread.add(connect_and_doit, on_success=self.change_card_label))
        label_vbox.addWidget(change_label_btn)
        
        label_msg = QLabel(_("The label is stored on the card and helps identify it."))
        label_msg.setWordWrap(True)
        label_msg.setStyleSheet(ColorScheme.GRAY.as_stylesheet())
        label_vbox.addWidget(label_msg)
        
        settings_layout.addWidget(label_group)
        
        # PIN Section
        pin_group = QGroupBox(_("PIN Management"))
        pin_vbox = QVBoxLayout(pin_group)
        
        pin_btn = QPushButton(_("Change PIN"))
        pin_btn.clicked.connect(lambda: thread.add(connect_and_doit, on_success=self.change_pin))
        pin_vbox.addWidget(pin_btn)
        
        pin_msg = QLabel(_("Change the PIN used to unlock your Satochip."))
        pin_msg.setWordWrap(True)
        pin_msg.setStyleSheet(ColorScheme.GRAY.as_stylesheet())
        pin_vbox.addWidget(pin_msg)
        
        settings_layout.addWidget(pin_group)
        settings_layout.addStretch(1)

        # =====================================
        # TAB 3: Advanced
        # =====================================
        advanced_tab = QWidget()
        advanced_layout = QVBoxLayout(advanced_tab)
        advanced_glayout = QGridLayout()
        advanced_glayout.setColumnStretch(2, 1)

        # Security status row
        y = 0
        for name, label in [('needs_2FA', _("2FA Enabled:")), ('needs_SC', _("Secure Channel:"))]:
            widget = QLabel('<tt>')
            advanced_glayout.addWidget(QLabel(label), y, 0, 1, 1, Qt.AlignmentFlag.AlignRight)
            advanced_glayout.addWidget(widget, y, 1, 1, 1, Qt.AlignmentFlag.AlignLeft)
            setattr(self, name, widget)
            y += 1
        
        advanced_layout.addLayout(advanced_glayout)
        advanced_layout.addSpacing(10)
        
        # 2FA Section
        twofa_group = QGroupBox(_("Two-Factor Authentication"))
        twofa_vbox = QVBoxLayout(twofa_group)
        
        self.set_2FA_btn = QPushButton(_("Enable 2FA"))
        self.set_2FA_btn.clicked.connect(lambda: thread.add(connect_and_doit, on_success=self.set_2FA))
        self.set_2FA_btn.clicked.connect(lambda: thread.add(connect_and_doit, on_success=self.show_values))
        twofa_vbox.addWidget(self.set_2FA_btn)
        
        self.reset_2FA_btn = QPushButton(_("Disable 2FA"))
        self.reset_2FA_btn.clicked.connect(lambda: thread.add(connect_and_doit, on_success=self.reset_2FA))
        self.reset_2FA_btn.clicked.connect(lambda: thread.add(connect_and_doit, on_success=self.show_values))
        twofa_vbox.addWidget(self.reset_2FA_btn)
        
        change_2FA_server_btn = QPushButton(_("Select 2FA Server"))
        change_2FA_server_btn.clicked.connect(lambda: thread.add(connect_and_doit, on_success=self.change_2FA_server))
        twofa_vbox.addWidget(change_2FA_server_btn)
        
        twofa_msg = QLabel(_("With 2FA, transactions must be confirmed on a second device (e.g., smartphone)."))
        twofa_msg.setWordWrap(True)
        twofa_msg.setStyleSheet(ColorScheme.GRAY.as_stylesheet())
        twofa_vbox.addWidget(twofa_msg)
        
        advanced_layout.addWidget(twofa_group)
        
        # Seed Management Section
        seed_group = QGroupBox(_("Seed Management"))
        seed_vbox = QVBoxLayout(seed_group)
        
        seed_btn = QPushButton(_("Reset Seed"))
        seed_btn.clicked.connect(lambda: thread.add(connect_and_doit, on_success=self.reset_seed))
        seed_btn.clicked.connect(lambda: thread.add(connect_and_doit, on_success=self.show_values))
        seed_vbox.addWidget(seed_btn)
        
        seed_warning = QLabel(
            _("⚠️ WARNING: Resetting the seed will erase all keys from the card. "
              "Make sure you have a backup of your seed before proceeding!"))
        seed_warning.setWordWrap(True)
        seed_warning.setStyleSheet(ColorScheme.RED.as_stylesheet())
        seed_vbox.addWidget(seed_warning)
        
        advanced_layout.addWidget(seed_group)
        
        # Card Verification Section
        verify_group = QGroupBox(_("Card Verification"))
        verify_vbox = QVBoxLayout(verify_group)
        
        verify_card_btn = QPushButton(_("Verify Card Authenticity"))
        verify_card_btn.clicked.connect(lambda: thread.add(connect_and_doit, on_success=self.verify_card))
        verify_vbox.addWidget(verify_card_btn)
        
        verify_msg = QLabel(_("Verify the card's certificate chain to ensure it is a genuine Satochip."))
        verify_msg.setWordWrap(True)
        verify_msg.setStyleSheet(ColorScheme.GRAY.as_stylesheet())
        verify_vbox.addWidget(verify_msg)
        
        advanced_layout.addWidget(verify_group)
        advanced_layout.addStretch(1)

        # Add tabs to widget
        tabs.addTab(info_tab, _("Information"))
        tabs.addTab(settings_tab, _("Settings"))
        tabs.addTab(advanced_tab, _("Advanced"))

        dialog_vbox = QVBoxLayout(self)
        dialog_vbox.addWidget(tabs)
        dialog_vbox.addLayout(Buttons(CloseButton(self)))

        # Fetch values and show them
        thread.add(connect_and_doit, on_success=self.show_values)

    def show_values(self, client):
        _logger.info("Show values!")
        try:
            is_ok = client.verify_PIN()
            if not is_ok:
                self.window.show_error(_("Action cancelled by user"))
                return
        except UserFacingException as e:
            self.window.show_error(str(e))
            return
        except Exception as e:
            self.window.show_error(get_user_friendly_error(e, "PIN verification"))
            return

        # Software version
        sw_rel = 'v' + str(SATOCHIP_PROTOCOL_MAJOR_VERSION) + '.' + str(SATOCHIP_PROTOCOL_MINOR_VERSION)
        self.sw_version.setText('<tt>%s' % sw_rel)

        # Card status
        try:
            (response, sw1, sw2, d) = client.cc.card_get_status()
        except Exception as e:
            self.window.show_error(get_user_friendly_error(e, "getting card status"))
            return
            
        if sw1 == 0x90 and sw2 == 0x00:
            # Firmware version
            fw_rel = 'v{}.{}-{}.{}'.format(
                d["protocol_major_version"], d["protocol_minor_version"],
                d["applet_major_version"], d["applet_minor_version"])
            self.fw_version.setText('<tt>%s' % fw_rel)
            
            # Device ID (from authentikey fingerprint)
            try:
                authentikey = client.cc.card_export_authentikey()
                if authentikey:
                    from electrum.crypto import hash_160
                    pubkey = authentikey.get_public_key_bytes(compressed=True)
                    device_id = hash_160(pubkey)[:4].hex()
                    self.device_id_label.setText('<tt>%s' % device_id.upper())
            except:
                self.device_id_label.setText('<tt>(unavailable)')

            # Setup status
            self.setup_done.setText('<tt>%s' % ("yes" if d.get("setup_done") else "no"))
            
            # PIN tries
            pin_tries = d.get("PIN0_remaining_tries", "?")
            self.pin_tries.setText('<tt>%s' % pin_tries)

            # Is seeded?
            if len(response) >= 10:
                is_seeded = d["is_seeded"]
            else:  # for earlier versions
                try:
                    client.cc.card_bip32_get_authentikey()
                    is_seeded = True
                except Exception:
                    is_seeded = False
            self.is_seeded.setText('<tt>%s' % ("yes" if is_seeded else "no"))

            # 2FA status
            needs_2FA = d.get("needs2FA", False)
            self.needs_2FA.setText('<tt>%s' % ("yes" if needs_2FA else "no"))
            
            # Update button states based on 2FA
            self.set_2FA_btn.setVisible(not needs_2FA)
            self.reset_2FA_btn.setVisible(needs_2FA)

            # Secure channel
            needs_SC = d.get("needs_secure_channel", False)
            self.needs_SC.setText('<tt>%s' % ("yes" if needs_SC else "no"))

            # Card label
            try:
                (_dummy, _dummy, _dummy, label) = client.cc.card_get_label()
                if label == "":
                    label = "(none)"
                self.card_label_display.setText('<tt>%s' % label)
            except:
                self.card_label_display.setText('<tt>(error)')

        else:
            # Uninitialized card
            self.fw_version.setText('<tt>(uninitialized)')
            self.device_id_label.setText('<tt>(none)')
            self.setup_done.setText('<tt>no')
            self.needs_2FA.setText('<tt>(uninitialized)')
            self.is_seeded.setText('<tt>no')
            self.needs_SC.setText('<tt>(unknown)')
            self.card_label_display.setText('<tt>(none)')

    def change_pin(self, client):
        _logger.info("In change_pin")
        msg_oldpin = _("Enter the current PIN for your Satochip:")
        msg_newpin = _("Enter a new PIN for your Satochip:")
        msg_confirm = _("Please confirm the new PIN for your Satochip:")
        msg_error = _("The PIN values do not match! Please type PIN again!")
        msg_cancel = _("PIN Change cancelled!")
        
        try:
            (is_pin, oldpin, newpin) = client.PIN_change_dialog(
                msg_oldpin, msg_newpin, msg_confirm, msg_error, msg_cancel)
            if not is_pin:
                return

            oldpin = list(oldpin)
            newpin = list(newpin)
            (response, sw1, sw2) = client.cc.card_change_PIN(0, oldpin, newpin)
            if sw1 == 0x90 and sw2 == 0x00:
                self.window.show_message(_("PIN changed successfully!"))
            else:
                self.window.show_error(_("Failed to change PIN! Error: {}{}").format(hex(sw1), hex(sw2)))
        except WrongPinError as ex:
            tries = getattr(ex, 'pin_left', 'unknown')
            self.window.show_error(_("Wrong PIN! {} tries remaining.").format(tries))
        except Exception as ex:
            self.window.show_error(get_user_friendly_error(ex, "PIN change"))

    def reset_seed(self, client):
        _logger.info("In reset_seed")

        msg = ''.join([
            _("⚠️ WARNING!\n\n"),
            _("You are about to reset the seed of your Satochip.\n"),
            _("This process is irreversible!\n\n"),
            _("Please be sure that your wallet is empty and that you have a backup of the seed as a precaution.\n\n"),
            _("To proceed, enter the PIN for your Satochip:")
        ])
        password = self.reset_seed_dialog(msg)
        if password is None:
            return
        pin = list(password.encode('utf8'))

        # if 2FA is enabled, get challenge-response
        hmac = []
        if client.cc.needs_2FA is None:
            (_dummy, _dummy, _dummy, d) = client.cc.card_get_status()
        if client.cc.needs_2FA:
            authentikeyx = bytearray(client.cc.parser.authentikey_coordx).hex()
            import json
            msg = {'action': "reset_seed", 'authentikeyx': authentikeyx}
            msg = json.dumps(msg)
            (id_2FA, msg_out) = client.cc.card_crypt_transaction_2FA(msg, True)
            d = {'msg_encrypt': msg_out, 'id_2FA': id_2FA}

            self.window.show_message(
                _('2FA request sent! Approve or reject request on your second device.'))
            server_2FA = self.config.get("satochip_2FA_server", default=SERVER_LIST[0])
            Satochip2FA.do_challenge_response(d, server_name=server_2FA)
            
            try:
                reply_encrypt = d['reply_encrypt']
            except Exception:
                self.window.show_error(_("No response received from 2FA device!"))
                return
            reply_decrypt = client.cc.card_crypt_transaction_2FA(reply_encrypt, False)
            _logger.info("challenge:response= " + reply_decrypt)
            chalresponse = reply_decrypt.split(":")[1]
            hmac = list(bytes.fromhex(chalresponse))

        try:
            (response, sw1, sw2) = client.cc.card_reset_seed(pin, hmac)
            if sw1 == 0x90 and sw2 == 0x00:
                self.window.show_message(_(
                    "Seed reset successfully!\n"
                    "You should close this wallet and launch the wizard to generate a new wallet."))
            elif sw1 == 0x9c and sw2 == 0x0b:
                self.window.show_error(_("Failed: request rejected by 2FA device."))
            else:
                self.window.show_error(_("Failed to reset seed. Error: {}{}").format(hex(sw1), hex(sw2)))
        except Exception as ex:
            self.window.show_error(get_user_friendly_error(ex, "seed reset"))

    def reset_seed_dialog(self, msg):
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

    def set_2FA(self, client):
        if not client.cc.needs_2FA:
            use_2FA = client.handler.yes_no_question(MSG_USE_2FA)
            if use_2FA:
                is_ok = client.verify_PIN()
                if not is_ok:
                    self.window.show_error(_("Action cancelled by user"))
                    return

                secret_2FA = urandom(20)
                secret_2FA_hex = secret_2FA.hex()
                try:
                    help_txt = _("Scan the QR-code with your Satochip-2FA app and make a backup of this secret: {}"
                                ).format(secret_2FA_hex)
                    d = WindowModalDialog(self.window, title=_("Setup 2FA"))
                    vbox = QVBoxLayout()
                    vbox.addWidget(WWLabel(help_txt))
                    vbox.addWidget(QRCodeWidget(secret_2FA_hex))
                    vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
                    d.setLayout(vbox)
                    if d.exec():
                        amount_limit = 0  # always use
                        (response, sw1, sw2) = client.cc.card_set_2FA_key(secret_2FA, amount_limit)
                        if sw1 != 0x90 or sw2 != 0x00:
                            self.window.show_error(_("Unable to setup 2FA. Error: {}{}"
                                                    ).format(hex(sw1), hex(sw2)))
                        else:
                            self.window.show_message(_("2FA enabled successfully!"))
                    else:
                        self.window.show_message(_("2FA setup cancelled by user."))
                except Exception as e:
                    self.window.show_error(get_user_friendly_error(e, "2FA setup"))

    def reset_2FA(self, client):
        if client.cc.needs_2FA:
            is_ok = client.verify_PIN()
            if not is_ok:
                self.window.show_error(_("Action cancelled by user"))
                return

            import json
            msg = {'action': "reset_2FA"}
            msg = json.dumps(msg)
            (id_2FA, msg_out) = client.cc.card_crypt_transaction_2FA(msg, True)
            d = {'msg_encrypt': msg_out, 'id_2FA': id_2FA}

            self.window.show_message(
                _('2FA request sent! Approve or reject request on your second device.'))
            server_2FA = self.config.get("satochip_2FA_server", default=SERVER_LIST[0])
            Satochip2FA.do_challenge_response(d, server_name=server_2FA)
            
            try:
                reply_encrypt = d['reply_encrypt']
            except Exception:
                self.window.show_error(_("No response received from 2FA device!"))
                return
            reply_decrypt = client.cc.card_crypt_transaction_2FA(reply_encrypt, False)
            chalresponse = reply_decrypt.split(":")[1]
            hmac = list(bytes.fromhex(chalresponse))

            try:
                (response, sw1, sw2) = client.cc.card_reset_2FA_key(hmac)
                if sw1 == 0x90 and sw2 == 0x00:
                    client.cc.needs_2FA = False
                    self.window.show_message(_("2FA disabled successfully!"))
                elif sw1 == 0x9c and sw2 == 0x17:
                    self.window.show_error(_("You must reset the seed first before disabling 2FA."))
                else:
                    self.window.show_error(_("Failed to disable 2FA. Error: {}{}").format(hex(sw1), hex(sw2)))
            except Exception as ex:
                self.window.show_error(get_user_friendly_error(ex, "2FA reset"))
        else:
            self.window.show_error(_("2FA is already disabled!"))

    def change_2FA_server(self, client):
        help_txt = _("Select the 2FA server to use for authentication:")
        option_name = "satochip_2FA_server"
        options = SERVER_LIST
        title = _("Select 2FA Server")
        d = SelectOptionsDialog(option_name=option_name, options=options,
                                parent=None, title=title, help_text=help_txt, config=self.config)
        d.exec()

    def verify_card(self, client):
        is_ok = client.verify_PIN()
        if not is_ok:
            return

        is_authentic, txt_ca, txt_subca, txt_device, txt_error = self.card_verify_authenticity(client)

        # Wrap text for display
        def wrap_text(txt, width=120):
            return '\n'.join(textwrap.fill(line, width, subsequent_indent="\t") for line in txt.splitlines())

        txt_ca = wrap_text(txt_ca)
        txt_subca = wrap_text(txt_subca)
        txt_device = wrap_text(txt_device)

        if is_authentic:
            txt_result = _('✓ Card authenticated successfully!')
        else:
            txt_result = ''.join([
                _('✗ Could not authenticate this card!\n'),
                _('Reason: {}\n\n').format(txt_error),
                _('If you did not load this card yourself, be extremely careful!\n'),
                _('Contact support@satochip.io to report a suspicious device.')
            ])
        
        d = DeviceCertificateDialog(
            parent=None,
            title=_("Satochip Certificate Chain"),
            is_authentic=is_authentic,
            txt_summary=txt_result,
            txt_ca=txt_ca,
            txt_subca=txt_subca,
            txt_device=txt_device,
        )
        d.exec()

    def card_verify_authenticity(self, client):
        cert_pem = ""
        txt_error = ""
        try:
            cert_pem = client.cc.card_export_perso_certificate()
            _logger.info('Cert PEM: ' + str(cert_pem))
        except CardError:
            txt_error = _("Feature unsupported. Requires Satochip v0.12 or higher.")
        except CardNotPresentError:
            txt_error = _("No card found! Please insert card.")
        except UnexpectedSW12Error as ex:
            txt_error = _("Certificate export error: {}").format(str(ex))

        if cert_pem == "(empty)":
            txt_error = _("Card has not been personalized.")

        if txt_error:
            return False, "(empty)", "(empty)", "(empty)", txt_error

        from pysatochip.certificate_validator import CertificateValidator
        validator = CertificateValidator()
        is_valid_chain, device_pubkey, txt_ca, txt_subca, txt_device, txt_error = \
            validator.validate_certificate_chain(cert_pem, client.cc.card_type)
        if not is_valid_chain:
            return False, txt_ca, txt_subca, txt_device, txt_error

        is_valid_chalresp, txt_error = client.cc.card_challenge_response_pki(device_pubkey)
        return is_valid_chalresp, txt_ca, txt_subca, txt_device, txt_error

    def change_card_label(self, client):
        msg = _('Enter a label for your Satochip (max 64 characters):')

        is_ok = client.verify_PIN()
        if not is_ok:
            return

        label = self.change_card_label_dialog(client, msg)
        if label is None:
            self.window.show_message(_("Operation cancelled."))
            return

        try:
            (response, sw1, sw2) = client.cc.card_set_label(label)
            if sw1 == 0x90 and sw2 == 0x00:
                self.window.show_message(_("Card label changed successfully!"))
                # Refresh display
                self.card_label_display.setText('<tt>%s' % (label if label else '(none)'))
            elif sw1 == 0x6D and sw2 == 0x00:
                self.window.show_error(_("This card does not support labels (requires v0.12+)."))
            else:
                self.window.show_error(_("Failed to change label. Error: {}{}").format(hex(sw1), hex(sw2)))
        except Exception as ex:
            self.window.show_error(get_user_friendly_error(ex, "label change"))

    def change_card_label_dialog(self, client, msg):
        parent = self.top_level_window()
        while True:
            label = line_dialog(
                parent=parent,
                title=_("Enter Label"),
                label=msg,
                ok_label=_("OK"),
            )
            if label is None or len(label.encode('utf-8')) <= 64:
                return label
            self.window.show_error(_("Label must be 64 characters or less!"))

class SelectOptionsDialog(WindowModalDialog):

    def __init__(
            self,
            *,
            option_name,
            options=None,
            parent=None,
            title="",
            help_text=None,
            config: SimpleConfig,
    ):
        WindowModalDialog.__init__(self, parent, title)
        self.config = config

        vbox = QVBoxLayout()
        if help_text:
            text_label = WWLabel()
            text_label.setText(help_text)
            vbox.addWidget(text_label)

        def set_option():
            _logger.info(f"New 2FA server: {options_combo.currentText()}")
            # save in config
            config.set_key(option_name, options_combo.currentText(), save=True)
            _logger.info("config changed!")

        default = config.get(option_name, default=SERVER_LIST[0])
        options_combo = QComboBox()
        options_combo.addItems(options)
        options_combo.setCurrentText(default)
        options_combo.currentIndexChanged.connect(set_option)
        vbox.addWidget(options_combo)

        hbox = QHBoxLayout()
        hbox.addStretch(1)

        b = QPushButton(_("Ok"))
        hbox.addWidget(b)
        b.clicked.connect(self.accept)
        b.setDefault(True)

        vbox.addLayout(hbox)
        self.setLayout(vbox)

        # note: the word-wrap on the text_label is causing layout sizing issues.
        #       see https://stackoverflow.com/a/25661985 and https://bugreports.qt.io/browse/QTBUG-37673
        #       workaround:
        self.setMinimumSize(self.sizeHint())


class DeviceCertificateDialog(WindowModalDialog):

    def __init__(
            self,
            *,
            parent=None,
            title="",
            is_authentic,
            txt_summary="",
            txt_ca="",
            txt_subca="",
            txt_device="",
    ):
        WindowModalDialog.__init__(self, parent, title)

        # super(QWidget, self).__init__(parent)
        self.layout = QVBoxLayout(self)

        # add summary text
        self.summary = QLabel(txt_summary)
        if is_authentic:
            self.summary.setStyleSheet(ColorScheme.GREEN.as_stylesheet())
        else:
            self.summary.setStyleSheet(ColorScheme.RED.as_stylesheet())
        self.summary.setWordWrap(True)
        self.layout.addWidget(self.summary)

        # Initialize tab screen
        self.tabs = QTabWidget()
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab3 = QWidget()
        self.tabs.resize(300, 200)

        # Add tabs
        self.tabs.addTab(self.tab1, "RootCA")
        self.tabs.addTab(self.tab2, "SubCA")
        self.tabs.addTab(self.tab3, "Device")

        # Create first tab
        self.tab1.layout = QVBoxLayout(self)
        self.cert1 = QLabel(txt_ca)
        self.cert1.setWordWrap(True)
        self.tab1.layout.addWidget(self.cert1)
        self.tab1.setLayout(self.tab1.layout)

        # Create second tab
        self.tab2.layout = QVBoxLayout(self)
        self.cert2 = QLabel(txt_subca)
        self.cert2.setWordWrap(True)
        self.tab2.layout.addWidget(self.cert2)
        self.tab2.setLayout(self.tab2.layout)

        # Create third tab
        self.tab3.layout = QVBoxLayout(self)
        self.cert3 = QLabel(txt_device)
        self.cert3.setWordWrap(True)
        self.tab3.layout.addWidget(self.cert3)
        self.tab3.setLayout(self.tab3.layout)

        # Add tabs to widget
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)


##########################
#    Setup PIN  wizard   #
##########################

def clean_text(widget):
    text = widget.toPlainText().strip()
    return ' '.join(text.split())


class SatochipSetupLayout(QVBoxLayout):
    validChanged = pyqtSignal([bool], arguments=['valid'])

    def __init__(self, device):
        _logger.info("[SatochipSetupLayout] __init__()")
        QVBoxLayout.__init__(self)

        vbox = QVBoxLayout()

        # intro
        msg_setup = WWLabel(
            _("Please take a moment to set up your Satochip. This must be done only once."))
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

        # PIN validation
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
        _logger.info("[SatochipSetupLayout] get_settings()")
        return self.pw.text()


class WCSatochipSetupParams(WalletWizardComponent):
    def __init__(self, parent, wizard):
        _logger.info("[WCSatochipSetupParams] __init__()")
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_('Satochip Setup'))
        self.plugins = wizard.plugins
        self._busy = True

    def on_ready(self):
        _logger.info("[WCSatochipSetupParams] on_ready()")
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        _name, _info = current_cosigner['hardware_device']
        self.settings_layout = SatochipSetupLayout(_info.device.id_)
        self.settings_layout.validChanged.connect(
            self.on_settings_valid_changed)
        self.layout().addLayout(self.settings_layout)
        self.layout().addStretch(1)

        self.valid = True  # debug
        self.busy = False

    def on_settings_valid_changed(self, is_valid: bool):
        _logger.info(
            f"[WCSatochipSetupParams] on_settings_valid_changed() is_valid: {is_valid}")
        self.valid = is_valid

    def apply(self):
        _logger.info("[WCSatochipSetupParams] apply()")
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        current_cosigner['satochip_setup_settings'] = self.settings_layout.get_settings(
        )


class WCSatochipSetup(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_('Satochip Setup'))
        _logger.info('[WCSatochipSetup] __init__()')  # debugsatochip

        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin('satochip')

        self.layout().addWidget(WWLabel('Done'))

        self._busy = True

    def on_ready(self):
        _logger.info('[WCSatochipSetup] on_ready()')  # debugsatochip
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        settings = current_cosigner['satochip_setup_settings']
        # method = current_cosigner['satochip_init']
        _name, _info = current_cosigner['hardware_device']
        device_id = _info.device.id_
        # debugsatochip
        _logger.info(f'[WCSatochipSetup] on_ready() device_id: {device_id}')

        client = self.plugins.device_manager.client_by_id(
            device_id, scan_now=False)
        client.handler = self.plugin.create_handler(self.wizard)

        def initialize_device_task(settings, device_id, client):
            try:
                # self.plugin._initialize_device(settings, method, device_id, handler)
                self.plugin._setup_device(settings, device_id, client)
                _logger.info(
                    '[WCSatochipSetup] initialize_device_task() Done initialize device')
                self.valid = True
                self.wizard.requestNext.emit()  # triggers Next GUI thread from event loop
            except Exception as e:
                self.valid = False
                self.error = str(e)
                _logger.exception(str(e))
            finally:
                self.busy = False

        t = threading.Thread(
            target=initialize_device_task,
            args=(settings, device_id, client),
            daemon=True)
        t.start()

    def apply(self):
        pass

##########################
#   Import seed wizard   #
##########################


class WCSeedMethodChoice(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(self, parent, wizard, title=_('Satochip needs a seed'))

        intro = WWLabel('\n'.join(MSG_SEED_IMPORT))
        intro.setWordWrap(True)
        self.layout().addWidget(intro)

        message = _('How do you want to provide a seed for this Satochip card?')
        choices = [
            ChoiceItem(key='import', label=_('I already have a seed phrase')),
            ChoiceItem(key='generate', label=_('Generate a new BIP39 seed phrase')),
        ]
        self.choice_w = ChoiceWidget(message=message, choices=choices, default_key='import')
        self.layout().addWidget(self.choice_w)
        self.layout().addStretch(1)

        self._valid = True

    def apply(self):
        self.wizard_data['satochip_seed_method'] = self.choice_w.selected_key


class WCSatochipGenerateSeed(WalletWizardComponent):
    """Display a freshly generated BIP39 seed phrase for the user to write down.

    Mirrors Electrum's WCCreateSeed pattern:
    - Defers generation to on_ready() via QTimer so the page renders first.
    - Uses Electrum's own SeedWidget (read-only mode) for display, which
      shows the words in the standard format and provides an "Options" button
      for the passphrase/extension checkbox.
    - If the user enables "Extend seed with custom words", seed_extend is set
      True and the wizard routes through satochip_have_ext (WCEnterExt) before
      importing — exactly the same path as the "import" branch.
    """

    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_('Your new BIP39 seed phrase')
        )
        self._seed = None
        self.seed_widget = None

        # Word-count selector + regenerate button — built before on_ready so
        # they are visible immediately while the seed generates.
        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel(_('Seed length:')))
        self.radio_12 = QRadioButton(_('12 words'))
        self.radio_24 = QRadioButton(_('24 words'))
        self.radio_24.setChecked(True)
        # Connect both buttons: whichever transitions to checked=True triggers a refresh.
        # Without connecting radio_24, clicking "24 words" only fires radio_12.toggled(False)
        # which the handler ignores, so no new seed would be generated.
        self.radio_12.toggled.connect(self._on_length_changed)
        self.radio_24.toggled.connect(self._on_length_changed)
        length_layout.addWidget(self.radio_12)
        length_layout.addWidget(self.radio_24)
        self.regen_btn = QPushButton(_('Regenerate'))
        self.regen_btn.clicked.connect(self._on_regenerate_clicked)
        length_layout.addWidget(self.regen_btn)
        length_layout.addStretch(1)
        self.layout().addLayout(length_layout)

        self._busy = True  # stays busy until seed is generated in on_ready

    def on_ready(self):
        # Defer by one event-loop tick (same as WCCreateSeed) so the
        # wizard page is fully rendered before we generate entropy.
        QTimer.singleShot(1, self._create_seed)

    # ------------------------------------------------------------------
    # Internal helpers

    def _current_length(self) -> int:
        return 12 if self.radio_12.isChecked() else 24

    def _create_seed(self):
        self.busy = True
        self._seed = _generate_bip39_mnemonic(self._current_length())

        self.seed_widget = SeedWidget(
            title=_('Your wallet generation seed is:'),
            seed=self._seed,
            options=['ext', 'bip39'],
            msg=True,
            parent=self,
            config=self.wizard.config,
        )
        self.layout().addWidget(self.seed_widget)
        self.layout().addStretch(1)

        self.busy = False
        self.valid = True  # same pattern as WCCreateSeed

    def _refresh_seed(self):
        """Generate a new seed and update the SeedWidget display."""
        self._seed = _generate_bip39_mnemonic(self._current_length())
        if self.seed_widget is not None:
            self.seed_widget.seed_e.setText(self._seed)

    def _on_length_changed(self, checked: bool) -> None:
        # Each radio emits toggled(True) when selected and toggled(False) when
        # deselected.  We only act on the newly-selected radio to avoid
        # generating two seeds per click.
        if checked:
            self._refresh_seed()

    def _on_regenerate_clicked(self) -> None:
        self._refresh_seed()

    # ------------------------------------------------------------------

    def apply(self):
        cosigner_data = self.wizard.current_cosigner(self.wizard_data)
        cosigner_data['seed'] = self._seed
        cosigner_data['seed_type'] = 'bip39'
        cosigner_data['seed_variant'] = 'bip39'
        # SeedWidget.is_ext is True when user enabled "Extend seed with custom words"
        # via the Options button.  WCEnterExt will then populate seed_extra_words.
        cosigner_data['seed_extend'] = bool(self.seed_widget and self.seed_widget.is_ext)


class WCSeedSuccess(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(self, parent, wizard, title=_('Success!'))

    def on_ready(self):
        w_icon = QLabel()
        w_icon.setPixmap(QPixmap(icon_path('confirmed.png')).scaledToWidth(48, mode=Qt.TransformationMode.SmoothTransformation))
        w_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label = WWLabel(_("Seed imported successfully!"))
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout().addStretch(1)
        self.layout().addWidget(w_icon)
        self.layout().addWidget(label)
        self.layout().addStretch(1)
        # self.layout().addWidget(WWLabel("Seed imported successfully!")
        # self.layout().addStretch(1)
        self._valid = True

    def apply(self):
        pass


class WCSatochipImportSeed(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_('Satochip Setup'))
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin('satochip')

        self.layout().addWidget(WWLabel('Done'))

        self._busy = True

    def on_ready(self):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)

        settings = current_cosigner['seed_type'], current_cosigner['seed'], current_cosigner['seed_extra_words'] if current_cosigner['seed_extend'] else ''

        _name, _info = current_cosigner['hardware_device']
        device_id = _info.device.id_
        client = self.plugins.device_manager.client_by_id(
            device_id, scan_now=False)
        client.handler = self.plugin.create_handler(self.wizard)

        def initialize_device_task(settings, device_id, handler):
            try:
                self.plugin._import_seed(settings, device_id, handler)
                _logger.info(
                    '[WCSatochipImportSeed] initialize_device_task() Done initialize device')
                self.valid = True
                self.wizard.requestNext.emit()  # triggers Next GUI thread from event loop
            except Exception as e:
                self.valid = False
                self.error = str(e)
                _logger.exception(str(e))
            finally:
                self.busy = False

        t = threading.Thread(
            target=initialize_device_task,
            args=(settings, device_id, client.handler),
            daemon=True)
        t.start()

    def apply(self):
        pass


instrument_module_function_entries(_logger, globals(), __name__)
