'''Satochip Qt plugin: settings dialog, wizard components, and handler.'''

import hashlib
import secrets
import threading
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QSlider,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from electrum.i18n import _
from electrum.logging import get_logger, Logger
from electrum.plugin import hook
from electrum.util import ChoiceItem

try:
    from electrum.hw_wallet.qt import QtHandlerBase, QtPluginBase
    from electrum.hw_wallet.plugin import only_hook_if_libraries_available
except ImportError:
    from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
    from ..hw_wallet.plugin import only_hook_if_libraries_available

from electrum.gui.qt.util import (
    Buttons,
    CancelButton,
    CloseButton,
    OkButton,
    PasswordLineEdit,
    WindowModalDialog,
    ColorScheme,
    WWLabel,
    icon_path,
    line_dialog,
)

from electrum.gui.qt.util import ChoiceWidget
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


def _set_error_later(widget, msg):
    QTimer.singleShot(0, lambda: setattr(widget, 'error', msg))


def _set_busy_later(widget, val):
    QTimer.singleShot(0, lambda: setattr(widget, 'busy', val))


RECOMMEND_PIN = _(
    'PIN protection is strongly recommended. A PIN is your only protection '
    'against someone stealing your Bitcoin if they obtain physical '
    'access to your Satochip.'
)


class TypedConfirmationDialog(WindowModalDialog):
    """Modal that requires the user to type an exact phrase before the
    destructive button enables. Used to gate irreversible operations
    like wiping a Satochip. Prevents muscle-memory or accidental clicks.

    Returns True from run() if the user typed the phrase and clicked
    the action button; False if cancelled.
    """

    _DESTRUCTIVE_BTN_STYLE = (
        'QPushButton { background-color: #c62828; color: white; '
        'font-weight: bold; padding: 6px 18px; border-radius: 4px; }'
        'QPushButton:disabled { background-color: #555; color: #999; }'
    )

    def __init__(
        self,
        parent,
        *,
        title: str,
        action_label: str,
        confirm_phrase: str,
        warnings: list,
        balance_warning: str | None = None,
    ):
        WindowModalDialog.__init__(self, parent, title)
        self._confirm_phrase = confirm_phrase

        vbox = QVBoxLayout(self)

        header = QLabel(
            "<b><span style='color:{}'>{}</span></b>".format(
                ColorScheme.RED.as_color().name(),
                _('This action cannot be undone'),
            )
        )
        vbox.addWidget(header)

        for w in warnings:
            vbox.addWidget(QLabel('\u2022 ' + w))

        if balance_warning:
            bal_lbl = QLabel(
                "<span style='color:{}'>{}</span>".format(
                    ColorScheme.RED.as_color().name(),
                    balance_warning,
                )
            )
            bal_lbl.setWordWrap(True)
            vbox.addWidget(bal_lbl)

        vbox.addSpacing(12)

        phrase_lbl = QLabel(
            _('Type {phrase} to confirm:').format(
                phrase='<tt><b>{}</b></tt>'.format(confirm_phrase)
            )
        )
        vbox.addWidget(phrase_lbl)

        self._lineedit = QLineEdit()
        self._lineedit.setPlaceholderText(confirm_phrase)
        self._lineedit.textChanged.connect(self._on_text_changed)
        vbox.addWidget(self._lineedit)

        self._confirm_btn = QPushButton(action_label)
        self._confirm_btn.setStyleSheet(self._DESTRUCTIVE_BTN_STYLE)
        self._confirm_btn.setEnabled(False)
        self._confirm_btn.clicked.connect(self.accept)

        self._cancel_btn = CancelButton(self)
        self._cancel_btn.setDefault(True)

        vbox.addLayout(Buttons(self._cancel_btn, self._confirm_btn))

    def _on_text_changed(self, text):
        self._confirm_btn.setEnabled(text.strip() == self._confirm_phrase)

    def run(self) -> bool:
        return self.exec() == QDialog.DialogCode.Accepted


class CardSwapDialog(WindowModalDialog):
    """Full-screen-ish modal that guides the user through card removal and
    reinsertion during a factory reset. Uses a QTimer to poll card presence
    (via ``smartcard``) and displays:
      - Phase REMOVAL: 'Remove the card' with a pulsing animation
      - Phase INSERTION: 'Insert the card' with a countdown timer
      - Phase DETECTED: brief 'Card detected' confirmation, then auto-closes
    Returns True from run() if the swap completed; False if cancelled.
    """

    _POLL_INTERVAL_MS = 500
    _COUNTDOWN_SECS = 120
    _DETECTED_CLOSE_MS = 1500

    _STATE_REMOVAL = 'removal'
    _STATE_INSERTION = 'insertion'
    _STATE_DETECTED = 'detected'

    _STYLE_SHEET = """
        QLabel { color: #eee; }
        QLabel#phase-icon { font-size: 64px; }
        QLabel#phase-title { font-size: 24px; font-weight: bold; }
        QLabel#phase-subtitle { font-size: 14px; color: #aaa; }
        QLabel#countdown { font-size: 48px;
            font-weight: bold; color: #ffab40; }
        QLabel#step-indicator { font-size: 12px; color: #888; }
        QPushButton { padding: 10px 24px; }
    """
    _BG = '#1e1e2e'

    def __init__(
        self,
        parent,
        *,
        remaining_steps: int = 0,
        total_steps: int = 0,
    ):
        WindowModalDialog.__init__(self, parent, _('Card Swap Required'))
        self.setWindowTitle(_('Card Swap Required'))
        self.setMinimumSize(420, 340)
        self.setStyleSheet(
            f'QDialog {{ background-color: {self._BG}; }} {self._STYLE_SHEET}'
        )

        self._phase = self._STATE_REMOVAL
        self._remaining_steps = remaining_steps
        self._total_steps = total_steps
        self._countdown = self._COUNTDOWN_SECS
        self._swap_complete = False

        vbox = QVBoxLayout(self)
        vbox.setSpacing(12)

        self._step_label = QLabel()
        self._step_label.setObjectName('step-indicator')
        self._step_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vbox.addWidget(self._step_label)
        self._refresh_step_label()

        vbox.addStretch(1)

        self._icon_label = QLabel('\u23cf')
        self._icon_label.setObjectName('phase-icon')
        self._icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vbox.addWidget(self._icon_label)

        self._title_label = QLabel()
        self._title_label.setObjectName('phase-title')
        self._title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vbox.addWidget(self._title_label)

        self._subtitle_label = QLabel()
        self._subtitle_label.setObjectName('phase-subtitle')
        self._subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._subtitle_label.setWordWrap(True)
        vbox.addWidget(self._subtitle_label)

        self._countdown_label = QLabel('')
        self._countdown_label.setObjectName('countdown')
        self._countdown_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vbox.addWidget(self._countdown_label)

        vbox.addStretch(1)

        self._cancel_btn = CancelButton(self)
        cancel_layout = QHBoxLayout()
        cancel_layout.addStretch(1)
        cancel_layout.addWidget(self._cancel_btn)
        cancel_layout.addStretch(1)
        vbox.addLayout(cancel_layout)

        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll)

        self._refresh_phase()

    def _refresh_step_label(self):
        if self._total_steps > 0:
            self._step_label.setText(
                _('Step {current} of {total}').format(
                    current=self._total_steps - self._remaining_steps + 1,
                    total=self._total_steps,
                )
            )
        else:
            self._step_label.setVisible(False)

    def _refresh_phase(self):
        if self._phase == self._STATE_REMOVAL:
            self._icon_label.setText('\u23cf')
            self._title_label.setText(_('Remove the card'))
            self._subtitle_label.setText(
                _(
                    'Pull the Satochip from the reader, '
                    'then wait for the prompt.'
                )
            )
            self._countdown_label.setText('')
        elif self._phase == self._STATE_INSERTION:
            self._icon_label.setText('\u23cf')
            self._title_label.setText(_('Insert the card'))
            self._subtitle_label.setText(
                _('Place the Satochip back in the reader.')
            )
            self._countdown_label.setText(str(self._countdown))
        elif self._phase == self._STATE_DETECTED:
            self._icon_label.setText('\u2705')
            self._title_label.setText(_('Card detected'))
            self._subtitle_label.setText(_('Reconnecting\u2026'))
            self._countdown_label.setText('')

    @staticmethod
    def _is_card_present() -> bool:
        try:
            from smartcard.System import readers
            rs = readers()
            for r in rs:
                try:
                    conn = r.createConnection()
                    conn.connect()
                    conn.disconnect()
                    return True
                except Exception:
                    continue
            return False
        except Exception:
            return False

    def _poll(self):
        present = self._is_card_present()

        if self._phase == self._STATE_REMOVAL:
            if not present:
                self._phase = self._STATE_INSERTION
                self._countdown = self._COUNTDOWN_SECS
                self._refresh_phase()

        elif self._phase == self._STATE_INSERTION:
            if present:
                self._phase = self._STATE_DETECTED
                self._refresh_phase()
                QTimer.singleShot(self._DETECTED_CLOSE_MS, self.accept)
            else:
                self._countdown -= 1
                self._countdown_label.setText(str(self._countdown))
                if self._countdown <= 0:
                    self._poll_timer.stop()
                    self.reject()

        elif self._phase == self._STATE_DETECTED:
            pass

    def run(self) -> bool:
        self._poll_timer.start(self._POLL_INTERVAL_MS)
        result = self.exec()
        self._poll_timer.stop()
        self._swap_complete = result == QDialog.DialogCode.Accepted
        return self._swap_complete


MSG_SEED_IMPORT = [
    _(
        'Your Satochip is currently unseeded. '
        'Import a BIP39 seed to use it (select BIP39 on the next screen). '
        'Electrum seeds are not supported by hardware wallets.'
    ),
]

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class Satochip_Handler(QtHandlerBase):
    '''Qt handler for Satochip device interactions (PIN dialog, messages).'''

    MESSAGE_DIALOG_TITLE = _('Satochip Status')

    def __init__(self, win, device):
        super().__init__(win, device)


class Plugin(SatochipPlugin, QtPluginBase):
    icon_unpaired = 'satochip_unpaired.png'
    icon_paired = 'satochip.png'

    def create_handler(self, window):
        return Satochip_Handler(window, self.device)

    @only_hook_if_libraries_available
    @hook
    def show_settings_dialog(self, window, keystore):
        def connect():
            device_id = self.choose_device(window, keystore)
            return device_id

        def show_dialog(device_id):
            if device_id:
                SatochipSettingsDialog(
                    window, self, keystore, device_id
                ).exec()

        keystore.thread.add(connect, on_success=show_dialog)

    @only_hook_if_libraries_available
    @hook
    def receive_menu(self, menu, addrs, wallet):
        if len(addrs) != 1:
            return
        self._add_menu_action(menu, addrs[0], wallet)

    @only_hook_if_libraries_available
    @hook
    def transaction_dialog_address_menu(self, menu, addr, wallet):
        self._add_menu_action(menu, addr, wallet)

    @only_hook_if_libraries_available
    @hook
    def init_wallet_wizard(self, wizard: 'QENewWalletWizard'):
        self.extend_wizard(wizard)

    def extend_wizard(self, wizard: 'QENewWalletWizard'):
        super().extend_wizard(wizard)
        views = {
            'satochip_start': {'gui': WCScriptAndDerivation},
            'satochip_xpub': {'gui': WCHWXPub},
            'satochip_not_setup': {'gui': WCSatochipSetupParams},
            'satochip_do_setup': {'gui': WCSatochipSetup},
            'satochip_not_seeded': {
                'gui': WCSeedMethodChoice,
            },
            'satochip_generate_seed': {
                'gui': WCSatochipGenerateSeed,
            },
            'satochip_have_seed': {
                'gui': WCHaveSeed,
                'next': lambda d: self._next_seed_ext(wizard, d),
                'params': {'seed_options': ['ext', 'bip39']},
            },
            'satochip_have_ext': {
                'gui': WCEnterExt,
                'next': 'satochip_import_seed',
            },
            'satochip_import_seed': {
                'gui': WCSatochipImportSeed,
            },
            'satochip_success_seed': {
                'gui': WCSeedSuccess,
            },
            'satochip_unlock': {'gui': WCSatochipUnlock},
            'satochip_blocked': {
                'gui': WCSatochipBlocked,
                'next': 'choose_hardware_device',
            },
            'satochip_wrong_card': {
                'gui': WCSatochipWrongCard,
                'next': 'choose_hardware_device',
            },
            'satochip_recover_setup': {
                'gui': WCSatochipRecoverSetup,
            },
            'satochip_recover_seed': {
                'gui': WCSatochipRecoverSeed,
                'next': 'satochip_unlock',
            },
        }
        wizard.navmap_merge(views)


class SatochipSettingsDialog(WindowModalDialog):
    """Tabbed settings dialog for Satochip device.

    Tab 1 - Information: Device status, firmware version, card info
    Tab 2 - Settings: Label edit, PIN change, session timeout
    Tab 3 - Advanced: Factory reset, seed reset
    """

    _MIN_PROTOCOL_VERSION = (0 << 8) | 12

    def __init__(self, window, plugin, keystore, device_id):
        title = _('{} Settings').format(plugin.device)
        super().__init__(window, title)
        self.setMaximumWidth(540)

        self.devmgr = plugin.device_manager()
        self.config = self.devmgr.config
        self.thread = keystore.thread
        self.window = window
        self.device_id = device_id
        self._setup_done = False

        tabs = QTabWidget(self)
        tabs.addTab(self._build_info_tab(), _('Information'))
        tabs.addTab(self._build_settings_tab(), _('Settings'))
        tabs.addTab(self._build_advanced_tab(), _('Advanced'))

        dialog_vbox = QVBoxLayout(self)
        dialog_vbox.addWidget(tabs)
        dialog_vbox.addLayout(Buttons(CloseButton(self)))

        self.thread.add(
            self._fetch_card_info,
            on_success=self.show_values,
            on_error=self.show_placeholders,
        )

    def _fetch_client(self):
        client = self.devmgr.client_by_id(self.device_id)
        if not client:
            raise RuntimeError('Device not connected')
        return client

    def _fetch_card_info(self):
        client = self._fetch_client()
        info = {}
        try:
            (response, sw1, sw2, d) = client.cc.card_get_status()
        except Exception as e:
            info['error'] = str(e)
            return info

        if sw1 != 0x90 or sw2 != 0x00:
            return info

        info['fw_rel'] = 'v{}.{}-{}.{}'.format(
            d['protocol_major_version'],
            d['protocol_minor_version'],
            d['applet_major_version'],
            d['applet_minor_version'],
        )
        info['protocol_version'] = d.get('protocol_version', 0)
        info['pin_tries'] = d.get('PIN0_remaining_tries', '?')
        info['setup_done'] = d.get('setup_done', False)

        if len(response) >= 10:
            info['is_seeded'] = d['is_seeded']
        else:
            try:
                client.cc.card_bip32_get_authentikey()
                info['is_seeded'] = True
            except Exception:
                info['is_seeded'] = False

        try:
            device_id_str = getattr(client.cc, 'UID_SHA1', None)
            if device_id_str:
                info['device_id'] = device_id_str[:8].upper()
            else:
                device_id_str = client.get_authentikey_fingerprint()
                if device_id_str:
                    info['device_id'] = device_id_str.upper()
        except Exception:
            _logger.debug('Could not fetch device ID', exc_info=True)

        try:
            (_d1, _d2, _d3, label) = client.cc.card_get_label()
            info['label'] = label if label and label.strip() else ''
        except Exception:
            _logger.debug('card_get_label failed', exc_info=True)

        reader_full = getattr(client, 'reader_full_name', None)
        if reader_full:
            from .satochip import _classify_reader
            cls = _classify_reader(reader_full)
            info['reader'] = f'{reader_full}, {cls}' if cls else reader_full

        try:
            info['taproot'] = client.supports_taproot()
        except Exception:
            info['taproot'] = False

        info['nfc_policy'] = getattr(client.cc, 'nfc_policy', None)
        info['schnorr_policy'] = getattr(
            client.cc, 'feature_schnorr_policy', None
        )

        return info

    def _invoke_client(self, method, *, unpair_after=False, on_complete=None):
        def do_action(client):
            getattr(self, method)(client)
            if unpair_after:
                self.devmgr.unpair_id(self.device_id)
            if on_complete:
                on_complete()

        self.thread.add(self._fetch_client, on_success=do_action)

    def _build_info_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        grid = QGridLayout()
        grid.setColumnStretch(2, 1)

        header = QLabel(
            "<center><span style='font-size: x-large'>Satochip</span>"
            "<br><a href='https://satochip.io'>satochip.io</a></center>"
        )
        header.setTextInteractionFlags(
            Qt.TextInteractionFlag.LinksAccessibleByMouse
        )
        header.setOpenExternalLinks(True)
        grid.addWidget(header, 0, 0, 1, 2, Qt.AlignmentFlag.AlignHCenter)

        y = 2
        for member_name, label_text in [
            ('fw_version', _('Applet Version:')),
            ('device_id_label', _('Device ID:')),
            ('card_status', _('Card Status:')),
            ('pin_tries', _('PIN tries remaining:')),
            ('reader_name', _('Card reader:')),
            ('taproot_status', _('Taproot / Schnorr:')),
            ('nfc_policy_status', _('NFC policy:')),
        ]:
            widget = QLabel('<tt></tt>')
            widget.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
                | Qt.TextInteractionFlag.TextSelectableByKeyboard
            )
            grid.addWidget(
                QLabel(label_text), y, 0, 1, 1,
                Qt.AlignmentFlag.AlignRight,
            )
            grid.addWidget(widget, y, 1, 1, 1, Qt.AlignmentFlag.AlignLeft)
            setattr(self, member_name, widget)
            y += 1

        layout.addLayout(grid)

        layout.addStretch(1)
        return tab

    def _build_settings_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        timeout_group = QGroupBox(_('Session Timeout'))
        timeout_vbox = QVBoxLayout(timeout_group)
        timeout_msg = QLabel(
            _(
                'Automatically lock the device after a period of inactivity. '
                'Once locked, you will need to enter your PIN '
                'again to use the device.'
            )
        )
        timeout_msg.setWordWrap(True)
        timeout_vbox.addWidget(timeout_msg)

        timeout_hbox = QHBoxLayout()
        self.timeout_label = QLabel(_('5 minutes'))
        self.timeout_label.setMinimumWidth(80)
        timeout_slider = QSlider(Qt.Orientation.Horizontal)
        timeout_slider.setRange(1, 60)
        timeout_slider.setSingleStep(1)
        timeout_slider.setTickInterval(5)
        timeout_slider.setTickPosition(QSlider.TickPosition.TicksBelow)

        current_timeout = (
            self.config.get('satochip_session_timeout', 300) // 60
        )
        timeout_slider.setValue(current_timeout)
        self.timeout_label.setText(_('{:d} minutes').format(current_timeout))

        def timeout_changed(value):
            self.timeout_label.setText(_('{:d} minutes').format(value))

        def timeout_released():
            mins = timeout_slider.value()
            self.config.set_key(
                'satochip_session_timeout', mins * 60, save=True
            )
            _logger.info(f'Session timeout set to {mins} minutes')

        timeout_slider.valueChanged.connect(timeout_changed)
        timeout_slider.sliderReleased.connect(timeout_released)

        timeout_hbox.addWidget(timeout_slider)
        timeout_hbox.addWidget(self.timeout_label)
        timeout_vbox.addLayout(timeout_hbox)
        layout.addWidget(timeout_group)

        label_group = QGroupBox(_('Card Label'))
        label_vbox = QVBoxLayout(label_group)
        self.card_label_display = QLabel('<tt>(none)</tt>')
        label_vbox.addWidget(self.card_label_display)
        change_label_btn = QPushButton(_('Change Label'))
        change_label_btn.clicked.connect(
            lambda: self._invoke_client('change_card_label')
        )
        label_vbox.addWidget(change_label_btn)
        label_msg = QLabel(
            _('The label is stored on the card and helps identify it.')
        )
        label_msg.setWordWrap(True)
        label_msg.setStyleSheet(ColorScheme.GRAY.as_stylesheet())
        label_vbox.addWidget(label_msg)
        layout.addWidget(label_group)

        pin_group = QGroupBox(_('PIN Management'))
        pin_vbox = QVBoxLayout(pin_group)
        self._pin_btn = QPushButton(_('Change PIN'))
        self._pin_btn.clicked.connect(
            lambda: self._invoke_client('change_pin')
        )
        pin_vbox.addWidget(self._pin_btn)
        pin_msg = QLabel(RECOMMEND_PIN)
        pin_msg.setWordWrap(True)
        pin_msg.setStyleSheet(ColorScheme.GRAY.as_stylesheet())
        pin_vbox.addWidget(pin_msg)
        layout.addWidget(pin_group)

        feature_group = QGroupBox(_('Card Features'))
        feature_vbox = QVBoxLayout(feature_group)

        schnorr_hbox = QHBoxLayout()
        schnorr_hbox.addWidget(QLabel(_('Schnorr signatures:')))
        self.schnorr_combo = QComboBox()
        self.schnorr_combo.addItem(_('Enabled'), 0x00)
        self.schnorr_combo.addItem(_('Disabled'), 0x01)
        self.schnorr_combo.addItem(_('Blocked'), 0x02)
        schnorr_hbox.addWidget(self.schnorr_combo)
        schnorr_apply = QPushButton(_('Apply'))
        schnorr_apply.clicked.connect(self._apply_schnorr_policy)
        schnorr_hbox.addWidget(schnorr_apply)
        feature_vbox.addLayout(schnorr_hbox)

        nfc_hbox = QHBoxLayout()
        nfc_hbox.addWidget(QLabel(_('NFC contactless:')))
        self.nfc_combo = QComboBox()
        self.nfc_combo.addItem(_('Enabled'), 0x00)
        self.nfc_combo.addItem(_('Disabled'), 0x01)
        self.nfc_combo.addItem(_('Deactivated'), 0x02)
        nfc_hbox.addWidget(self.nfc_combo)
        nfc_apply = QPushButton(_('Apply'))
        nfc_apply.clicked.connect(self._apply_nfc_policy)
        nfc_hbox.addWidget(nfc_apply)
        feature_vbox.addLayout(nfc_hbox)

        feature_note = QLabel(
            _(
                'These settings are stored on the card '
                'and persist across sessions.'
            )
        )
        feature_note.setWordWrap(True)
        feature_note.setStyleSheet(ColorScheme.GRAY.as_stylesheet())
        feature_vbox.addWidget(feature_note)
        layout.addWidget(feature_group)

        layout.addStretch(1)
        return tab

    def _build_advanced_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        wipe_group = QGroupBox(_('Wipe Card'))
        wipe_vbox = QVBoxLayout(wipe_group)
        wipe_btn = QPushButton(_('Wipe Card\u2026'))
        wipe_btn.clicked.connect(
            lambda: self._invoke_client(
                'factory_reset', unpair_after=True,
                on_complete=lambda: self.show_placeholders(None),
            )
        )
        wipe_vbox.addWidget(wipe_btn)
        wipe_subtext = QLabel(
            _(
                'Permanently erases the seed phrase and PIN. '
                'Requires confirmation.'
            )
        )
        wipe_subtext.setWordWrap(True)
        wipe_vbox.addWidget(wipe_subtext)
        wipe_warning = QLabel(_('<b>This action is irreversible.</b>'))
        wipe_warning.setStyleSheet(ColorScheme.RED.as_stylesheet())
        wipe_warning.setWordWrap(True)
        wipe_vbox.addWidget(wipe_warning)
        wipe_note = QLabel(
            _(
                'The wipe may require removing and reinserting the card '
                'several times. You will be guided through each step.'
            )
        )
        wipe_note.setWordWrap(True)
        wipe_vbox.addWidget(wipe_note)
        layout.addWidget(wipe_group)
        layout.addStretch(1)
        return tab

    # ------------------------------------------------------------------
    # Dialog helpers
    # ------------------------------------------------------------------

    def show_placeholders(self, error):
        '''Show placeholder values when the card is not connected.'''
        self.fw_version.setText('<tt>—</tt>')
        self.device_id_label.setText('<tt>—</tt>')
        self.card_status.setText('<tt>%s</tt>' % _('Not connected'))
        self.pin_tries.setText('<tt>—</tt>')
        self.reader_name.setText('<tt>—</tt>')
        self.taproot_status.setText('<tt>—</tt>')
        self.nfc_policy_status.setText('<tt>—</tt>')
        self.card_label_display.setText('<tt>(none)</tt>')

    def _pin_entry_dialog(self, msg):
        '''Show a PIN entry dialog and return the entered text or None.'''
        parent = self.top_level_window()
        d = WindowModalDialog(parent, _('Enter PIN'))
        pw = PasswordLineEdit()
        pw.setMinimumWidth(200)
        vbox = QVBoxLayout()
        vbox.addWidget(WWLabel(msg))
        vbox.addWidget(pw)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        d.setLayout(vbox)
        return pw.text() if d.exec() else None

    def _label_dialog(self, msg):
        '''Show a label entry dialog and return the entered text or None.'''
        parent = self.top_level_window()
        while True:
            label = line_dialog(
                parent=parent,
                title=_('Enter Label'),
                label=msg,
                ok_label=_('OK'),
            )
            if label is None or len(label.encode('utf-8')) <= 64:
                return label
            self.window.show_error(_('Label must be 64 characters or less!'))

    # ------------------------------------------------------------------
    # Tab data loading
    # ------------------------------------------------------------------

    def show_values(self, info):
        if info.get('error'):
            self.window.show_error(info['error'])
            return

        if not info:
            self.fw_version.setText('<tt>{}</tt>'.format(_('(uninitialized)')))
            self.device_id_label.setText('<tt>{}</tt>'.format(_('(none)')))
            self.card_status.setText('<tt>%s</tt>' % _('Not initialized'))
            self.pin_tries.setText('<tt>—</tt>')
            self.card_label_display.setText('<tt>%s</tt>' % _('Not set'))
            self.reader_name.setText('<tt>{}</tt>'.format(_('(none)')))
            return

        self.fw_version.setText('<tt>%s</tt>' % info['fw_rel'])

        protocol_ver = info.get('protocol_version', 0)
        if protocol_ver < self._MIN_PROTOCOL_VERSION:
            _logger.debug(
                'Protocol version 0x%04x below min 0x%04x.',
                protocol_ver,
                self._MIN_PROTOCOL_VERSION,
            )

        if 'device_id' in info:
            self.device_id_label.setText('<tt>%s</tt>' % info['device_id'])
        else:
            self.device_id_label.setText(
                '<tt>{}</tt>'.format(_('(unavailable)'))
            )

        setup_done = info['setup_done']
        is_seeded = info.get('is_seeded', False)
        pin_tries = info['pin_tries']

        if setup_done:
            if isinstance(pin_tries, int) and pin_tries == 0:
                card_status_str = _('PIN blocked')
            elif is_seeded:
                card_status_str = _('Ready')
            else:
                card_status_str = _('Initialized, no seed')
        else:
            card_status_str = _('Not initialized')
        self.card_status.setText('<tt>%s</tt>' % card_status_str)
        self._setup_done = setup_done
        self._pin_btn.setText(
            _('Set PIN') if not setup_done else _('Change PIN')
        )

        if not setup_done:
            self.pin_tries.setText('<tt>%s</tt>' % _('N/A'))
        else:
            self.pin_tries.setText('<tt>%s</tt>' % pin_tries)

        if 'label' in info:
            label = info['label'] or _('Not set')
            self.card_label_display.setText('<tt>%s</tt>' % label)
        else:
            self.card_label_display.setText('<tt>{}</tt>'.format(_('(error)')))

        if 'reader' in info:
            self.reader_name.setText('<tt>%s</tt>' % info['reader'])
        else:
            self.reader_name.setText('<tt>{}</tt>'.format(_('(unknown)')))

        taproot = info.get('taproot', False)
        proto_ver = info.get('protocol_version', 0)
        if taproot:
            self.taproot_status.setText('<tt>%s</tt>' % _('Supported'))
        elif proto_ver < 14:
            self.taproot_status.setText(
                '<tt>{}</tt>'.format(
                    _('Not available (requires firmware v0.14+)')
                )
            )
        else:
            self.taproot_status.setText(
                '<tt>{}</tt>'.format(_('Disabled on this card'))
            )

        nfc_policy = info.get('nfc_policy')
        _NFC_LABELS = {
            0x00: _('Enabled'),
            0x01: _('Disabled'),
            0x02: _('Deactivated'),
        }
        if nfc_policy is not None:
            self.nfc_policy_status.setText(
                '<tt>%s</tt>' % _NFC_LABELS.get(nfc_policy, _('Unknown'))
            )
            idx = self.nfc_combo.findData(nfc_policy)
            if idx >= 0:
                self.nfc_combo.setCurrentIndex(idx)
        else:
            self.nfc_policy_status.setText(
                '<tt>%s</tt>' % _('Not available')
            )

        schnorr_policy = info.get('schnorr_policy')
        if schnorr_policy is not None:
            idx = self.schnorr_combo.findData(schnorr_policy)
            if idx >= 0:
                self.schnorr_combo.setCurrentIndex(idx)

    # ------------------------------------------------------------------
    # Settings actions
    # ------------------------------------------------------------------

    def change_pin(self, client):
        _logger.info('In change_pin')
        msg_oldpin = _('Enter your current PIN:')
        msg_newpin = _('Enter a new PIN:')
        msg_confirm = _('Confirm your new PIN:')
        msg_error = _('The PIN values do not match! Please type PIN again!')
        msg_cancel = _('PIN Change cancelled!')

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
                self.window.show_message(_('PIN changed successfully!'))
                self.thread.add(
                    self._fetch_card_info,
                    on_success=self.show_values,
                    on_error=self.show_placeholders,
                )
            else:
                self.window.show_error(
                    _(
                        'Failed to change PIN. '
                        'The current PIN may be incorrect.'
                    )
                )
        except Exception as ex:
            self.window.show_error(
                _('Failed to change PIN: {}').format(str(ex))
            )

    def change_card_label(self, client):
        msg = _('Enter a label for your Satochip (max 64 characters):')

        is_ok = client.verify_PIN()
        if not is_ok:
            return

        label = self._label_dialog(msg)
        if label is None:
            self.window.show_message(_('Operation cancelled.'))
            return

        try:
            (response, sw1, sw2) = client.cc.card_set_label(label)
            if sw1 == 0x90 and sw2 == 0x00:
                self.window.show_message(_('Card label changed successfully!'))
                self.thread.add(
                    self._fetch_card_info,
                    on_success=self.show_values,
                    on_error=self.show_placeholders,
                )
            elif sw1 == 0x6D and sw2 == 0x00:
                self.window.show_error(
                    _('This card does not support labels (requires v0.12+).')
                )
            else:
                self.window.show_error(
                    _('Failed to change the card label. Please try again.')
                )
        except Exception as ex:
            self.window.show_error(
                _('Failed to change label: {}').format(str(ex))
            )

    def _apply_schnorr_policy(self):
        policy = self.schnorr_combo.currentData()

        if not self.window.question(
            _('Change Schnorr signature policy on this card?')
            + '\n\n'
            + _('This affects all wallets using this card.'),
            title=_('Confirm'),
        ):
            return

        def do_apply(client):
            try:
                client.verify_PIN()
                (resp, sw1, sw2) = client.cc.card_set_feature_policy(
                    0x00, policy
                )
                if sw1 == 0x90 and sw2 == 0x00:
                    self.window.show_message(
                        _('Schnorr policy updated successfully!')
                    )
                    self.thread.add(
                        self._fetch_card_info,
                        on_success=self.show_values,
                        on_error=self.show_placeholders,
                    )
                elif sw1 == 0x6D and sw2 == 0x00:
                    self.window.show_error(
                        _('This card does not support feature policies.')
                    )
                else:
                    self.window.show_error(
                        _(
                            'Failed to update Schnorr policy '
                            '(SW: {:02X}{:02X})'
                        ).format(
                            sw1, sw2
                        )
                    )
            except Exception as ex:
                self.window.show_error(
                    _('Failed to update Schnorr policy: {}').format(str(ex))
                )

        self.thread.add(self._fetch_client, on_success=do_apply)

    def _apply_nfc_policy(self):
        policy = self.nfc_combo.currentData()

        if not self.window.question(
            _('Change NFC contactless policy on this card?')
            + '\n\n'
            + _(
                'If you disable NFC, you will need '
                'a contact reader to re-enable it.'
            ),
            title=_('Confirm'),
        ):
            return

        def do_apply(client):
            try:
                client.verify_PIN()
                (resp, sw1, sw2) = client.cc.card_set_nfc_policy(policy)
                if sw1 == 0x90 and sw2 == 0x00:
                    self.window.show_message(
                        _('NFC policy updated successfully!')
                    )
                    self.thread.add(
                        self._fetch_card_info,
                        on_success=self.show_values,
                        on_error=self.show_placeholders,
                    )
                elif sw1 == 0x6D and sw2 == 0x00:
                    self.window.show_error(
                        _('This card does not support NFC policy settings.')
                    )
                else:
                    self.window.show_error(
                        _(
                            'Failed to update NFC policy '
                            '(SW: {:02X}{:02X})'
                        ).format(
                            sw1, sw2
                        )
                    )
            except Exception as ex:
                self.window.show_error(
                    _('Failed to update NFC policy: {}').format(str(ex))
                )

        self.thread.add(self._fetch_client, on_success=do_apply)

    # ------------------------------------------------------------------
    # Advanced actions
    # ------------------------------------------------------------------

    def factory_reset(self, client):
        wallet = self.window.wallet
        balance_sats = sum(wallet.get_balance()) if wallet else 0

        confirm_phrase = 'WIPE'
        try:
            (_r1, _r2, _r3, lbl) = client.cc.card_get_label()
            if lbl and lbl.strip() and lbl.strip() not in (
                '(none)',
                '(unknown)',
            ):
                confirm_phrase = lbl.strip()
        except Exception:
            pass

        warnings = [
            _(
                'The seed phrase stored on the card '
                'will be permanently erased.'
            ),
            _('The PIN, card label, and all stored data will be deleted.'),
            _('The card will be returned to factory state.'),
            _('This action is irreversible.'),
        ]

        balance_warning = None
        if balance_sats > 0:
            balance_warning = _(
                'Electrum shows this wallet has a balance of {bal}. '
                'Make sure you have a backup of your seed phrase before '
                'continuing — after wipe, the only way to recover the '
                'funds is to restore the seed into a new wallet.'
            ).format(bal=self.window.format_amount_and_units(balance_sats))

        confirmed = TypedConfirmationDialog(
            parent=self,
            title=_('Wipe Satochip'),
            action_label=_('Wipe Card'),
            confirm_phrase=confirm_phrase,
            warnings=warnings,
            balance_warning=balance_warning,
        ).run()
        if not confirmed:
            return

        def reset_task():
            _perform_factory_reset(
                self,
                client,
                show_message_func=self.window.show_message,
                show_error_func=self.window.show_error,
            )

        threading.Thread(target=reset_task, daemon=True).start()


class WCSatochipBlocked(WalletWizardComponent):
    """Wizard page for when the Satochip is PIN-locked;
    offers wipe-and-recover flow."""

    validChanged = pyqtSignal([bool], arguments=['valid'])

    def __init__(self, parent, wizard):
        super().__init__(parent, wizard)
        self.title = _('Satochip Is Locked')
        self.validChanged.connect(self._on_valid_changed)
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin('satochip')
        self._reset_btn = None

    def _on_valid_changed(self, valid):
        self.valid = valid

    def on_ready(self):
        msg = WWLabel(
            _(
                'The Satochip is locked due to '
                'too many incorrect PIN attempts.'
            )
        )
        self.layout().addWidget(msg)

        puk_note = WWLabel(
            _(
                'If you have the PUK code set during card '
                'initialization, press Next to unblock the PIN '
                'without losing data.'
            )
        )
        self.layout().addWidget(puk_note)

        wipe_note = WWLabel(
            _(
                'If you do not have the PUK, you can wipe the '
                'card to start over. This will permanently erase '
                'all data.'
            )
        )
        wipe_note.setStyleSheet(ColorScheme.GRAY.as_stylesheet())
        self.layout().addWidget(wipe_note)

        self._reset_btn = QPushButton(_('Wipe Card'))
        self._reset_btn.setFlat(True)
        self._reset_btn.setStyleSheet(
            'QPushButton {{ color: {red}; border: none; '
            'padding: 4px 0; text-decoration: underline; }}'.format(
                red=ColorScheme.RED.as_color().name()
            )
        )
        self._reset_btn.clicked.connect(self._on_factory_reset)
        self.layout().addWidget(self._reset_btn)
        self.layout().addStretch(1)

        self.valid = True

    def _on_factory_reset(self):
        self.busy = True
        self._reset_btn.setEnabled(False)
        self._reset_btn.setText(_('Wiping...'))

        _name, _info = self.wizard_data['hardware_device']
        device_id = _info.device.id_
        client = self.plugins.device_manager.client_by_id(
            device_id, scan_now=False
        )

        def show_message(msg):
            QTimer.singleShot(
                0, lambda: self._reset_btn.setText(_('Wipe Complete'))
            )

        def show_error(msg):
            QTimer.singleShot(0, lambda: setattr(self, 'error', msg))
            _logger.error('Wipe failed: %s', msg)

        def reset_task():
            try:
                _perform_factory_reset(
                    self,
                    client,
                    show_message_func=show_message,
                    show_error_func=show_error,
                )
                self.validChanged.emit(True)
            finally:
                QTimer.singleShot(0, lambda: setattr(self, 'busy', False))
                QTimer.singleShot(0, lambda: self._reset_btn.setEnabled(True))

        t = threading.Thread(target=reset_task, daemon=True)
        t.start()

    def apply(self):
        pass


class WCSatochipWrongCard(WalletWizardComponent):
    """Wizard page shown when the selected Satochip cannot be used with the
    wallet (authentikey mismatch)."""

    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_('Card Mismatch')
        )

    def on_ready(self):
        _name, _info = self.wizard_data['hardware_device']
        device_label = _info.label if _info else _('Unknown')

        msg = WWLabel(
            ''.join(
                [
                    _('This Satochip cannot be used with this wallet.\n\n'),
                    _(
                        'The card ({}) does not contain '
                        'the seed that was used to '
                        'create this wallet.\n\n'
                    ).format(device_label),
                    _(
                        'To use a Satochip with an existing wallet, '
                        'the card must already have the SAME seed '
                        'that created the wallet.\n\n'
                    ),
                    _('Options:\n'),
                    _(
                        '  \u2022 Use a different Satochip that '
                        "contains the wallet's seed\n"
                    ),
                    _(
                        '  \u2022 Use Satochip-Utils to import '
                        'the correct seed onto this card\n'
                    ),
                    _(
                        '  \u2022 Create a new wallet '
                        'with this card instead\n\n'
                    ),
                    _("Click 'Back' to choose a different device."),
                ]
            )
        )
        self.layout().addWidget(msg)
        self.layout().addStretch(1)
        self.valid = True

    def apply(self):
        pass


class WCSatochipRecoverSetup(WalletWizardComponent, Logger):

    validChanged = pyqtSignal([bool], arguments=['valid'])

    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard,
            title=_('Set Up Satochip for Existing Wallet'),
        )
        Logger.__init__(self)
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin('satochip')
        self.validChanged.connect(self._on_valid_changed)

    def _on_valid_changed(self, valid):
        self.valid = valid

    def on_ready(self):
        _name, _info = self.wizard_data['hardware_device']
        device_label = _info.label if _info else _('Unknown')

        msg = WWLabel(
            ''.join(
                [
                    _('This Satochip ({}) is not yet initialized.\n\n').format(
                        device_label
                    ),
                    _(
                        'To use this card with your existing wallet, '
                        'you must first set a PIN, then import '
                        'the seed phrase that was used to create '
                        'this wallet.\n\n'
                    ),
                    _(
                        'Enter a new PIN for this card below '
                        '(4-16 characters).\n'
                    ),
                ]
            )
        )
        self.layout().addWidget(msg)

        self.pw = PasswordLineEdit()
        self.pw.setMinimumWidth(32)
        self.layout().addWidget(WWLabel(_('Enter new PIN:')))
        self.layout().addWidget(self.pw)

        self.pw2 = PasswordLineEdit()
        self.pw2.setMinimumWidth(32)
        self.layout().addWidget(WWLabel(_('Confirm new PIN:')))
        self.layout().addWidget(self.pw2)

        self.layout().addStretch(1)

        def validate():
            is_valid = True
            if self.pw.text() != self.pw2.text():
                is_valid = False
            pw_bytes = self.pw.text().encode('utf-8')
            if len(pw_bytes) < 4 or len(pw_bytes) > 16:
                is_valid = False
            pw2_bytes = self.pw2.text().encode('utf-8')
            if len(pw2_bytes) < 4 or len(pw2_bytes) > 16:
                is_valid = False
            self.valid = is_valid

        self.pw2.textChanged.connect(validate)
        self.pw.textChanged.connect(validate)

    def apply(self):
        self.busy = True
        pin = self.pw.text()
        _name, _info = self.wizard_data['hardware_device']
        device_id = _info.device.id_

        client = self.plugins.device_manager.client_by_id(
            device_id, scan_now=False
        )
        client.handler = self.plugin.create_handler(self.wizard)

        def setup_task():
            try:
                self.plugin._setup_device(pin, device_id, client)
                _logger.info('[WCSatochipRecoverSetup] Card setup completed')
                self.validChanged.emit(True)
            except Exception as e:
                self.logger.exception('Failed to set up card')
                _set_error_later(self, str(e))
                self.validChanged.emit(False)
            finally:
                _set_busy_later(self, False)

        t = threading.Thread(target=setup_task, daemon=True)
        t.start()


class WCSatochipRecoverSeed(WalletWizardComponent, Logger):

    validChanged = pyqtSignal([bool], arguments=['valid'])

    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_('Import Seed for Existing Wallet')
        )
        Logger.__init__(self)
        self._seed_widget = None
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin('satochip')
        self.validChanged.connect(self._on_valid_changed)

    def _on_valid_changed(self, valid):
        self.valid = valid

    def on_ready(self):
        from electrum.gui.qt.seed_dialog import SeedWidget
        from electrum.keystore import bip39_is_checksum_valid

        _name, _info = self.wizard_data['hardware_device']
        device_label = _info.label if _info else _('Unknown')

        msg = WWLabel(
            ''.join(
                [
                    _(
                        'This Satochip ({}) '
                        'is not yet seeded.\n\n'
                    ).format(device_label),
                    _(
                        'To use this card with your existing wallet, '
                        'you must import '
                        'the seed phrase that was used to create '
                        'this wallet.\n\n'
                    ),
                    _(
                        'Enter your BIP39 seed phrase below. '
                        'It must be the SAME seed '
                        'that was used to create this wallet.\n\n'
                    ),
                    _(
                        'If you enter the wrong seed, '
                        'the wallet will not open correctly.\n'
                    ),
                ]
            )
        )
        self.layout().addWidget(msg)

        def _is_valid_bip39_seed(text):
            (is_checksum_valid, is_wordlist_valid) = (
                bip39_is_checksum_valid(text)
            )
            return is_checksum_valid and is_wordlist_valid

        self._seed_widget = SeedWidget(
            is_seed=_is_valid_bip39_seed,
            options=['ext', 'bip39'],
            config=self.wizard.config,
        )

        def seed_valid_changed(valid):
            self.valid = valid

        self._seed_widget.validChanged.connect(seed_valid_changed)
        self.layout().addWidget(self._seed_widget)
        self.layout().addStretch(1)

    def apply(self):
        self.busy = True
        if not self._seed_widget:
            self.busy = False
            return

        seed = self._seed_widget.get_seed()
        passphrase = self.wizard_data.get('seed_extra_words', '')

        cosigner_data = self.wizard.current_cosigner(self.wizard_data)
        cosigner_data['seed'] = seed
        cosigner_data['seed_variant'] = 'bip39'
        cosigner_data['seed_type'] = 'bip39'
        cosigner_data['seed_extend'] = bool(passphrase)
        cosigner_data['seed_extra_words'] = passphrase

        _name, _info = self.wizard_data['hardware_device']
        device_id = _info.device.id_

        settings = ('bip39', seed, passphrase)
        handler = self.plugin.create_handler(self.wizard)

        def import_task():
            try:
                self.plugin._import_seed(settings, device_id, handler)
                _logger.info(
                    '[WCSatochipRecoverSeed] Seed imported successfully'
                )
                self.validChanged.emit(True)
            except Exception as e:
                self.logger.exception('Failed to import seed')
                _set_error_later(self, str(e))
                self.validChanged.emit(False)
            finally:
                _set_busy_later(self, False)

        t = threading.Thread(target=import_task, daemon=True)
        t.start()


class WCSatochipUnlock(WCHWUnlock):
    """Satochip-specific unlock page with clean error messages and
    navigation to satochip_wrong_card on authentikey mismatch."""

    _navigate_to = pyqtSignal(str)

    def __init__(self, parent, wizard):
        super().__init__(parent, wizard)
        self._navigate_to.connect(self._do_navigate)

    def _do_navigate(self, view_key):
        '''Navigate to a named page (called via signal for GUI thread).'''
        self.wizard.load_next_component(view_key, self.wizard_data)

    def on_ready(self):
        _name, _info = self.wizard_data['hardware_device']
        self.plugin = self.plugins.get_plugin(_info.plugin_name)
        self.title = _('Unlocking {} ({})').format(
            _info.model_name, _info.label
        )

        device_id = _info.device.id_
        client = self.plugins.device_manager.client_by_id(
            device_id, scan_now=False
        )
        if client is None:
            self.error = _('The device was disconnected.')
            self.busy = False
            self.validate()
            return
        client.handler = self.plugin.create_handler(self.wizard)

        def unlock_task(client):
            try:
                self.password = client.get_password_for_storage_encryption()
            except Exception as e:
                from electrum.plugins.satochip.exceptions import WrongCardError
                if isinstance(e, WrongCardError):
                    _set_busy_later(self, False)
                    self._navigate_to.emit('satochip_wrong_card')
                    return
                _set_error_later(self, str(e))
                self.logger.exception(str(e))
            _set_busy_later(self, False)
            self.validate()

        t = threading.Thread(target=unlock_task, args=(client,), daemon=True)
        t.start()


class SatochipSetupLayout(QVBoxLayout):
    '''PIN and label setup for a new Satochip card.'''

    validChanged = pyqtSignal([bool], arguments=['valid'])

    def __init__(self, device):
        QVBoxLayout.__init__(self)

        vbox = QVBoxLayout()
        msg_setup = WWLabel(
            _(
                'Please take a moment to set up your Satochip. '
                'This must be done only once.'
            )
        )
        vbox.addWidget(msg_setup)

        self.pw = PasswordLineEdit()
        self.pw.setMinimumWidth(32)
        vbox.addWidget(WWLabel(_('Enter new PIN:')))
        vbox.addWidget(self.pw)
        self.addLayout(vbox)

        self.pw2 = PasswordLineEdit()
        self.pw2.setMinimumWidth(32)
        vbox2 = QVBoxLayout()
        vbox2.addWidget(WWLabel(_('Confirm new PIN:')))
        vbox2.addWidget(self.pw2)
        self.addLayout(vbox2)

        self.label_edit = QLineEdit()
        self.label_edit.setMaxLength(64)
        self.label_edit.setPlaceholderText(_('e.g., Savings'))
        vbox3 = QVBoxLayout()
        vbox3.addWidget(WWLabel(_('Card label (optional):')))
        vbox3.addWidget(self.label_edit)
        self.addLayout(vbox3)

        if self.pw.text() == '' or self.pw.text() is None:
            self.validChanged.emit(False)

        def set_enabled():
            is_valid = True
            if self.pw.text() != self.pw2.text():
                is_valid = False
            pw_bytes = self.pw.text().encode('utf-8')
            if len(pw_bytes) < 4 or len(pw_bytes) > 16:
                is_valid = False
            pw2_bytes = self.pw2.text().encode('utf-8')
            if len(pw2_bytes) < 4 or len(pw2_bytes) > 16:
                is_valid = False
            self.validChanged.emit(is_valid)

        self.pw2.textChanged.connect(set_enabled)
        self.pw.textChanged.connect(set_enabled)

    def get_settings(self):
        return (self.pw.text(), self.label_edit.text().strip())


class WCSatochipSetupParams(WalletWizardComponent):
    validChanged = pyqtSignal([bool], arguments=['valid'])

    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_('Satochip Setup')
        )
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin('satochip')

        self.layout().addWidget(
            WWLabel(_('Satochip card setup in progress\u2026'))
        )

    def on_ready(self):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        _name, _info = current_cosigner['hardware_device']
        self.settings_layout = SatochipSetupLayout(_info.device.id_)
        self.settings_layout.validChanged.connect(
            self.on_settings_valid_changed
        )
        self.layout().addLayout(self.settings_layout)
        self.layout().addStretch(1)

        self.valid = True
        self.busy = False

    def on_settings_valid_changed(self, is_valid: bool):
        self.valid = is_valid

    def apply(self):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        current_cosigner['satochip_setup_settings'] = (
            self.settings_layout.get_settings()
        )


class WCSatochipSetup(WalletWizardComponent, Logger):
    validChanged = pyqtSignal([bool], arguments=['valid'])

    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_('Satochip Setup')
        )
        Logger.__init__(self)
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin('satochip')
        self.validChanged.connect(self._on_valid_changed)

        self.layout().addWidget(WWLabel(_('Setting up card\u2026')))

    def on_ready(self):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        settings = current_cosigner['satochip_setup_settings']
        _name, _info = current_cosigner['hardware_device']
        device_id = _info.device.id_

        client = self.plugins.device_manager.client_by_id(
            device_id, scan_now=False
        )
        client.handler = self.plugin.create_handler(self.wizard)

        def initialize_device_task(settings, device_id, client):
            try:
                self.plugin._setup_device(settings, device_id, client)
                _logger.info('[WCSatochipSetup] Done initialize device')
                self.validChanged.emit(True)
                self.wizard.requestNext.emit()
            except Exception as e:
                self.validChanged.emit(False)
                _set_error_later(self, str(e))
                self.logger.exception(str(e))
            finally:
                _set_busy_later(self, False)

        t = threading.Thread(
            target=initialize_device_task,
            args=(settings, device_id, client),
            daemon=True,
        )
        t.start()

    def apply(self):
        pass

    def _on_valid_changed(self, valid):
        self.valid = valid


class WCSeedMethodChoice(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_('Satochip Needs a Seed')
        )

        intro = WWLabel('\n'.join(MSG_SEED_IMPORT))
        self.layout().addWidget(intro)

        message = _(
            'How do you want to provide a seed for this Satochip card?'
        )
        choices = [
            ChoiceItem(key='import', label=_('I already have a seed phrase')),
            ChoiceItem(
                key='generate',
                label=_('Generate a new BIP39 seed phrase'),
            ),
        ]
        self.choice_w = ChoiceWidget(
            message=message, choices=choices, default_key='import'
        )
        self.layout().addWidget(self.choice_w)
        self.layout().addStretch(1)

        self.valid = True

    def apply(self):
        cosigner_data = self.wizard.current_cosigner(self.wizard_data)
        cosigner_data[
            'satochip_seed_method'
        ] = self.choice_w.selected_key


class WCSatochipGenerateSeed(WalletWizardComponent):
    """Display a freshly generated BIP39 seed phrase for the user to write
    down, with 12/24-word selector and regenerate button."""

    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_('Your New BIP39 Seed Phrase')
        )
        self._seed = None
        self.seed_widget = None

        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel(_('Seed length:')))
        self.radio_12 = QRadioButton(_('12 words'))
        self.radio_24 = QRadioButton(_('24 words'))
        self.radio_24.setChecked(True)
        self.radio_12.toggled.connect(self._on_length_changed)
        self.radio_24.toggled.connect(self._on_length_changed)
        length_layout.addWidget(self.radio_12)
        length_layout.addWidget(self.radio_24)
        self.regen_btn = QPushButton(_('Regenerate'))
        self.regen_btn.clicked.connect(self._on_regenerate_clicked)
        length_layout.addWidget(self.regen_btn)
        length_layout.addStretch(1)
        self.layout().addLayout(length_layout)

    def on_ready(self):
        QTimer.singleShot(1, self._create_seed)

    def _current_length(self) -> int:
        return 12 if self.radio_12.isChecked() else 24

    def _create_seed(self):
        self.busy = True
        self._seed = _generate_bip39_mnemonic(self._current_length())

        from electrum.gui.qt.seed_dialog import SeedWidget

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
        cosigner_data['seed'] = self._seed
        cosigner_data['seed_type'] = 'bip39'
        cosigner_data['seed_variant'] = 'bip39'
        cosigner_data['seed_extend'] = bool(
            self.seed_widget and self.seed_widget.is_ext
        )


class WCSeedSuccess(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_('Seed Imported')
        )

    def on_ready(self):
        w_icon = QLabel()
        w_icon.setPixmap(
            QPixmap(icon_path('confirmed.png')).scaledToWidth(
                48, mode=Qt.TransformationMode.SmoothTransformation
            )
        )
        w_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label = WWLabel(_('Seed imported successfully!'))
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout().addStretch(1)
        self.layout().addWidget(w_icon)
        self.layout().addWidget(label)
        self.layout().addStretch(1)
        self.valid = True
        QTimer.singleShot(0, self.wizard.requestNext.emit)

    def apply(self):
        pass


class WCSatochipImportSeed(WalletWizardComponent, Logger):
    validChanged = pyqtSignal([bool], arguments=['valid'])

    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(
            self, parent, wizard, title=_('Satochip Setup')
        )
        Logger.__init__(self)
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin('satochip')
        self.validChanged.connect(self._on_valid_changed)

        self.layout().addWidget(WWLabel(_('Importing seed\u2026')))

    def on_ready(self):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)

        settings = (
            current_cosigner['seed_type'],
            current_cosigner['seed'],
            current_cosigner['seed_extra_words']
            if current_cosigner.get('seed_extend')
            else '',
        )

        _name, _info = current_cosigner['hardware_device']
        device_id = _info.device.id_
        client = self.plugins.device_manager.client_by_id(
            device_id, scan_now=False
        )
        client.handler = self.plugin.create_handler(self.wizard)

        def initialize_device_task(settings, device_id, handler):
            try:
                self.plugin._import_seed(settings, device_id, handler)
                _logger.info('[WCSatochipImportSeed] Done initialize device')
                self.validChanged.emit(True)
                self.wizard.requestNext.emit()
            except Exception as e:
                self.validChanged.emit(False)
                _set_error_later(self, str(e))
                self.logger.exception(str(e))
            finally:
                _set_busy_later(self, False)

        t = threading.Thread(
            target=initialize_device_task,
            args=(settings, device_id, client.handler),
            daemon=True,
        )
        t.start()

    def apply(self):
        pass

    def _on_valid_changed(self, valid):
        self.valid = valid


def _run_card_swap_dialog(parent, remaining_steps, total_steps):
    result = [False]
    event = threading.Event()

    def _show_and_wait():
        try:
            dlg = CardSwapDialog(
                parent,
                remaining_steps=remaining_steps,
                total_steps=total_steps,
            )
            result[0] = dlg.run()
        finally:
            event.set()

    QTimer.singleShot(0, _show_and_wait)
    event.wait()
    return result[0]


def _perform_factory_reset(parent, client, show_message_func, show_error_func):
    from electrum.plugins.satochip.satochip import (
        FactoryResetAlreadyDone,
        FactoryResetCardNotRemoved,
        FactoryResetInProgress,
    )
    max_attempts = 10
    for attempt in range(1, max_attempts + 1):
        try:
            client.perform_factory_reset()
            show_message_func(_('Card wiped successfully.'))
            return
        except FactoryResetAlreadyDone as ex:
            show_message_func(str(ex))
            return
        except FactoryResetInProgress as ex:
            remaining = ex.remaining_steps
            total = remaining + attempt
            if not _run_card_swap_dialog(parent, remaining, total):
                show_message_func(_('Wipe cancelled.'))
                return
            continue
        except FactoryResetCardNotRemoved:
            remaining = 4
            total = remaining + attempt
            if not _run_card_swap_dialog(parent, remaining, total):
                show_message_func(_('Wipe cancelled.'))
                return
            continue
        except Exception as ex:
            show_error_func(_('Wipe failed: {}').format(str(ex)))
            return
    show_error_func(_('Wipe failed after {} attempts.').format(max_attempts))


def _generate_bip39_mnemonic(num_words: int) -> str:
    """Generate a BIP39 mnemonic using only Electrum's bundled wordlist.

    Implements the BIP39 algorithm directly:
      entropy -> sha256 checksum -> concatenate -> split into 11-bit
      indices -> words.

    Uses only Python stdlib and Electrum's english.txt wordlist.
    *num_words* must be 12 (128-bit entropy) or 24 (256-bit entropy).
    """
    assert num_words in (12, 24), (
        f'num_words must be 12 or 24, got {num_words}'
    )

    entropy_bits = 128 if num_words == 12 else 256
    entropy_bytes = secrets.token_bytes(entropy_bits // 8)

    # BIP39: checksum = first (entropy_bits / 32) bits of sha256(entropy)
    checksum_bits = entropy_bits // 32
    digest = hashlib.sha256(entropy_bytes).digest()
    checksum = digest[0] >> (8 - checksum_bits)

    # Pack entropy + checksum into one big integer
    entropy_int = int.from_bytes(entropy_bytes, 'big')
    combined = (entropy_int << checksum_bits) | checksum

    # Split into 11-bit groups and look up words
    from electrum.mnemonic import Wordlist

    wordlist = Wordlist.from_file('english.txt')
    words = [
        wordlist[(combined >> (11 * i)) & 0x7FF]
        for i in range(num_words - 1, -1, -1)
    ]
    return ' '.join(words)
