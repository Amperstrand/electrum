'''Satochip hardware client: wraps CardConnector into HardwareClientBase.'''

import time
from contextlib import contextmanager
from typing import Optional

from electrum.i18n import _
from electrum.plugin import runs_in_hwd_thread
from electrum.util import UserFacingException
from electrum.crypto import hash_160
try:
    from electrum.bip32 import (
        BIP32Node,
        convert_bip32_strpath_to_intpath,
    )
except ImportError:
    from electrum.bip32 import (
        BIP32Node,
        convert_bip32_path_to_list_of_uint32
        as convert_bip32_strpath_to_intpath,
    )
from electrum.logging import get_logger
try:
    from electrum.hw_wallet import HardwareClientBase
except ImportError:
    from ..hw_wallet import HardwareClientBase

from .exceptions import (
    UninitializedSeedError,
    UnexpectedSW12Error,
    CardNotPresentError,
    WrongPinError,
    PinBlockedError,
    PinRequiredError,
    CardSetupNotDoneError,
)

try:
    from smartcard.Exceptions import CardConnectionException
except ImportError:
    CardConnectionException = None

_logger = get_logger(__name__)

_BLOCKED_SUFFIX = ' [blocked]'


def _bip32path2bytes(bip32path: str):
    int_path = convert_bip32_strpath_to_intpath(bip32path)
    depth = len(int_path)
    byte_path = b''
    for index in int_path:
        byte_path += index.to_bytes(4, byteorder='big', signed=False)
    return depth, byte_path


class SatochipClient(HardwareClientBase):
    def __init__(self, plugin, handler, hw_device=None):
        super().__init__(plugin=plugin)
        self._soft_device_id = None
        self.device = plugin.device
        self.handler = handler
        reader_idx = (
            self._reader_index_from_path(hw_device) if hw_device else None
        )
        self.reader_full_name = self._resolve_reader_full_name(reader_idx)
        from .card_connector import CardConnector
        self.cc = CardConnector(self, reader_index=reader_idx)
        self.last_operation = float('inf')
        self.in_flow = False
        self.used()

    @staticmethod
    def _reader_index_from_path(hw_device) -> Optional[int]:
        try:
            return int(str(hw_device.path).rsplit('/', 1)[-1])
        except (ValueError, IndexError, AttributeError):
            return None

    @staticmethod
    def _resolve_reader_full_name(reader_idx: Optional[int]) -> str:
        try:
            from smartcard.System import readers as list_pcsc_readers
            readers = list_pcsc_readers()
            if reader_idx is not None and 0 <= reader_idx < len(readers):
                return str(readers[reader_idx])
            if readers:
                return str(readers[0])
        except Exception:
            pass
        return ''

    def __repr__(self):
        try:
            return '<SatochipClient: label=%r>' % (self.label(),)
        except Exception:
            return '<SatochipClient: (disconnected)>'

    # -- flow / lifecycle ---------------------------------------------------

    def used(self):
        self.last_operation = time.time()

    def prevent_timeouts(self):
        self.last_operation = float('inf')

    @contextmanager
    def run_flow(self, message=None):
        if self.in_flow:
            raise RuntimeError('Overlapping call to run_flow')
        self.in_flow = True
        self.prevent_timeouts()
        try:
            yield self
        except CardNotPresentError as e:
            raise UserFacingException(
                _('Card not detected. Please insert your Satochip.')
            ) from e
        except UninitializedSeedError as e:
            raise UserFacingException(str(e)) from e
        except UnexpectedSW12Error as e:
            raise UserFacingException(str(e)) from e
        except Exception as e:
            if (CardConnectionException is not None
                    and isinstance(e, CardConnectionException)):
                raise UserFacingException(
                    _('Could not communicate with the card: {}').format(e)
                ) from e
            raise
        finally:
            self.in_flow = False
            self.handler.finished()
            self.used()

    def clear_session(self):
        if hasattr(self.cc, 'set_pin'):
            self.cc.set_pin(0, None)
        self.used()

    # -- HardwareClientBase abstract methods --------------------------------

    def is_pairable(self):
        return True

    @runs_in_hwd_thread
    def close(self):
        self.cc.card_disconnect()
        self.cc.cardmonitor.deleteObserver(self.cc.cardobserver)

    def timeout(self, cutoff):
        if self.last_operation < cutoff:
            _logger.info('Satochip session timed out, clearing PIN cache')
            self.clear_session()

    @runs_in_hwd_thread
    def is_initialized(self):
        try:
            time.sleep(0.3)
            if not self._ensure_card_connection():
                return None
            self.cc.card_get_status()
        except CardNotPresentError:
            return None

        if self.cc.setup_done is None:
            return None
        if not self.cc.setup_done:
            return None
        if self.cc.setup_done and not self.cc.is_seeded:
            return False
        return True

    @runs_in_hwd_thread
    def has_usable_connection_with_device(self):
        if self.in_flow:
            return True
        try:
            if self.cc.cardservice is None:
                return False
            self.cc.card_get_ATR()
        except Exception:
            return False
        return True

    @runs_in_hwd_thread
    def get_xpub(self, bip32_path, xtype):
        assert xtype in self.plugin.SUPPORTED_XTYPES
        with self.run_flow():
            self.verify_PIN()

            _logger.info(f'get_xpub(): bip32_path={bip32_path}')
            (depth, bytepath) = _bip32path2bytes(bip32_path)
            try:
                (childkey, childchaincode) = (
                    self.cc.card_bip32_get_extendedkey(bytepath)
                )
            except UninitializedSeedError as e:
                raise UserFacingException(str(e))

            if depth == 0:
                fingerprint = bytes([0, 0, 0, 0])
                child_number = bytes([0, 0, 0, 0])
            else:
                (parentkey, parentchaincode) = (
                    self.cc.card_bip32_get_extendedkey(bytepath[0:-4])
                )
                fingerprint = hash_160(
                    parentkey.get_public_key_bytes(compressed=True)
                )[0:4]
                child_number = bytepath[-4:]

            xpub = BIP32Node(
                xtype=xtype,
                eckey=childkey,
                chaincode=childchaincode,
                depth=depth,
                fingerprint=fingerprint,
                child_number=child_number,
            ).to_xpub()
            _logger.info(f'get_xpub(): xpub={xpub}')
            return xpub

    # -- label / device-id --------------------------------------------------

    _CARD_LABEL_SENTINELS = frozenset({'(none)', '(unknown)'})

    @runs_in_hwd_thread
    def label(self):
        try:
            if not self._ensure_card_connection():
                return ''
            try:
                self.cc.card_get_status()
            except CardNotPresentError:
                return ''
            except PinBlockedError:
                identity = self._get_device_identity()
                return f'{identity}{_BLOCKED_SUFFIX}' if identity else ''
            except Exception:
                pass
            return self._get_device_identity()
        except Exception:
            return ''

    def _get_device_identity(self):
        card_label = self._try_get_card_label()
        if card_label:
            return card_label
        device_id = self._get_short_device_id()
        if device_id and device_id != '????????':
            return device_id
        return ''

    def _try_get_card_label(self):
        if self.cc and hasattr(self.cc, 'card_get_label'):
            try:
                (_r1, _r2, _r3, card_label) = self.cc.card_get_label()
                if (
                    card_label
                    and card_label not in self._CARD_LABEL_SENTINELS
                    and card_label.strip()
                ):
                    return card_label.strip()
            except Exception:
                pass
        return None

    def _get_short_device_id(self) -> str:
        try:
            uid_sha1 = getattr(self.cc, 'UID_SHA1', None)
            if uid_sha1:
                return uid_sha1[:8].upper()
        except Exception:
            pass
        try:
            parser = getattr(self.cc, 'parser', None)
            if parser is not None:
                coordx = getattr(parser, 'authentikey_coordx', None)
                if coordx is not None:
                    fp = hash_160(bytes(coordx))[:4]
                    return fp.hex().upper()
        except Exception:
            pass
        return '????????'

    def device_model_name(self):
        return 'Satochip'

    def get_soft_device_id(self):
        if self._soft_device_id is None:
            self._soft_device_id = self._get_short_device_id()
        return self._soft_device_id

    # -- PIN helpers --------------------------------------------------------

    @runs_in_hwd_thread
    def verify_PIN(self, pin=None):
        while True:
            try:
                self.cc.card_verify_PIN_simple(pin)
                return True
            except CardNotPresentError:
                msg = _(
                    'No card found!'
                    '\nPlease insert card, then enter your PIN:'
                )
                (is_PIN, pin) = self.PIN_dialog(msg)
                if not is_PIN:
                    return False
            except PinRequiredError:
                msg = _('Enter the PIN for your card:')
                (is_PIN, pin) = self.PIN_dialog(msg)
                if not is_PIN:
                    return False
            except WrongPinError as ex:
                pin = None
                msg = _(
                    'Wrong PIN! {} tries remaining!'
                    '\nEnter the PIN for your card:'
                ).format(ex.pin_left)
                (is_PIN, pin) = self.PIN_dialog(msg)
                if not is_PIN:
                    return False
            except PinBlockedError:
                raise UserFacingException(
                    _(
                        'Your Satochip PIN is blocked due to too many'
                        ' failed attempts.\n\n'
                        'The only way to recover is a factory reset,'
                        ' which will erase all data from the card.\n\n'
                        'If you are setting up a wallet, the wizard will'
                        ' guide you through the reset. Otherwise, open'
                        ' Settings \u2192 Advanced \u2192 Factory Reset.'
                    )
                )
            except CardSetupNotDoneError:
                raise UserFacingException(
                    _(
                        'This Satochip has not been set up yet.\n\n'
                        'The card needs to be initialized with a PIN and'
                        ' seed before it can be used.'
                    )
                )
            except Exception as ex:
                raise UserFacingException(
                    _(
                        'Unexpected error during PIN verification: {}'
                    ).format(ex)
                )

    def PIN_dialog(self, msg):
        while True:
            password = self.handler.get_passphrase(msg, False)
            if password is None:
                return False, None
            if len(password) < 4:
                msg = (
                    _('PIN must have at least 4 characters.')
                    + '\n\n'
                    + _('Enter PIN:')
                )
            elif len(password) > 16:
                msg = (
                    _('PIN must have less than 16 characters.')
                    + '\n\n'
                    + _('Enter PIN:')
                )
            else:
                return True, password.encode('utf8')

    def PIN_change_dialog(
        self, msg_old, msg_new, msg_confirm, msg_error, msg_cancel
    ):
        (is_pin, oldpin) = self.PIN_dialog(msg_old)
        if not is_pin:
            self.request('show_message', msg_cancel)
            return False, None, None
        while True:
            (is_pin, newpin) = self.PIN_dialog(msg_new)
            if not is_pin:
                self.request('show_message', msg_cancel)
                return False, None, None
            (is_pin, newpin_confirm) = self.PIN_dialog(msg_confirm)
            if not is_pin:
                self.request('show_message', msg_cancel)
                return False, None, None
            if newpin != newpin_confirm:
                self.request('show_error', msg_error)
            else:
                return True, oldpin, newpin

    @runs_in_hwd_thread
    def perform_factory_reset(self):
        from .satochip import (
            FactoryResetAlreadyDone,
            FactoryResetCardNotRemoved,
            FactoryResetInProgress,
        )
        self.cc.mode_factory_reset = True
        try:
            with self.run_flow():
                response, sw1, sw2 = self.cc.card_reset_factory_signal()

                if sw1 == 0xFF and sw2 == 0x00:
                    self.cc.card_disconnect()
                    return
                elif sw1 == 0x9C and sw2 == 0x04:
                    self.cc.card_disconnect()
                    raise FactoryResetAlreadyDone(
                        _(
                            'Card is already in factory state'
                            ' (not initialized).'
                        )
                    )
                elif sw1 == 0xFF and sw2 == 0xFF:
                    self.cc.card_disconnect()
                    raise FactoryResetCardNotRemoved(
                        _(
                            'Card was not removed since last attempt. '
                            'Remove and reinsert the card, then try again.'
                        )
                    )
                elif sw1 == 0xFF and sw2 > 0x00:
                    self.cc.card_disconnect()
                    raise FactoryResetInProgress(
                        _(
                            'Factory reset in progress (remaining steps: {}). '
                            'Remove and reinsert the card, then'
                            ' click Factory Reset again.'
                        ).format(sw2),
                        remaining_steps=sw2,
                    )
                else:
                    self.cc.card_disconnect()
                    raise UserFacingException(
                        _(
                            'Factory reset failed. Please remove and'
                            ' reinsert the card, then try again.'
                        )
                    )
        except UserFacingException:
            raise
        except Exception:
            self.cc.card_disconnect()
            raise
        finally:
            self.cc.mode_factory_reset = False

    # -- handler communication -----------------------------------------------

    def request(self, request_type, *args):
        if self.handler is not None:
            if request_type == 'update_status':
                return self.handler.update_status(*args)
            elif request_type == 'show_error':
                return self.handler.show_error(*args)
            elif request_type == 'show_message':
                return self.handler.show_message(*args)
            else:
                return self.handler.show_error(
                    _('Unknown request: {}').format(request_type)
                )
        return None

    # -- card connection helpers --------------------------------------------

    def _ensure_card_connection(self, timeout: float = 3.0) -> bool:
        start = time.time()
        while (time.time() - start) < timeout:
            if not getattr(self.cc, 'card_present', False):
                time.sleep(0.15)
                continue
            cs = getattr(self.cc, 'cardservice', None)
            if (cs is not None
                    and hasattr(getattr(cs, 'connection', None), 'transmit')):
                return True
            time.sleep(0.15)
        return False

    @runs_in_hwd_thread
    def get_authentikey_fingerprint(self) -> Optional[str]:
        try:
            parser = getattr(self.cc, 'parser', None)
            if parser is not None:
                coordx = getattr(parser, 'authentikey_coordx', None)
                if coordx is not None:
                    fp = hash_160(bytes(coordx))[:4]
                    return fp.hex()
            with self.run_flow():
                self.verify_PIN()
                authentikey = self.cc.card_export_authentikey()
                if authentikey:
                    pubkey = authentikey.get_public_key_bytes(compressed=True)
                    fp = hash_160(pubkey)[:4]
                    return fp.hex()
        except Exception as e:
            _logger.debug(f'get_authentikey_fingerprint(): error: {e}')
        return None

    @runs_in_hwd_thread
    def supports_taproot(self):
        try:
            if self.cc.protocol_version is None:
                self.cc.card_get_status()
            if self.cc.protocol_version < self.plugin.MIN_TAPROOT_VERSION:
                return False
            policy = getattr(self.cc, 'feature_schnorr_policy', None)
            if policy is not None and policy != 0:
                return False
            return True
        except Exception:
            return False
