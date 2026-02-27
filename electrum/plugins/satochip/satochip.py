from os import urandom
import hashlib


import time
from typing import Optional
import electrum_ecc as ecc
from electrum_ecc.util import bip340_tagged_hash

# electrum
from electrum import constants
from electrum.bitcoin import var_int
from electrum.i18n import _
from electrum.plugin import Device, DeviceInfo, runs_in_hwd_thread
from electrum.keystore import Hardware_KeyStore, bip39_to_seed, bip39_is_checksum_valid, ScriptTypeNotSupported
from electrum.transaction import Sighash
from electrum.wallet import Standard_Wallet
from electrum.wizard import NewWalletWizard
from electrum.util import UserFacingException
from electrum.crypto import hash_160, sha256d
from electrum.bip32 import BIP32Node, convert_bip32_strpath_to_intpath, convert_bip32_intpath_to_strpath
from electrum.logging import get_logger

from electrum.hw_wallet  import HW_PluginBase, HardwareClientBase



# pysatochip
import pysatochip
from pysatochip.CardConnector import CardConnector, UninitializedSeedError
from pysatochip.CardConnector import CardNotPresentError, UnexpectedSW12Error, WrongPinError, PinBlockedError, PinRequiredError, CardResetToFactoryError, CardSetupNotDoneError
from pysatochip.Satochip2FA import Satochip2FA, SERVER_LIST
from .logging_utils import instrument_module_function_entries

# pyscard
from smartcard.Exceptions import CardRequestTimeoutException, CardConnectionException
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest

from smartcard.System import readers as list_pcsc_readers

_logger = get_logger(__name__)

# version history for the plugin
SATOCHIP_PLUGIN_REVISION = 'lib0.11.a-plugin0.1'

# debug: smartcard reader ids
SATOCHIP_VID = 0  # 0x096E
SATOCHIP_PID = 0  # 0x0503

MSG_USE_2FA = _("Do you want to use 2-Factor-Authentication (2FA)?\n\nWith 2FA, any transaction must be confirmed on "
                "a second device such as your smartphone. First you have to install the Satochip-2FA android app on "
                "google play. Then you have to pair your 2FA device with your Satochip by scanning the qr-code on the "
                "next screen. \n\nWARNING: be sure to backup a copy of the qr-code in a safe place, in case you have "
                "to reinstall the app!")


def bip32path2bytes(bip32path: str) -> (int, bytes):
    intPath = convert_bip32_strpath_to_intpath(bip32path)
    depth = len(intPath)
    bytePath = b''
    for index in intPath:
        bytePath += index.to_bytes(4, byteorder='big', signed=False)
    return depth, bytePath


class SatochipClient(HardwareClientBase):
    def __init__(self, plugin: HW_PluginBase, handler):
        HardwareClientBase.__init__(self, plugin=plugin)
        _logger.info(f"[SatochipClient] __init__()")
        self._soft_device_id = None
        self.device = plugin.device
        self.handler = handler
        # self.parser= CardDataParser()
        self.cc = CardConnector(self, _logger.getEffectiveLevel())

        # Track last operation for session timeout (similar to Trezor)
        self.last_operation = float('inf')

    def __repr__(self):
        try:
            return '<SatochipClient: label=%r>' % (self.label(),)
        except Exception:
            return '<SatochipClient: (disconnected)>'

    def is_pairable(self):
        return True

    @runs_in_hwd_thread
    def close(self):
        _logger.info(f"close()")
        self.cc.card_disconnect()
        self.cc.cardmonitor.deleteObserver(self.cc.cardobserver)

    def used(self):
        """Update timestamp of last operation. Called by Electrum framework."""
        self.last_operation = time.time()

    def prevent_timeouts(self):
        """Prevent session timeout. Sets last_operation to infinity."""
        self.last_operation = float('inf')

    @runs_in_hwd_thread
    def timeout(self, cutoff):
        '''Clear cached PIN if the last operation was before cutoff.
        
        SECURITY DESIGN DISCUSSION:
        ============================
        This method implements session-based security by clearing the cached PIN
        after a period of inactivity (configurable via Electrum's session timeout).
        
        Trade-offs to consider:
        
        1. PIN TIMEOUT APPROACH (current implementation):
           - Pro: Forces re-authentication after inactivity, similar to other HW wallets
           - Pro: Provides security if user walks away from unlocked computer
           - Con: Users may get PIN fatigue from frequent re-prompts
           - Con: May train users to enter PIN without thinking
        
        2. PHYSICAL CARD REMOVAL ONLY:
           - Pro: Satochip is a smartcard - removing it should be the primary security
           - Pro: Less user friction, PIN entered once per card insertion
           - Con: If card is left inserted and computer unlocked, funds are accessible
           - Note: This is how physical credit cards work (PIN per insertion, not per operation)
        
        3. HYBRID APPROACH (potential future):
           - Short timeout: Just clear PIN cache (current behavior)
           - Long timeout: Full card disconnect (more disruptive but more secure)
        
        CURRENT DECISION:
        We clear only the PIN cache (not full disconnect) to balance security and usability.
        The PIN cache is stored in pysatochip's CardConnector.pin and is reset via set_pin().
        This is less disruptive than a full card_disconnect() which would require card
        reinsertion.
        
        To disable timeout behavior entirely, the user can increase Electrum's
        session timeout setting or this method can be modified to return early.
        
        See also: Trezor's implementation in plugins/trezor/clientbase.py
        '''
        if self.last_operation < cutoff:
            _logger.info("Satochip session timed out, clearing PIN cache")
            # Clear PIN cache in pysatochip CardConnector
            # This forces re-authentication on next operation
            # We use set_pin() instead of card_disconnect() to avoid disrupting
            # the card monitor and requiring physical card reinsertion
            if hasattr(self.cc, 'set_pin'):
                self.cc.set_pin(0, None)

    def is_initialized(self):
        _logger.info(f"SATOCHIP is_initialized()")

        # Let some time for the PC/SC monitor to notice the reader/card,
        # then try to query card status. When no card is present we treat
        # the device as "uninitialized" for the purposes of DeviceInfo.
        try:
            time.sleep(0.3)
            if not self._ensure_card_connection():
                _logger.info("SATOCHIP is_initialized() connection not ready")
                return None
            (response, sw1, sw2, d) = self.cc.card_get_status()
        except CardNotPresentError:
            _logger.info("SATOCHIP is_initialized() None (no card present)")
            return None

        # Check for communication error (setup_done=None indicates unknown state from card_get_status)
        if self.cc.setup_done is None:
            _logger.warning(
                "SATOCHIP is_initialized() None (communication error - card state unknown)")
            return None
        
        # if setup is not done, we return None (factory‑fresh card)
        if not self.cc.setup_done:
            _logger.info("SATOCHIP is_initialized() None (no setup)")
            return None
        # if not seeded, return False (PIN set but no seed)
        if self.cc.setup_done and not self.cc.is_seeded:
            _logger.info(
                "SATOCHIP is_initialized() False (PIN set but card not seeded)"
            )
            return False
        # initialized if pin is set and device is seeded
        if self.cc.setup_done and self.cc.is_seeded:
            _logger.info(
                "SATOCHIP is_initialized() True (PIN set and card seeded)"
            )
            return True
        
        # Fallback - should not reach here
        _logger.warning(f"SATOCHIP is_initialized() unexpected state: setup_done={self.cc.setup_done}, is_seeded={self.cc.is_seeded}")
        return None

    def get_soft_device_id(self):
        return self._soft_device_id

    def _ensure_card_connection(self, timeout: float = 3.0) -> bool:
        """Wait for pysatochip's RemovalObserver to finish setting up cardservice.connection.
        Returns True if the card is present and connection is ready, False on timeout.
        """
        start = time.time()
        while (time.time() - start) < timeout:
            if not getattr(self.cc, 'card_present', False):
                time.sleep(0.15)
                continue
            cs = getattr(self.cc, 'cardservice', None)
            if cs is not None and hasattr(getattr(cs, 'connection', None), 'transmit'):
                return True
            time.sleep(0.15)
        return False

    # Card label sentinel values returned by pysatochip when no label is stored
    # or when the card does not support the label feature.
    _CARD_LABEL_SENTINELS = frozenset({'(none)', '(unknown)'})

    def label(self):
        """Return device label for display in Electrum UI.

        Priority order (first non-empty/non-sentinel value wins):
          1. User-set label stored in card flash via card_set_label().
             Formatted as "Satochip: <label>" so the device type is always
             visible.
          2. Fingerprint derived from the authentikey (unique per card, like
             Coldcard's approach).  Privacy-friendly: it identifies the card
             without exposing the serial number.
          3. Generic fallback: just "Satochip".

        Notes:
          - This label appears in Electrum's wallet selector — distinct labels
            let users tell multiple Satochip cards apart.
          - The label is saved in the wallet file on first pairing, so it
            should be stable across reconnects.
          - pysatochip returns '(none)' when no label has been set and
            '(unknown)' on unexpected SW12 errors; both are treated as absent.
          - Older card firmware (< v0.12) does not support card_get_label and
            will return SW=0x6D00; pysatochip maps that to '(none)' as well.
        """
        try:
            if not self._ensure_card_connection():
                return "Satochip"
            status = None
            blocked_via_exception = False
            try:
                (_resp, _sw1, _sw2, status) = self.cc.card_get_status()
            except CardNotPresentError:
                return "Satochip (no card inserted)"
            except PinBlockedError:
                # Card is blocked; card_get_status (or its auth handshake) raised.
                # Return immediately with blocked sentinel — don't call card_get_label etc.
                return "Satochip [blocked]"
            except Exception:
                status = None

            # 1. Try label stored on card
            base_label = None
            if self.cc and hasattr(self.cc, 'card_get_label'):
                try:
                    (_, _, _, card_label) = self.cc.card_get_label()
                    if (card_label
                            and card_label not in self._CARD_LABEL_SENTINELS
                            and card_label.strip()):
                        base_label = f"Satochip: {card_label}"
                except Exception:
                    pass

            # 2. Fingerprint from authentikey (available once card is seeded)
            if base_label is None:
                parser = getattr(self.cc, 'parser', None)
                if parser is not None:
                    coordx = getattr(parser, 'authentikey_coordx', None)
                    if coordx:
                        from electrum.crypto import hash_160
                        fingerprint = hash_160(bytes(coordx))[:4]
                        base_label = f"Satochip {fingerprint.hex()}"

            if base_label is None:
                base_label = "Satochip"

            # 3. Append pysatochip status fields verbatim.
            suffix_parts = []
            if isinstance(status, dict):
                pin_tries = status.get("PIN0_remaining_tries")
                if pin_tries is not None:
                    suffix_parts.append(f"PIN0_remaining_tries={pin_tries}")
                # Mark blocked cards so the wizard can offer factory reset at device selection.
                if pin_tries == 0:
                    suffix_parts.append("blocked")
                if "is_seeded" in status:
                    suffix_parts.append(
                        f"is_seeded={status['is_seeded']}"
                    )
                if status.get("needs2FA"):
                    suffix_parts.append("needs2FA=True")
                pmaj = status.get("protocol_major_version")
                pmin = status.get("protocol_minor_version")
                amaj = status.get("applet_major_version")
                amin = status.get("applet_minor_version")
                if pmaj is not None and amaj is not None:
                    suffix_parts.append(f"fw={pmaj}.{pmin}-{amaj}.{amin}")

            if suffix_parts:
                return f"{base_label} [{', '.join(suffix_parts)}]"
            return base_label
        except Exception as e:
            _logger.debug(f"label(): error getting label: {e}")
            return "Satochip"

    def device_model_name(self):
        return "Satochip"

    def supports_taproot(self):
        """Check if the Satochip card supports Taproot (Schnorr signatures).
        
        Requires protocol version 0.14 or higher.
        Returns:
            bool: True if Taproot is supported, False otherwise.
        """
        try:
            # Get card status to populate version info
            if self.cc.protocol_version is None:
                _ = self.cc.card_get_status()
            
            version = self.cc.protocol_version  # e.g., 14, 15, etc.
            supported = version >= SatochipPlugin.MIN_TAPROOT_VERSION
            _logger.info(f"supports_taproot(): version={version}, supported={supported}")
            return supported
        except Exception as e:
            _logger.warning(f"supports_taproot(): error checking version: {e}")
            return False

    @runs_in_hwd_thread
    def has_usable_connection_with_device(self):
        _logger.info(f"has_usable_connection_with_device()")
        try:
            if self.cc.cardservice is None:
                _logger.info("has_usable_connection_with_device: no cardservice (card removed?)")
                return False

            atr = self.cc.card_get_ATR()
            _logger.info("Card ATR: " + bytes(atr).hex())

        except Exception as e:  # except SWException as e:
            _logger.exception(
                f"Exception in has_usable_connection_with_device: {str(e)}")

            return False
        return True

    @runs_in_hwd_thread
    def get_authentikey_fingerprint(self) -> Optional[str]:
        """Get the 4-byte fingerprint derived from the card's authentikey.
        
        This is used to uniquely identify the card for device verification.
        Returns the fingerprint as hex string, or None if card is not seeded.
        """
        try:
            # 1. Try authentikey_coordx from parser (set after card_bip32_get_authentikey)
            parser = getattr(self.cc, 'parser', None)
            if parser is not None:
                coordx = getattr(parser, 'authentikey_coordx', None)
                if coordx is not None:
                    from electrum.crypto import hash_160
                    fingerprint = hash_160(bytes(coordx))[:4]
                    return fingerprint.hex()
            
            # 2. Fallback: try exporting authentikey via card_export_authentikey()
            #    Note: This requires PIN verification
            self.verify_PIN()
            authentikey = self.cc.card_export_authentikey()
            if authentikey:
                from electrum.crypto import hash_160
                pubkey = authentikey.get_public_key_bytes(compressed=True)
                fingerprint = hash_160(pubkey)[:4]
                return fingerprint.hex()
        except Exception as e:
            _logger.debug(f"get_authentikey_fingerprint(): error: {e}")
        
        return None


    def verify_PIN(self, pin=None):
        while True:
            try:
                # when pin is None, pysatochip use a cached pin if available
                (response, sw1, sw2) = self.cc.card_verify_PIN_simple(pin)
                return True

            # recoverable errors
            except CardNotPresentError:
                msg = f"No card found! \nPlease insert card, then enter your PIN:"
                (is_PIN, pin) = self.PIN_dialog(msg)
                if is_PIN is False:
                    return False
            except PinRequiredError:
                # no pin value cached in pysatochip
                msg = f'Enter the PIN for your card:'
                (is_PIN, pin) = self.PIN_dialog(msg)
                if is_PIN is False:
                    return False
            except WrongPinError as ex:
                pin = None  # reset pin
                msg = f"Wrong PIN! {ex.pin_left} tries remaining! \n Enter the PIN for your card:"
                (is_PIN, pin) = self.PIN_dialog(msg)
                if is_PIN is False:
                    return False

            # unrecoverable errors
            except PinBlockedError:
                # Card has 0 PIN tries left; only recovery is factory reset. Run it automatically
                # (no confirmation dialog — user already chose to proceed with this device).
                try:
                    self.perform_factory_reset()
                    self.request('show_message',
                        _("Factory reset completed successfully!\n\n"
                          "Your Satochip has been returned to factory state. "
                          "You can now set it up again with a new PIN and seed."))
                except UserFacingException:
                    raise
                except Exception as e:
                    raise UserFacingException(_("Factory reset failed: {}").format(e))
                return False
            except CardSetupNotDoneError:
                # Card has not been set up (factory-fresh or factory reset).
                # This is a critical error for existing wallets - the user needs to
                # set up the card and import the seed that matches the wallet.
                raise UserFacingException(
                    _("This Satochip has not been set up yet.\n\n")
                    + _("The card needs to be initialized with a PIN and seed before it can be used.\n")
                    + _("If you are opening an existing wallet, you must import the SAME seed that was used to create this wallet.\n\n")
                    + _("Please use 'Create new wallet' with this card to set it up, or use Satochip-Utils to initialize the card.")
                )
            except UnexpectedSW12Error as ex:
                raise UserFacingException(
                    f"Unexpected error during PIN verification: {ex}")
            except Exception as ex:
                raise UserFacingException(
                    f"Unexpected error during PIN verification: {ex}")

    @runs_in_hwd_thread
    def get_xpub(self, bip32_path, xtype):
        assert xtype in SatochipPlugin.SUPPORTED_XTYPES

        # needs PIN
        self.verify_PIN()

        # bip32_path is of the form 44'/0'/1'
        _logger.info(f"[SatochipClient] get_xpub(): bip32_path={bip32_path}")
        (depth, bytepath) = bip32path2bytes(bip32_path)
        try:
            (childkey, childchaincode) = self.cc.card_bip32_get_extendedkey(bytepath)
        except UninitializedSeedError as e:
            raise UserFacingException(str(e))
        if depth == 0:  # masterkey
            fingerprint = bytes([0, 0, 0, 0])
            child_number = bytes([0, 0, 0, 0])
        else:  # get parent info
            (parentkey, parentchaincode) = self.cc.card_bip32_get_extendedkey(
                bytepath[0:-4])
            fingerprint = hash_160(
                parentkey.get_public_key_bytes(compressed=True))[0:4]
            child_number = bytepath[-4:]
        xpub = BIP32Node(xtype=xtype,
                         eckey=childkey,
                         chaincode=childchaincode,
                         depth=depth,
                         fingerprint=fingerprint,
                         child_number=child_number).to_xpub()
        _logger.info(f"[SatochipClient] get_xpub(): xpub={str(xpub)}")
        return xpub

    def request(self, request_type, *args):
        _logger.info('[SatochipClient] client request: ' + str(request_type))

        if self.handler is not None:
            if request_type == 'update_status':
                reply = self.handler.update_status(*args)
                return reply
            elif request_type == 'show_error':
                reply = self.handler.show_error(*args)
                return reply
            elif request_type == 'show_message':
                reply = self.handler.show_message(*args)
                return reply
            else:
                reply = self.handler.show_error(
                    'Unknown request: ' + str(request_type))
                return reply
        else:
            _logger.info('[SatochipClient] self.handler is None! ')
            return None

    def PIN_dialog(self, msg):
        while True:
            password = self.handler.get_passphrase(msg, False)
            if password is None:
                return False, None
            if len(password) < 4:
                msg = _("PIN must have at least 4 characters.") + \
                    "\n\n" + _("Enter PIN:")
            elif len(password) > 16:
                msg = _("PIN must have less than 16 characters.") + \
                    "\n\n" + _("Enter PIN:")
            else:
                password = password.encode('utf8')
                return True, password

    def PIN_setup_dialog(self, msg, msg_confirm, msg_error):
        while True:
            (is_PIN, pin) = self.PIN_dialog(msg)
            if not is_PIN:
                # return (False, None)
                raise RuntimeError(
                    ('A PIN code is required to initialize the Satochip!'))
            (is_PIN, pin_confirm) = self.PIN_dialog(msg_confirm)
            if not is_PIN:
                # return (False, None)
                raise RuntimeError('A PIN confirmation is required to initialize the Satochip!')
            if pin != pin_confirm:
                self.request('show_error', msg_error)
            else:
                return is_PIN, pin

    def PIN_change_dialog(self, msg_oldpin, msg_newpin, msg_confirm, msg_error, msg_cancel):
        # old pin
        (is_PIN, oldpin) = self.PIN_dialog(msg_oldpin)
        if not is_PIN:
            self.request('show_message', msg_cancel)
            return False, None, None

        # new pin
        while True:
            (is_PIN, newpin) = self.PIN_dialog(msg_newpin)
            if not is_PIN:
                self.request('show_message', msg_cancel)
                return False, None, None
            (is_PIN, pin_confirm) = self.PIN_dialog(msg_confirm)
            if not is_PIN:
                self.request('show_message', msg_cancel)
                return False, None, None
            if newpin != pin_confirm:
                self.request('show_error', msg_error)
            else:
                return True, oldpin, newpin

    def _wait_for_card_absent(self, timeout: float = 30.0) -> bool:
        """Block until the card is physically removed or timeout expires.  Returns True if removed."""
        start = time.time()
        while self.cc.card_present and (time.time() - start) < timeout:
            time.sleep(0.3)
        return not self.cc.card_present

    def _wait_for_card_present(self, timeout: float = 60.0) -> bool:
        """Block until the card is physically inserted and pysatochip has established
        a connection.  The card monitor sets card_present before the connection is
        ready, so we also wait for cardservice.connection to be valid.
        """
        start = time.time()
        while (time.time() - start) < timeout:
            if not self.cc.card_present:
                time.sleep(0.3)
                continue
            # card_present is True, but RemovalObserver may not have finished
            # setting cardservice.connection yet — wait for it
            if getattr(self.cc, 'cardservice', None) and hasattr(
                    getattr(self.cc.cardservice, 'connection', None), 'transmit'):
                return True
            time.sleep(0.2)
        return False

    def perform_factory_reset(self):
        """Perform a factory reset of the Satochip card using the legacy multi-signal method.

        Supported on Satochip firmware v0.12-0.4 and newer.  The process requires
        sending a special APDU several times; between each send the user must
        physically remove and reinsert the card.  The card's internal counter
        decrements with each accepted signal until it reaches zero and the reset fires.

        Card removal/reinsertion is detected automatically via the pysatochip card
        monitor — no manual button clicks required between steps.

        Raises UserFacingException on version incompatibility or any card-level error.
        Returns True on successful reset.
        """
        card_type = getattr(self.cc, "card_type", None)
        if card_type != "Satochip":
            raise UserFacingException(
                _("Factory reset in this plugin only supports Satochip cards. "
                  "Detected card type: {}.").format(card_type or "unknown")
            )

        # Verify the firmware is new enough to support factory reset (v0.12-0.4+).
        try:
            (response, sw1, sw2, d) = self.cc.card_get_status()
            vmaj = d.get("protocol_major_version", 0)
            vmin = d.get("protocol_minor_version", 0)
            amaj = d.get("applet_major_version", 0)
            amin = d.get("applet_minor_version", 0)
            version = (vmaj << 24) + (vmin << 16) + (amaj << 8) + amin
            version_min = (12 << 16) + 4  # v0.12-0.4
            if version < version_min:
                raise UserFacingException(
                    _("Factory reset is not supported on this card.\n\n"
                      "Your firmware (v{}.{}-{}.{}) is too old — "
                      "factory reset requires v0.12-0.4 or newer.").format(vmaj, vmin, amaj, amin))
        except UserFacingException:
            raise
        except Exception as e:
            raise UserFacingException(
                _("Factory reset aborted: unable to verify Satochip firmware version ({})").format(e)
            )

        # Tell pysatochip's RemovalObserver to skip card_get_status and secure_channel
        # on each reinsert (see CardConnector.py RemovalObserver). Otherwise the observer
        # tries to init the secure channel on a blocked card and can leave the connection
        # in a bad state, causing 0x6E00 or "Invalid protocol in transmit".
        self.cc.set_mode_factory_reset(True)
        try:
            step_count = 0  # Number of removal/reinsertion cycles completed.

            def _prompt_remove(step_msg=None):
                self.request('show_message', step_msg or _(
                    "Factory reset: please REMOVE your Satochip card from the reader..."))
                if not self._wait_for_card_absent():
                    raise UserFacingException(_("Factory reset timed out waiting for card removal."))

            def _prompt_reinsert(steps_remaining=None):
                if steps_remaining is not None:
                    msg = _("Card removed. Reinsert to continue ({} step(s) remaining)...").format(
                        steps_remaining)
                else:
                    msg = _("Card removed. Please reinsert it to continue...")
                self.request('show_message', msg)
                if not self._wait_for_card_present():
                    raise UserFacingException(_("Factory reset timed out waiting for card reinsertion."))
                # Reference CLI waits for user to confirm after reinsert, so the observer has
                # time to finish CPLC + card_select() before the next APDU. We have no confirm,
                # so wait here for the observer to complete; otherwise we send before the
                # Satochip applet is selected and get 0x6E00 (CLA not supported).
                time.sleep(2.0)

            # The factory reset APDU is only accepted by the card from a fresh session.
            # Cycle the card once before sending the first signal.
            _prompt_remove()
            _prompt_reinsert()

            # Send the reset signal repeatedly.  Card removal/reinsertion is detected
            # automatically — no manual OK clicks.  sw2 is the steps-remaining counter.
            while True:
                try:
                    (response, sw1, sw2) = self.cc.card_reset_factory_signal()
                except CardNotPresentError:
                    _prompt_reinsert(steps_remaining="?")
                    continue
                except CardResetToFactoryError:
                    self.cc.card_disconnect()
                    return True

                if sw1 == 0xFF and sw2 == 0x00:
                    self.cc.card_disconnect()
                    return True
                elif sw1 == 0xFF and sw2 == 0xFF:
                    # Card was not removed since the last signal — wait and retry.
                    step_count += 1
                    self.request('show_message', _(
                        "Step {}: remove your Satochip card...").format(step_count))
                    _prompt_remove()
                    _prompt_reinsert()
                elif sw1 == 0xFF and sw2 > 0x00:
                    step_count += 1
                    self.request('show_message', _(
                        "Step {} ({} remaining): remove your Satochip card...").format(
                        step_count, sw2))
                    _prompt_remove()
                    _prompt_reinsert(steps_remaining=sw2)
                elif sw1 == 0x9C and sw2 == 0x04:
                    raise UserFacingException(
                        _("Factory reset failed: the card has not been set up yet (error 0x9C04)."))
                elif sw1 == 0x6D and sw2 == 0x00:
                    raise UserFacingException(
                        _("Factory reset failed: instruction not supported (error 0x6D00)."))
                elif sw1 == 0x6E and sw2 == 0x00:
                    raise UserFacingException(
                        _("Factory reset failed: class not supported (error 0x6E00)."))
                else:
                    raise UserFacingException(
                        _("Factory reset failed with unexpected error: {}").format(hex(256 * sw1 + sw2)))
        finally:
            self.cc.set_mode_factory_reset(False)


class Satochip_KeyStore(Hardware_KeyStore):
    hw_type = 'satochip'
    device = 'Satochip'
    plugin: 'SatochipPlugin'

    def __init__(self, d):
        Hardware_KeyStore.__init__(self, d)
        self.force_watching_only = False
        self.ux_busy = False
        # Store authentikey fingerprint for device verification (like Coldcard's ckcc_xpub)
        self._satochip_authentikey = d.get('satochip_authentikey', None)
        self._expected_device = None  # Cache for verified device

    def dump(self):
        d = Hardware_KeyStore.dump(self)
        d['satochip_authentikey'] = self._satochip_authentikey
        return d

    def get_client(self, force_pair=True, *, devices=None, allow_user_interaction=True):
        """Get client and verify the connected device matches expected authentikey.
        
        This prevents using the wrong card if multiple cards are available.
        Similar to Coldcard's verify_connection() approach.
        """
        client = super().get_client(
            force_pair=force_pair,
            devices=devices,
            allow_user_interaction=allow_user_interaction,
        )
        if client:
            self.verify_connection(client)
        
        return client

    def verify_connection(self, client: 'SatochipClient'):
        """Verify that the connected card matches expected authentikey.
        
        Raises RuntimeError if mismatch detected.
        """
        expected_authentikey = self._satochip_authentikey
        
        if expected_authentikey is None:
            # No authentikey stored yet - this is first use or after wallet creation
            # Fill it in opportunistically
            self.opportunistically_fill_in_missing_info_from_device(client)
            return
        
        # Get the authentikey from the connected card
        actual_authentikey = client.get_authentikey_fingerprint()
        if actual_authentikey is None:
            _logger.warning("verify_connection: could not get authentikey from card")
            return
        
        # Check if already verified (cached)
        if self._expected_device == actual_authentikey:
            return  # Already verified
        
        if actual_authentikey != expected_authentikey:
            _logger.error(
                f"verify_connection: authentikey mismatch! "
                f"Expected: {expected_authentikey}, "
                f"Connected: {actual_authentikey}"
            )
            raise UserFacingException(
                _("Wrong Satochip connected! ") +
                _("This card does not match the wallet. ") +
                _("Please connect the correct Satochip for this wallet.")
            )
        
        # All good - cache for next check
        self._expected_device = actual_authentikey
        _logger.info(f"verify_connection: card verified (fingerprint: {actual_authentikey})")

    def opportunistically_fill_in_missing_info_from_device(self, client: 'SatochipClient'):
        """Fill in missing authentikey from device if not already stored.
        
        Similar to Coldcard's approach.
        """
        super().opportunistically_fill_in_missing_info_from_device(client)
        
        if self._satochip_authentikey is None:
            authentikey = client.get_authentikey_fingerprint()
            if authentikey:
                self._satochip_authentikey = authentikey
                self.is_requesting_to_be_rewritten_to_wallet_file = True
                _logger.info(f"Stored authentikey fingerprint: {authentikey}")


    def give_error(self, message, clear_client=False):
        _logger.error(f"[Satochip_KeyStore] give_error() {message}")
        if not self.ux_busy:
            self.handler.show_error(message)
        else:
            self.ux_busy = False
        if clear_client:
            self.client = None
        raise UserFacingException(message)

    @staticmethod
    def wrap_busy(func):
        """Decorator: function takes over the UX on the device.
        
        Sets ux_busy flag during hardware operations so the UI can show
        appropriate busy state. Also ensures the flag is reset on error.
        
        Follows the same pattern as Coldcard (electrum/plugins/coldcard/coldcard.py:312)
        """
        def wrapper(self, *args, **kwargs):
            try:
                self.ux_busy = True
                return func(self, *args, **kwargs)
            finally:
                self.ux_busy = False
        return wrapper

    def decrypt_message(self, pubkey, message, password):
        raise RuntimeError(
            _('Encryption and decryption are currently not supported for {}').format(self.device))

    @wrap_busy
    def sign_message(self, sequence, message, password, *, script_type=None):
        message_byte = message.encode('utf8')
        message_hash = hashlib.sha256(message_byte).hexdigest().upper()
        client = self.get_client()
        is_ok = client.verify_PIN()
        if not is_ok:
            return b''

        address_path = self.get_derivation_prefix() + "/%d/%d" % sequence
        _logger.info(f"[Satochip_KeyStore] sign_message: path: {address_path}")

        # check if 2FA is required
        hmac = b''
        if client.cc.needs_2FA is None:
            (response, sw1, sw2, d) = client.cc.card_get_status()
        if client.cc.needs_2FA:
            # challenge based on sha256(btcheader+msg)
            # format & encrypt msg
            import json
            msg = {'action': "sign_msg", 'msg': message}
            msg = json.dumps(msg)
            # do challenge-response with 2FA device...
            hmac = self.do_challenge_response(msg)
            hmac = bytes.fromhex(hmac)
        else:
            self.handler.show_message(
            "Signing message ...\r\nMessage hash: " + message_hash)

        try:
            keynbr = 0xFF  # for extended key
            (depth, bytepath) = bip32path2bytes(address_path)
            (pubkey, chaincode) = client.cc.card_bip32_get_extendedkey(bytepath)
            (response2, sw1, sw2, compsig) = client.cc.card_sign_message(
                keynbr, pubkey, message_byte, hmac)
            if compsig == b'':
                self.handler.show_error(
                    _("Wrong signature!\nThe 2FA device may have rejected the action."))
            return compsig

        except CardNotPresentError as e:
            _logger.error(f"[Satochip_KeyStore] sign_message: card not present: {e}")
            self.handler.show_error(_("Card not detected. Please insert your Satochip."))
            return b''
        except PinBlockedError as e:
            _logger.error(f"[Satochip_KeyStore] sign_message: PIN blocked: {e}")
            self.handler.show_error(_("PIN is blocked. Card must be replaced."))
            return b''
        except UnexpectedSW12Error as e:
            _logger.error(f"[Satochip_KeyStore] sign_message: card error: {e}")
            self.handler.show_error(_("Card returned an error.") + "\n" + str(e))
            return b''
        except Exception as e:
            _logger.error(f"[Satochip_KeyStore] sign_message: unexpected error: {e}")
            self.handler.show_error(_("Failed to sign message.") + "\n" + str(e))
            return b''
        finally:
            _logger.info(f"[Satochip_KeyStore] sign_message: finally")
            self.handler.finished()

    @wrap_busy
    def sign_transaction(self, tx, password):
        _logger.info(f"In sign_transaction(): tx: {str(tx)}")
        client = self.get_client()
        client.verify_PIN()
        try:
            segwitTransaction = False

            # outputs (bytes format)
            txOutputs = bytearray()
            txOutputs += var_int(len(tx.outputs()))
            for o in tx.outputs():
                txOutputs += int.to_bytes(o.value, length=8,
                                          byteorder="little", signed=False)
                script = o.scriptpubkey
                txOutputs += var_int(len(script))
                txOutputs += script
            txOutputs = bytes(txOutputs)
            hashOutputs = sha256d(txOutputs).hex()
            _logger.info(f"In sign_transaction(): hashOutputs= {hashOutputs}")
            _logger.info(f"In sign_transaction(): outputs= {txOutputs.hex()}")

            # Fetch inputs of the transaction to sign
            for i, txin in enumerate(tx.inputs()):

                if tx.is_complete():
                    break

                desc = txin.script_descriptor
                assert desc
                script_type = desc.to_legacy_electrum_script_type()

                _logger.info(
                    f"In sign_transaction(): input= {str(i)} - input[type]: {script_type}")
                if txin.is_coinbase_input():
                    # should never happen
                    self.give_error("Coinbase not supported")

                if script_type in ['p2wpkh', 'p2wsh', 'p2wpkh-p2sh', 'p2wsh-p2sh', 'p2tr']:
                    segwitTransaction = True

                my_pubkey, inputPath = self.find_my_pubkey_in_txinout(txin)

                # Check Taproot compatibility with 2FA
                is_taproot = script_type == 'p2tr'
                if is_taproot:
                    # 2FA is not supported with Taproot (pysatochip limitation)
                    if client.cc.needs_2FA:
                        raise UserFacingException(
                            _("Taproot (P2TR) is not compatible with 2FA.\n\n"
                              "To use Taproot addresses, you must disable 2FA on your Satochip.\n\n"
                              "You can do this through the Satochip settings dialog."))
                    # Check if card supports Taproot (protocol v0.14+)
                    if not client.supports_taproot():
                        raise UserFacingException(
                            _("Your Satochip does not support Taproot.\n\n"
                              "Taproot requires Satochip firmware v0.14 or newer.\n\n"
                              "Please update your Satochip firmware or use a different address type."))
                if not inputPath:
                    # should never happen
                    self.give_error("No matching pubkey for sign_transaction")
                inputPath = convert_bip32_intpath_to_strpath(inputPath)  # [2:]

                # get corresponing extended key
                (depth, bytepath) = bip32path2bytes(inputPath)
                (key, chaincode) = client.cc.card_bip32_get_extendedkey(bytepath)

                # parse tx (bytes format)
                pre_tx = tx.serialize_preimage(i)
                pre_hash = sha256d(pre_tx)
                _logger.info(
                    f"[Satochip_KeyStore] sign_transaction(): pre_tx= {pre_tx.hex()}")
                _logger.info(
                    f"[Satochip_KeyStore] sign_transaction(): pre_hash= {pre_hash.hex()}")
                (response, sw1, sw2, tx_hash_list, needs_2fa) = client.cc.card_parse_transaction(
                    pre_tx, segwitTransaction)
                tx_hash = bytearray(tx_hash_list)
                if pre_hash != tx_hash:
                    raise RuntimeError(
                        f"[Satochip_KeyStore] Tx preimage mismatch: {pre_hash.hex()} vs {tx_hash.hex()}")

                # 2FA
                keynbr = 0xFF  # for extended key
                if needs_2fa:
                    # format & encrypt msg
                    import json
                    coin_type = 1 if constants.net.TESTNET else 0
                    if segwitTransaction:
                        msg = {'tx': pre_tx.hex(), 'ct': coin_type, 'sw': segwitTransaction,
                               'txo': txOutputs.hex(), 'ty': script_type}
                    else:
                        msg = {'tx': pre_tx.hex(), 'ct': coin_type,
                               'sw': segwitTransaction}
                    msg = json.dumps(msg)

                    # do challenge-response with 2FA device...
                    hmac = self.do_challenge_response(msg)
                    hmac = list(bytes.fromhex(hmac))
                else:
                    hmac = None

                # sign tx
                if is_taproot:
                    # Taproot: Use Schnorr signature (BIP-340)
                    # The hash for Taproot is computed differently (BIP-341 tagged hash)
                    tap_hash = bip340_tagged_hash(b"TapSighash", pre_hash)
                    _logger.info(f"[Satochip_KeyStore] sign_transaction(): tap_hash= {tap_hash.hex()}")

                    # Sign with Schnorr (2FA not supported for Schnorr - already checked above)
                    (tx_sig, sw1, sw2) = client.cc.card_sign_schnorr_hash(
                        keynbr, list(tap_hash), None)

                    # check sw1sw2 for error
                    if sw1 != 0x90 or sw2 != 0x00:
                        self.give_error(
                            f"Satochip failed to sign Taproot transaction with code {hex(256*sw1+sw2)}")

                    # Schnorr signature is raw 64 bytes - no DER decoding needed
                    # No low-S normalization needed for Schnorr (BIP-340 handles it)
                    tx_sig = bytes(tx_sig)

                    # For Taproot, default sighash is DEFAULT (empty bytes), not ALL
                    # Check if txin specifies a sighash, otherwise use DEFAULT
                    sighash = txin.sighash if txin.sighash is not None else Sighash.DEFAULT
                    tx_sig = tx_sig + Sighash.to_sigbytes(sighash)

                else:
                    # Regular ECDSA signing (existing logic)
                    (tx_sig, sw1, sw2) = client.cc.card_sign_transaction(
                        keynbr, tx_hash_list, hmac)
                    # check sw1sw2 for error (0x9c0b if wrong challenge-response)
                    if sw1 != 0x90 or sw2 != 0x00:
                        self.give_error(
                            f"Satochip failed to sign transaction with code {hex(256*sw1+sw2)}")

                    # enforce low-S signature (BIP 62)
                    tx_sig = bytes(tx_sig)  # bytearray(tx_sig)
                    r, s = ecc.get_r_and_s_from_ecdsa_der_sig(tx_sig)
                    if s > ecc.CURVE_ORDER // 2:
                        s = ecc.CURVE_ORDER - s
                    tx_sig = ecc.ecdsa_der_sig_from_r_and_s(r, s)
                    # update tx with signature
                    tx_sig = tx_sig + Sighash.to_sigbytes(Sighash.ALL)

                tx.add_signature_to_txin(
                    txin_idx=i, signing_pubkey=my_pubkey, sig=tx_sig)

            _logger.info(f"Tx is complete: {str(tx.is_complete())}")
            tx.raw = tx.serialize()
            return
        except UserFacingException:
            raise
        except RuntimeError:
            raise
        except (CardNotPresentError, PinBlockedError, UnexpectedSW12Error,
                UninitializedSeedError, WrongPinError, PinRequiredError) as e:
            _logger.error(f"[Satochip_KeyStore] sign_transaction: card error: {e}")
            self.give_error(e)
        except Exception as e:
            _logger.error(f"[Satochip_KeyStore] sign_transaction: unexpected error: {e}")
            self.give_error(e)

    def show_address(self, sequence, txin_type):
        from electrum import bitcoin
        client = self.get_client()
        is_ok = client.verify_PIN()
        if not is_ok:
            return

        address_path = self.get_derivation_prefix() + "/%d/%d" % sequence
        _logger.info(f"[Satochip_KeyStore] show_address: path: {address_path}")

        try:
            (depth, bytepath) = bip32path2bytes(address_path)
            (pubkey, chaincode) = client.cc.card_bip32_get_extendedkey(bytepath)
            (response, sw1, sw2, status) = client.cc.card_get_status()

            # Derive address from pubkey
            pubkey_hex = pubkey.hex()
            address = bitcoin.pubkey_to_address(txin_type, pubkey_hex)

            # Build info string with card and address details
            label = status.get('label', '')
            applet_version = status.get('applet_version', 'unknown')
            pin_tries = status.get('PIN0_remaining_tries', 'unknown')
            needs_2fa = status.get('needs2FA', False)
            is_seeded = status.get('is_seeded', False)

            info_lines = [
                _("Address:") + f" {address}",
                _("Derivation:") + f" {address_path}",
                _("Card label:") + f" {label}" if label else _("Card label:") + " " + _("(not set)"),
                _("Applet version:") + f" {applet_version}",
                _("PIN tries remaining:") + f" {pin_tries}",
                _("2FA enabled:") + (" " + _("Yes") if needs_2fa else " " + _("No")),
                _("Card seeded:") + (" " + _("Yes") if is_seeded else " " + _("No")),
            ]
            info_string = "\n".join(info_lines)

            self.handler.show_message(info_string)

        except CardNotPresentError:
            self.handler.show_error(_("Card not detected. Please insert your Satochip."))
            return
        except PinBlockedError:
            self.handler.show_error(_("PIN is blocked. Card must be replaced."))
            return
        except Exception as e:
            _logger.info(f"[Satochip_KeyStore] show_address: Exception {e}")
            self.handler.show_error(_("Could not communicate with card.") + "\n" + str(e))
            return
        finally:
            _logger.info(f"[Satochip_KeyStore] show_address: finally")
            self.handler.finished()

    def do_challenge_response(self, msg):
        client = self.get_client()
        (id_2FA, msg_out) = client.cc.card_crypt_transaction_2FA(msg, True)
        d = {}
        d['msg_encrypt'] = msg_out
        d['id_2FA'] = id_2FA
        _logger.info("id_2FA: " + id_2FA)

        reply_encrypt = None
        hmac = 20 * "00"  # default response (reject)
        status_msg = ""

        # get server_2FA from config from existing object
        server_2FA = self.plugin.config.get(
            "satochip_2FA_server", default=SERVER_LIST[0])
        status_msg += f"2FA request sent to '{server_2FA}' \nApprove or reject request on your second device."
        try:
            self.handler.show_message(status_msg)
            try:
                Satochip2FA.do_challenge_response(d, server_name=server_2FA)
                # decrypt and parse reply to extract challenge response
                reply_encrypt = d['reply_encrypt']
            except Exception:
                status_msg += f"\nFailed to contact cosigner! \n=> Select another 2FA server in Satochip settings\n\n"
                self.handler.show_message(status_msg)
            if reply_encrypt is not None:
                reply_decrypt = client.cc.card_crypt_transaction_2FA(
                    reply_encrypt, False)
                _logger.info("challenge:response= " + reply_decrypt)
                reply_decrypt = reply_decrypt.split(":")
                hmac = reply_decrypt[1]
        except Exception as ex:
            _logger.info(f"do_challenge_response: exception with handler: {ex}")
        finally:
            _logger.info(f"[Satochip_KeyStore] do_challenge_response: finally")
            self.handler.finished()

        return hmac  # return a hexstring


class SatochipPlugin(HW_PluginBase):
    libraries_available = True
    minimum_library = (0, 0, 0)
    keystore_class = Satochip_KeyStore
    DEVICE_IDS = [
        (SATOCHIP_VID, SATOCHIP_PID)
    ]
    SUPPORTED_XTYPES = ('standard', 'p2wpkh-p2sh',
                        'p2wpkh', 'p2wsh-p2sh', 'p2wsh', 'p2tr')
    
    # Minimum protocol version for Taproot support (v0.14+)
    MIN_TAPROOT_VERSION = 14

    def __init__(self, parent, config, name):
        _logger.info(f"[SatochipPlugin] init()")
        HW_PluginBase.__init__(self, parent, config, name)
        self.device_manager().register_enumerate_func(self.detect_smartcard_reader)


    @staticmethod
    def _explain_cardconnection_error(exc: Exception) -> str:
        """
        Map low-level CardConnectionException messages to user-friendly explanations.
        This runs in the HW-wallet thread; keep it cheap and side-effect free.
        """
        text = str(exc)
        # Card is visible to PC/SC but reported as unpowered or not fully inserted.
        if "Card is unpowered" in text:
            return _(
                "Electrum could see your smart card reader, but the Satochip card "
                "was reported as unpowered or not fully inserted.\n\n"
                "Please check that the card is firmly inserted in the reader, the reader "
                "is powered and connected directly (avoid unpowered USB hubs), and that "
                "no other application is currently using the card, then try again."
            )
        # Reader/driver rejected the protocol requested by pyscard (T=0/T=1).
        if "Invalid protocol in transmit" in text:
            return _(
                "Your smart card reader or its operating system driver rejected the "
                "communication protocol required by the Satochip card.\n\n"
                "This is usually a limitation or bug in the reader/driver combination "
                "on this system. Try a different smart card reader, update the reader's "
                "driver/firmware, or use the documented remote pcscd setup for Satochip."
            )
        # Generic fallback: still surface the technical detail for advanced users.
        return _(
            "Electrum could not establish a connection to your Satochip card.\n\n"
            "Low-level error: {}"
        ).format(text)

    def get_library_version(self) -> str:
        """Return the version of the pysatochip library we are using."""
        return pysatochip.__version__

    def detect_smartcard_reader(self):
        _logger.info(f"[SatochipPlugin] detect_smartcard_reader")
        self.cardtype = AnyCardType()


        # First, check if there is at least one PC/SC reader. We want to keep
        # showing a Satochip entry in the device list even if no card is
        # inserted, as long as a reader is available.
        try:
            pcsc_readers = list_pcsc_readers()
        except Exception as exc:
            _logger.info(f"PC/SC reader enumeration failed: {exc}")

            return []

        if not pcsc_readers:
            _logger.info("No PC/SC readers detected for Satochip.")

            return []

        # Optionally, try a short CardRequest to see if a card is already
        # present. We ignore timeouts here so that the reader still shows up
        # even when empty.
        try:
            cardrequest = CardRequest(timeout=0.1, cardType=self.cardtype)
            try:
                cardservice = cardrequest.waitforcard()

            except CardRequestTimeoutException:
                _logger.info("PC/SC reader detected but no Satochip card present.")

        except Exception as exc:
            _logger.info(f"Error during CardRequest: {exc}")


        # Regardless of whether a card is inserted, as long as we have at least
        # one PC/SC reader we expose a single logical Satochip device. The
        # client (CardConnector) will manage card insertion/removal events.
        return [Device(path="/satochip",
                       interface_number=-1,
                       id_="/satochip",
                       product_key=(SATOCHIP_VID, SATOCHIP_PID),
                       usage_page=0,
                       transport_ui_string='ccid')]

    @runs_in_hwd_thread
    def create_client(self, device, handler):
        _logger.info(f"[SatochipPlugin] create_client()")

        if handler:
            self.handler = handler

        try:
            rv = SatochipClient(self, handler)
            return rv
        except CardConnectionException as e:
            # Map low-level PC/SC error to a user-facing explanation.
            friendly = self._explain_cardconnection_error(e)
            _logger.error(f"[SatochipPlugin] create_client() CardConnectionException: {e!r} -> {friendly}")

            if handler:
                try:
                    handler.show_error(friendly)
                except Exception:
                    # Handler issues should not hide the original problem.
                    pass
            # Raise a UserFacingException so higher layers can surface a clear message.
            raise UserFacingException(friendly)
        except Exception as e:
            _logger.exception(
                f"[SatochipPlugin] create_client() exception: {str(e)}")
            return None

    def get_xpub(self, device_id, derivation, xtype, wizard):
        # this seems to be part of the pairing process only, not during normal ops?
        # base_wizard:on_hw_derivation
        _logger.info(f"[SatochipPlugin] get_xpub()")
        if xtype not in self.SUPPORTED_XTYPES:
            raise ScriptTypeNotSupported(
                _('This type of script is not supported with {}.').format(self.device))
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        client.handler = self.create_handler(wizard)

        xpub = client.get_xpub(derivation, xtype)
        return xpub

    def get_client(self, keystore, force_pair=True, *, devices=None, allow_user_interaction=True):
        # All client interaction should not be in the main GUI thread
        devmgr = self.device_manager()
        handler = keystore.handler
        client = devmgr.client_for_keystore(self, handler, keystore, force_pair,
                                            devices=devices,
                                            allow_user_interaction=allow_user_interaction)
        # returns the client for a given keystore. can use xpub
        return client

    def _setup_device(self, settings, device_id, handler):
        _logger.info(f"[SatochipPlugin] _setup_device()")

        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        if not client:
            raise Exception(_("The device was disconnected."))

        # Check current card state before attempting setup
        _logger.info(f"[SatochipPlugin] _setup_device(): checking card state before setup...")
        try:
            (_r, _sw1, _sw2, status) = client.cc.card_get_status()
            setup_done = status.get('setup_done')
            is_seeded = status.get('is_seeded')
            _logger.info(f"[SatochipPlugin] _setup_device(): card state = setup_done={setup_done}, is_seeded={is_seeded}")
            
            # Check for communication error (setup_done=None indicates unknown state)
            if setup_done is None:
                _logger.error("[SatochipPlugin] _setup_device(): cannot determine card state - communication error?")
                raise UserFacingException(
                    _("Cannot communicate with the card. ") +
                    _("Please check the card reader connection and try again. ") +
                    _("If the problem persists, unplug and replug the card reader.")
                )
            
            # Check if card is already set up
            if setup_done:
                _logger.warning(f"[SatochipPlugin] _setup_device(): card already set up (setup_done=True)")
                if is_seeded:
                    raise UserFacingException(
                        _("This card is already fully initialized with a seed. ") +
                        _("No setup is needed - you can unlock the card directly.")
                    )
                else:
                    raise UserFacingException(
                        _("This card already has a PIN set but no seed. ") +
                        _("You should import a seed instead of running setup again.")
                    )
        except UserFacingException:
            raise
        except Exception as e:
            _logger.warning(f"[SatochipPlugin] _setup_device(): could not check card state: {e}")
            raise UserFacingException(
                _("Cannot communicate with the card: {}").format(e) + " " +
                _("Please check the card reader connection and try again.")
            )
        
        # check that card is indeed a Satochip
        if client.cc.card_type != "Satochip":
            raise Exception(_('Failed to create a client for this device.') + '\n' +
                            _('Inserted card is not a Satochip!'))

        pin_0 = settings
        pin_0 = list(pin_0.encode("utf-8"))
        client.cc.set_pin(0, pin_0)  # cache PIN value in client
        pin_tries_0 = 0x05
        # PUK (Personal Unblocking Key) Configuration - DELIBERATE DESIGN DECISION
        # =========================================================================
        # The PUK is set to random bytes (urandom(16)) and is NEVER shown to the user.
        # We configure ublk_tries_0 = 0x01, meaning only ONE attempt is allowed to unblock.
        # Although the card_unblock_PIN() API exists in pysatochip (CardConnector.py:1893),
        # it is intentionally NOT exposed in this Electrum plugin.
        #
        # CONSEQUENCE: If the user enters the wrong PIN 5 times (pin_tries_0 = 0x05),
        # the card becomes permanently locked/bricked. The user must obtain a new card.
        #
        # This is a deliberate security design choice, not a TODO or missing feature.
        # The secondary PIN/PUK below (pin_1, ublk_1) are similarly configured with
        # random values and single attempt limits, as they are not used by the GUI.
        ublk_tries_0 = 0x01
        ublk_0 = list(urandom(16))
        # the second pin is not used currently, use random values
        pin_tries_1 = 0x01
        ublk_tries_1 = 0x01
        pin_1 = list(urandom(16))
        ublk_1 = list(urandom(16))
        secmemsize = 32  # number of slot reserved in memory cache
        memsize = 0x0000  # RFU
        create_object_ACL = 0x01  # RFU
        create_key_ACL = 0x01  # RFU
        create_pin_ACL = 0x01  # RFU

        # setup
        try:
            (response, sw1, sw2) = client.cc.card_setup(pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                                                        pin_tries_1, ublk_tries_1, pin_1, ublk_1,
                                                        secmemsize, memsize,
                                                        create_object_ACL, create_key_ACL, create_pin_ACL)
            if sw1 == 0x90 and sw2 == 0x00:
                _logger.info(
                    f"[SatochipPlugin] _setup_device(): setup applet successfully!")
                client.handler.show_message(
                    f"Satochip setup performed successfully!")
            elif sw1 == 0x9c and sw2 == 0x07:
                # SW_OBJECT_NOT_FOUND (0x9C07): Card already has PIN/objects set up
                # This should not happen if the pre-check above worked, but handle it anyway
                _logger.error(
                    f"[SatochipPlugin] _setup_device(): card_setup returned 0x9C07 (SW_OBJECT_NOT_FOUND) - "
                    f"card already initialized. This may indicate a race condition or communication issue.")
                raise UserFacingException(
                    _("This card is already initialized. ") +
                    _("If you want to set up this card, you need to factory reset it first."))
            else:
                sw_code = f"0x{sw1:02x}{sw2:02x}"
                _logger.error(
                    f"[SatochipPlugin] _setup_device(): card_setup failed with SW={sw_code}")
                # Provide helpful context for common errors
                if sw1 == 0x6e:
                    raise UserFacingException(
                        _("Card reader communication error (SW={}). ").format(sw_code) +
                        _("Please unplug and replug the card reader, then try again."))
                else:
                    raise UserFacingException(
                        _("Failed to set up card (error code: {}").format(sw_code) + ")")
        except Exception as ex:
            _logger.error(
                f"[SatochipPlugin] _setup_device(): exception during setup: {ex}")
            raise

        # verify pin:
        client.verify_PIN()

    def _import_seed(self, settings, device_id, handler):
        _logger.info(f"[SatochipPlugin] _import_seed()")

        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        if not client:
            raise Exception(_("The device was disconnected."))

        seed_type, seed, passphrase = settings

        # check seed type:
        if seed_type != 'bip39':
            _logger.error(
                f"[SatochipPlugin] _import_seed() wrong seed type!")
            raise UserFacingException(_(f'Wrong seed type {seed_type}: only BIP39 is supported!'))

        # check seed validity
        (is_checksum_valid, is_wordlist_valid) = bip39_is_checksum_valid(seed)
        if is_checksum_valid and is_wordlist_valid:
            _logger.info(
                f"[SatochipPlugin] _import_seed() seed format is valid!")
            masterseed_bytes = bip39_to_seed(seed, passphrase=passphrase)
            masterseed_list = list(masterseed_bytes)
        else:
            _logger.error(
                f"[SatochipPlugin] _import_seed() wrong seed format!")
            raise UserFacingException(_('Wrong BIP39 mnemonic format!'))

        # verify pin:
        client.verify_PIN()

        # import seed
        try:
            authentikey = client.cc.card_bip32_import_seed(masterseed_list)
            _logger.info(
                f"[SatochipPlugin] _import_seed(): seed imported successfully!")
            hex_authentikey = authentikey.get_public_key_hex(compressed=True)
            _logger.info(
                f"[SatochipPlugin] _import_seed(): authentikey={hex_authentikey}")
        except Exception as ex:
            _logger.error(
                f"[SatochipPlugin] _import_seed(): exception during seed import: {ex}")
            raise ex

    def wizard_entry_for_device(self, device_info: 'DeviceInfo', *, new_wallet=True) -> str:
        _logger.info(f"[SatochipPlugin] wizard_entry_for_device()")
        _logger.info(
            f"[SatochipPlugin] wizard_entry_for_device() device_info: {device_info}")
        _logger.info(
            f"[SatochipPlugin] wizard_entry_for_device() new_wallet: {new_wallet}")

        # Blocked cards (PIN tries exhausted) get the factory-reset page first.
        label_str = (device_info.label or "").lower()
        if "blocked" in label_str:
            _logger.info("[SatochipPlugin] wizard_entry_for_device() device is blocked -> satochip_blocked")
            return 'satochip_blocked'

        device_state = device_info.initialized  # can be None, False or True.
        # None is used to distinguish a completely new card from a card where the seed has been reset, but the PIN is still set.
        _logger.info(
            f"[SatochipPlugin] wizard_entry_for_device() device_state: {device_state}")
        if new_wallet:
            if device_state is None:
                return 'satochip_not_setup'
            elif device_state is False:
                return 'satochip_not_seeded'
            else:
                return 'satochip_start'
        else:
            # For existing wallets, the card MUST be seeded (device_state=True)
            # If not seeded, offer to import the seed that matches the wallet
            if device_state is None:
                # Factory-fresh card - user must set up PIN first, then import seed
                _logger.info(
                    f"[SatochipPlugin] wizard_entry_for_device() existing wallet with factory-fresh Satochip - needs setup")
                return 'satochip_recover_setup'
            elif device_state is False:
                # PIN set but no seed - user can import seed directly
                _logger.info(
                    f"[SatochipPlugin] wizard_entry_for_device() existing wallet with unseeded Satochip - needs seed")
                return 'satochip_recover_seed'
            else:
                return 'satochip_unlock'

    # insert satochip pages in new wallet wizard
    def extend_wizard(self, wizard: 'NewWalletWizard'):
        _logger.info(f"[SatochipPlugin] extend_wizard()")
        views = {
            'satochip_start': {
                'next': 'satochip_xpub',
            },
            'satochip_xpub': {
                'next': lambda d: wizard.wallet_password_view(d) if wizard.last_cosigner(d) else 'multisig_cosigner_keystore',
                'accept': wizard.maybe_master_pubkey,
                'last': lambda d: wizard.is_single_password() and wizard.last_cosigner(d)
            },
            'satochip_not_setup': {
                'next': 'satochip_do_setup',
            },
            'satochip_do_setup': {
                'next': 'satochip_not_seeded',
            },
            'satochip_not_seeded': {
                'next': lambda d: 'satochip_have_seed'
                                  if d.get('satochip_seed_method') == 'import'
                                  else 'satochip_generate_seed',
            },
            'satochip_generate_seed': {
                'next': lambda d: 'satochip_have_ext' if wizard.wants_ext(d) else 'satochip_import_seed',
            },
            'satochip_import_seed': {
                'next': 'satochip_success_seed',
            },
            'satochip_success_seed': {
                'next': 'satochip_start',
            },
            'satochip_unlock': {
                'last': True
            },
            'satochip_wrong_card': {
                'last': True
            },
            # Seed recovery for existing wallets
            'satochip_recover_setup': {
                'next': 'satochip_recover_seed',
            },
            'satochip_recover_seed': {
                'last': True  # Will trigger unlock after seed import
            },
        }
        wizard.navmap_merge(views)

    def show_address(self, wallet, address, keystore=None):
        if keystore is None:
            keystore = wallet.get_keystore()
        if not self.show_address_helper(wallet, address, keystore):
            return

        # Standard_Wallet => not multisig, must be bip32
        if type(wallet) is not Standard_Wallet:
            keystore.handler.show_error(
                _('This function is only available for standard wallets when using {}.').format(self.device))
            return

        sequence = wallet.get_address_index(address)
        txin_type = wallet.get_txin_type(address)
        keystore.show_address(sequence, txin_type)


instrument_module_function_entries(_logger, globals(), __name__)
