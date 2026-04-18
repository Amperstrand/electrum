import time
import hashlib
from typing import Optional, TYPE_CHECKING

import electrum_ecc as ecc
from electrum_ecc.util import bip340_tagged_hash

from electrum import constants
from electrum.bitcoin import var_int
from electrum.i18n import _
from electrum.plugin import Device, DeviceInfo, runs_in_hwd_thread
from electrum.keystore import (
    Hardware_KeyStore,
    bip39_to_seed,
    bip39_is_checksum_valid,
    ScriptTypeNotSupported,
)
from electrum.transaction import Sighash
from electrum.wallet import Standard_Wallet
from electrum.wizard import NewWalletWizard
from electrum.util import UserFacingException
from electrum.crypto import hash_160, sha256d
from electrum.bip32 import (
    BIP32Node,
    convert_bip32_strpath_to_intpath,
    convert_bip32_intpath_to_strpath,
)
from electrum.logging import get_logger

from electrum.hw_wallet import HW_PluginBase, HardwareClientBase

if TYPE_CHECKING:
    pass

_logger = get_logger(__name__)

SATOCHIP_VID = 0
SATOCHIP_PID = 0

try:
    from smartcard.System import readers as list_pcsc_readers
    from smartcard.Exceptions import (
        CardRequestTimeoutException,
        CardConnectionException,
    )
    from smartcard.CardType import AnyCardType
    from smartcard.CardRequest import CardRequest

    from .card_connector import CardConnector
    from .card_connector import (
        UninitializedSeedError,
        CardNotPresentError,
        UnexpectedSW12Error,
        WrongPinError,
        PinBlockedError,
        PinRequiredError,
        CardSetupNotDoneError,
    )

    SMARTCARD = True
except Exception as e:
    if not (isinstance(e, ModuleNotFoundError) and e.name == "smartcard"):
        _logger.exception("error importing satochip plugin deps")
    SMARTCARD = False


def _bip32path2bytes(bip32path: str):
    """Convert BIP32 string path to (depth, bytes)."""
    int_path = convert_bip32_strpath_to_intpath(bip32path)
    depth = len(int_path)
    byte_path = b""
    for index in int_path:
        byte_path += index.to_bytes(4, byteorder="big", signed=False)
    return depth, byte_path


# ---------------------------------------------------------------------------
# SatochipClient – wraps CardConnector into the HardwareClientBase interface
# ---------------------------------------------------------------------------


class SatochipClient(HardwareClientBase):
    def __init__(self, plugin: HW_PluginBase, handler):
        HardwareClientBase.__init__(self, plugin=plugin)
        self._soft_device_id = None
        self.device = plugin.device
        self.handler = handler
        self.cc = CardConnector(self)
        self.last_operation = float("inf")

    def __repr__(self):
        try:
            return "<SatochipClient: label=%r>" % (self.label(),)
        except Exception:
            return "<SatochipClient: (disconnected)>"

    # -- HardwareClientBase abstract methods --------------------------------

    def is_pairable(self):
        return True

    @runs_in_hwd_thread
    def close(self):
        self.cc.card_disconnect()
        self.cc.cardmonitor.deleteObserver(self.cc.cardobserver)

    def timeout(self, cutoff):
        """Clear cached PIN if the last operation was before *cutoff*."""
        if self.last_operation < cutoff:
            _logger.info("Satochip session timed out, clearing PIN cache")
            if hasattr(self.cc, "set_pin"):
                self.cc.set_pin(0, None)

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
        try:
            if self.cc.cardservice is None:
                return False
            self.cc.card_get_ATR()
        except Exception:
            return False
        return True

    @runs_in_hwd_thread
    def get_xpub(self, bip32_path, xtype):
        assert xtype in SatochipPlugin.SUPPORTED_XTYPES
        self.verify_PIN()

        _logger.info(f"get_xpub(): bip32_path={bip32_path}")
        (depth, bytepath) = _bip32path2bytes(bip32_path)
        try:
            (childkey, childchaincode) = self.cc.card_bip32_get_extendedkey(bytepath)
        except UninitializedSeedError as e:
            raise UserFacingException(str(e))

        if depth == 0:
            fingerprint = bytes([0, 0, 0, 0])
            child_number = bytes([0, 0, 0, 0])
        else:
            (parentkey, parentchaincode) = self.cc.card_bip32_get_extendedkey(
                bytepath[0:-4]
            )
            fingerprint = hash_160(parentkey.get_public_key_bytes(compressed=True))[0:4]
            child_number = bytepath[-4:]

        xpub = BIP32Node(
            xtype=xtype,
            eckey=childkey,
            chaincode=childchaincode,
            depth=depth,
            fingerprint=fingerprint,
            child_number=child_number,
        ).to_xpub()
        _logger.info(f"get_xpub(): xpub={xpub}")
        return xpub

    # -- label / device-id --------------------------------------------------

    _CARD_LABEL_SENTINELS = frozenset({"(none)", "(unknown)"})

    def label(self):
        try:
            if not self._ensure_card_connection():
                return "Satochip"
            status = None
            try:
                self.cc.card_get_status()
            except CardNotPresentError:
                return "Satochip (no card inserted)"
            except PinBlockedError:
                return "Satochip [blocked]"
            except Exception:
                pass

            base_label = None
            # 1. card-set label
            if self.cc and hasattr(self.cc, "card_get_label"):
                try:
                    (_, _, _, card_label) = self.cc.card_get_label()
                    if (
                        card_label
                        and card_label not in self._CARD_LABEL_SENTINELS
                        and card_label.strip()
                    ):
                        base_label = f"Satochip: {card_label}"
                except Exception:
                    pass

            # 2. fingerprint from authentikey
            if base_label is None:
                parser = getattr(self.cc, "parser", None)
                if parser is not None:
                    coordx = getattr(parser, "authentikey_coordx", None)
                    if coordx:
                        fp = hash_160(bytes(coordx))[:4]
                        base_label = f"Satochip {fp.hex()}"

            if base_label is None:
                base_label = "Satochip"

            return base_label
        except Exception:
            return "Satochip"

    def device_model_name(self):
        return "Satochip"

    def get_soft_device_id(self):
        return self._soft_device_id

    # -- PIN helpers --------------------------------------------------------

    def verify_PIN(self, pin=None):
        """Verify card PIN, prompting the user if needed. Returns True on success."""
        while True:
            try:
                self.cc.card_verify_PIN_simple(pin)
                return True
            except CardNotPresentError:
                msg = _("No card found!\nPlease insert card, then enter your PIN:")
                (is_PIN, pin) = self.PIN_dialog(msg)
                if not is_PIN:
                    return False
            except PinRequiredError:
                msg = _("Enter the PIN for your card:")
                (is_PIN, pin) = self.PIN_dialog(msg)
                if not is_PIN:
                    return False
            except WrongPinError as ex:
                pin = None
                msg = _(
                    "Wrong PIN! {} tries remaining!\nEnter the PIN for your card:"
                ).format(ex.pin_left)
                (is_PIN, pin) = self.PIN_dialog(msg)
                if not is_PIN:
                    return False
            except PinBlockedError:
                raise UserFacingException(
                    _(
                        "Your Satochip PIN is blocked. The card must be factory-reset before it can be used again."
                    )
                )
            except CardSetupNotDoneError:
                raise UserFacingException(
                    _(
                        "This Satochip has not been set up yet.\n\n"
                        "The card needs to be initialized with a PIN and seed before it can be used."
                    )
                )
            except UnexpectedSW12Error as ex:
                raise UserFacingException(
                    f"Unexpected error during PIN verification: {ex}"
                )
            except Exception as ex:
                raise UserFacingException(
                    f"Unexpected error during PIN verification: {ex}"
                )

    def PIN_dialog(self, msg):
        """Show PIN entry dialog. Returns (True, pin_bytes) or (False, None)."""
        while True:
            password = self.handler.get_passphrase(msg, False)
            if password is None:
                return False, None
            if len(password) < 4:
                msg = (
                    _("PIN must have at least 4 characters.") + "\n\n" + _("Enter PIN:")
                )
            elif len(password) > 16:
                msg = (
                    _("PIN must have less than 16 characters.")
                    + "\n\n"
                    + _("Enter PIN:")
                )
            else:
                return True, password.encode("utf8")

    def PIN_setup_dialog(self, msg, msg_confirm, msg_error):
        while True:
            (is_PIN, pin) = self.PIN_dialog(msg)
            if not is_PIN:
                raise RuntimeError("A PIN code is required to initialize the Satochip!")
            (is_PIN, pin_confirm) = self.PIN_dialog(msg_confirm)
            if not is_PIN:
                raise RuntimeError(
                    "A PIN confirmation is required to initialize the Satochip!"
                )
            if pin != pin_confirm:
                self.request("show_error", msg_error)
            else:
                return is_PIN, pin

    # -- handler communication -----------------------------------------------

    def request(self, request_type, *args):
        if self.handler is not None:
            if request_type == "update_status":
                return self.handler.update_status(*args)
            elif request_type == "show_error":
                return self.handler.show_error(*args)
            elif request_type == "show_message":
                return self.handler.show_message(*args)
            else:
                return self.handler.show_error("Unknown request: " + str(request_type))
        return None

    # -- card connection helpers --------------------------------------------

    def _ensure_card_connection(self, timeout: float = 3.0) -> bool:
        start = time.time()
        while (time.time() - start) < timeout:
            if not getattr(self.cc, "card_present", False):
                time.sleep(0.15)
                continue
            cs = getattr(self.cc, "cardservice", None)
            if cs is not None and hasattr(getattr(cs, "connection", None), "transmit"):
                return True
            time.sleep(0.15)
        return False

    @runs_in_hwd_thread
    def get_authentikey_fingerprint(self) -> Optional[str]:
        """Get 4-byte fingerprint from the card's authentikey, or None."""
        try:
            parser = getattr(self.cc, "parser", None)
            if parser is not None:
                coordx = getattr(parser, "authentikey_coordx", None)
                if coordx is not None:
                    fp = hash_160(bytes(coordx))[:4]
                    return fp.hex()
            self.verify_PIN()
            authentikey = self.cc.card_export_authentikey()
            if authentikey:
                pubkey = authentikey.get_public_key_bytes(compressed=True)
                fp = hash_160(pubkey)[:4]
                return fp.hex()
        except Exception as e:
            _logger.debug(f"get_authentikey_fingerprint(): error: {e}")
        return None

    def supports_taproot(self):
        """Check if the card firmware supports Taproot (protocol v0.14+)."""
        try:
            if self.cc.protocol_version is None:
                self.cc.card_get_status()
            return self.cc.protocol_version >= SatochipPlugin.MIN_TAPROOT_VERSION
        except Exception:
            return False


# ---------------------------------------------------------------------------
# SatochipKeyStore
# ---------------------------------------------------------------------------


class SatochipKeyStore(Hardware_KeyStore):
    hw_type = "satochip"
    device = "Satochip"
    plugin: "SatochipPlugin"

    def __init__(self, d):
        Hardware_KeyStore.__init__(self, d)
        self.ux_busy = False
        self._satochip_authentikey = d.get("satochip_authentikey", None)
        self._expected_device = None

    def dump(self):
        d = Hardware_KeyStore.dump(self)
        d["satochip_authentikey"] = self._satochip_authentikey
        return d

    def get_client(self, force_pair=True, *, devices=None, allow_user_interaction=True):
        client = super().get_client(
            force_pair=force_pair,
            devices=devices,
            allow_user_interaction=allow_user_interaction,
        )
        if client:
            self.verify_connection(client)
        return client

    def verify_connection(self, client: "SatochipClient"):
        expected = self._satochip_authentikey
        if expected is None:
            self.opportunistically_fill_in_missing_info_from_device(client)
            return
        actual = client.get_authentikey_fingerprint()
        if actual is None:
            return
        if self._expected_device == actual:
            return
        if actual != expected:
            raise UserFacingException(
                _(
                    "Wrong Satochip connected! This card does not match the wallet. "
                    "Please connect the correct Satochip for this wallet."
                )
            )
        self._expected_device = actual

    def opportunistically_fill_in_missing_info_from_device(
        self, client: "SatochipClient"
    ):
        super().opportunistically_fill_in_missing_info_from_device(client)
        if self._satochip_authentikey is None:
            authentikey = client.get_authentikey_fingerprint()
            if authentikey:
                self._satochip_authentikey = authentikey
                self.is_requesting_to_be_rewritten_to_wallet_file = True

    def decrypt_message(self, sequence, message, password):
        raise UserFacingException(
            _("Encryption and decryption are not implemented by {}").format(self.device)
        )

    def sign_message(self, sequence, message, password, *, script_type=None):
        message_byte = message.encode("utf8")
        client = self.get_client()
        if not client.verify_PIN():
            return b""

        address_path = self.get_derivation_prefix() + "/%d/%d" % sequence
        _logger.info(f"sign_message: path={address_path}")

        try:
            keynbr = 0xFF  # extended key
            (depth, bytepath) = _bip32path2bytes(address_path)
            (pubkey, chaincode) = client.cc.card_bip32_get_extendedkey(bytepath)
            (_, _, _, compsig) = client.cc.card_sign_message(
                keynbr, pubkey, message_byte
            )
            if compsig == b"":
                self.handler.show_error(_("Wrong signature!"))
            return compsig
        except CardNotPresentError:
            self.handler.show_error(
                _("Card not detected. Please insert your Satochip.")
            )
            return b""
        except PinBlockedError:
            self.handler.show_error(_("PIN is blocked."))
            return b""
        except Exception as e:
            self.handler.show_error(_("Failed to sign message.") + "\n" + str(e))
            return b""
        finally:
            self.handler.finished()

    def sign_transaction(self, tx, password):
        if tx.is_complete():
            return
        prev_tx = {}
        for txin in tx.inputs():
            tx_hash = txin.prevout.txid.hex()
            if txin.utxo is None:
                raise UserFacingException(_("Missing previous tx."))
            prev_tx[tx_hash] = txin.utxo
        self.plugin.sign_transaction(self, tx, prev_tx)

    def show_address(self, sequence, txin_type):
        from electrum import bitcoin

        client = self.get_client()
        if not client.verify_PIN():
            return

        address_path = self.get_derivation_prefix() + "/%d/%d" % sequence
        try:
            (depth, bytepath) = _bip32path2bytes(address_path)
            (pubkey, chaincode) = client.cc.card_bip32_get_extendedkey(bytepath)
            pubkey_hex = pubkey.get_public_key_bytes(compressed=True).hex()
            address = bitcoin.pubkey_to_address(txin_type, pubkey_hex)
            self.handler.show_message(
                _("Address:") + f" {address}\n" + _("Derivation:") + f" {address_path}"
            )
        except Exception as e:
            self.handler.show_error(
                _("Could not communicate with card.") + "\n" + str(e)
            )
        finally:
            self.handler.finished()


# ---------------------------------------------------------------------------
# SatochipPlugin
# ---------------------------------------------------------------------------


class SatochipPlugin(HW_PluginBase):
    keystore_class = SatochipKeyStore
    libraries_available = SMARTCARD
    minimum_library = (0, 0, 0)
    DEVICE_IDS = ((SATOCHIP_VID, SATOCHIP_PID),)
    SUPPORTED_XTYPES = (
        "standard",
        "p2wpkh-p2sh",
        "p2wpkh",
        "p2wsh-p2sh",
        "p2wsh",
        "p2tr",
    )

    MIN_TAPROOT_VERSION = 14

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)
        if not self.libraries_available:
            return
        self.device_manager().register_enumerate_func(self.detect_smartcard_reader)

    def get_library_version(self):
        try:
            import smartcard

            return getattr(smartcard, "__version__", "unknown")
        except Exception:
            return "unknown"

    @runs_in_hwd_thread
    def detect_smartcard_reader(self):
        """Enumerate PC/SC readers. Returns a Device for each reader found."""
        try:
            pcsc_readers = list_pcsc_readers()
        except Exception:
            return []

        if not pcsc_readers:
            return []

        # As long as at least one PC/SC reader is present, expose a single
        # logical Satochip device. The CardConnector manages card
        # insertion/removal events internally.
        return [
            Device(
                path="/satochip",
                interface_number=-1,
                id_="/satochip",
                product_key=(SATOCHIP_VID, SATOCHIP_PID),
                usage_page=0,
                transport_ui_string="ccid",
            )
        ]

    @runs_in_hwd_thread
    def create_client(self, device, handler):
        if handler:
            self.handler = handler
        try:
            return SatochipClient(self, handler)
        except CardConnectionException as e:
            raise UserFacingException(
                _("Could not connect to Satochip card reader: {}").format(e)
            )
        except Exception as e:
            _logger.exception(f"create_client() exception: {e}")
            return None

    def get_xpub(self, device_id, derivation, xtype, wizard):
        if xtype not in self.SUPPORTED_XTYPES:
            raise ScriptTypeNotSupported(
                _("This type of script is not supported with {}.").format(self.device)
            )
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        client.handler = self.create_handler(wizard)
        return client.get_xpub(derivation, xtype)

    def get_client(
        self, keystore, force_pair=True, *, devices=None, allow_user_interaction=True
    ):
        devmgr = self.device_manager()
        handler = keystore.handler
        return devmgr.client_for_keystore(
            self,
            handler,
            keystore,
            force_pair,
            devices=devices,
            allow_user_interaction=allow_user_interaction,
        )

    def create_handler(self, window):
        # Defer to cmdline handler; Qt override in qt.py
        from electrum.hw_wallet.cmdline import CmdLineHandler

        return CmdLineHandler()

    # -- device setup -------------------------------------------------------

    @runs_in_hwd_thread
    def setup_device(self, device_info, wizard, purpose):
        """Set up an uninitialized Satochip card (PIN + optional seed import).

        *purpose* is one of the constants in NewWalletWizard
        (e.g. HWD_SETUP_NEW_WALLET, HWD_SETUP_DECRYPT_WALLET).
        """
        device_id = device_info.device.id_
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        if not client:
            raise Exception(_("The device was disconnected."))
        client.handler = self.create_handler(wizard)

        # If the card is already set up, nothing to do.
        try:
            time.sleep(0.3)
            if not client._ensure_card_connection():
                raise UserFacingException(_("Cannot communicate with the card."))
            self.cc = client.cc
            (_, _, _, status) = client.cc.card_get_status()
            if status.get("setup_done"):
                return
        except UserFacingException:
            raise
        except Exception:
            pass

    @runs_in_hwd_thread
    def _setup_device(self, pin_str, device_id, handler):
        """Low-level: send card_setup APDU with the given PIN string."""
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        if not client:
            raise Exception(_("The device was disconnected."))

        from os import urandom

        pin_0 = list(pin_str.encode("utf-8"))
        client.cc.set_pin(0, pin_0)

        pin_tries_0 = 0x05
        ublk_tries_0 = 0x01
        ublk_0 = list(urandom(16))
        pin_tries_1 = 0x01
        ublk_tries_1 = 0x01
        pin_1 = list(urandom(16))
        ublk_1 = list(urandom(16))
        secmemsize = 32
        memsize = 0x0000
        create_object_ACL = 0x01
        create_key_ACL = 0x01
        create_pin_ACL = 0x01

        (response, sw1, sw2) = client.cc.card_setup(
            pin_tries_0,
            ublk_tries_0,
            pin_0,
            ublk_0,
            pin_tries_1,
            ublk_tries_1,
            pin_1,
            ublk_1,
            secmemsize,
            memsize,
            create_object_ACL,
            create_key_ACL,
            create_pin_ACL,
        )
        if sw1 != 0x90 or sw2 != 0x00:
            raise UserFacingException(
                _("Failed to set up card (error code: 0x{:02x}{:02x})").format(sw1, sw2)
            )

        client.verify_PIN()

    @runs_in_hwd_thread
    def _import_seed(self, settings, device_id, handler):
        """Import a BIP-39 seed into the card."""
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        if not client:
            raise Exception(_("The device was disconnected."))

        seed_type, seed, passphrase = settings

        if seed_type != "bip39":
            raise UserFacingException(_("Only BIP39 seeds are supported!"))

        (is_checksum_valid, is_wordlist_valid) = bip39_is_checksum_valid(seed)
        if not (is_checksum_valid and is_wordlist_valid):
            raise UserFacingException(_("Wrong BIP39 mnemonic format!"))

        masterseed_bytes = bip39_to_seed(seed, passphrase=passphrase)
        masterseed_list = list(masterseed_bytes)

        client.verify_PIN()

        authentikey = client.cc.card_bip32_import_seed(masterseed_list)
        if authentikey:
            _logger.info("Seed imported successfully.")

    # -- signing ------------------------------------------------------------

    @runs_in_hwd_thread
    def sign_transaction(self, keystore, tx, prev_tx):
        client = self.get_client(keystore)
        client.verify_PIN()

        segwit_tx = False

        # Precompute serialized outputs and their hash
        tx_outputs = bytearray()
        tx_outputs += var_int(len(tx.outputs()))
        for o in tx.outputs():
            tx_outputs += int.to_bytes(
                o.value, length=8, byteorder="little", signed=False
            )
            script = o.scriptpubkey
            tx_outputs += var_int(len(script))
            tx_outputs += script
        tx_outputs = bytes(tx_outputs)

        for i, txin in enumerate(tx.inputs()):
            if tx.is_complete():
                break

            desc = txin.script_descriptor
            assert desc
            script_type = desc.to_legacy_electrum_script_type()

            if txin.is_coinbase_input():
                raise UserFacingException("Coinbase not supported")

            if script_type in ("p2wpkh", "p2wsh", "p2wpkh-p2sh", "p2wsh-p2sh", "p2tr"):
                segwit_tx = True

            my_pubkey, input_path = keystore.find_my_pubkey_in_txinout(txin)
            if not input_path:
                raise UserFacingException("No matching pubkey for sign_transaction")
            input_path = convert_bip32_intpath_to_strpath(input_path)

            is_taproot = script_type == "p2tr"
            if is_taproot and not client.supports_taproot():
                raise UserFacingException(
                    _(
                        "Your Satochip does not support Taproot. "
                        "Taproot requires firmware v0.14 or newer."
                    )
                )

            # Get extended key
            (_, bytepath) = _bip32path2bytes(input_path)
            client.cc.card_bip32_get_extendedkey(bytepath)

            # Parse tx preimage
            pre_tx = tx.serialize_preimage(i)
            pre_hash = sha256d(pre_tx)
            (_, _, _, tx_hash_list, _needs_2fa) = client.cc.card_parse_transaction(
                pre_tx, segwit_tx
            )
            tx_hash = bytearray(tx_hash_list)
            if pre_hash != tx_hash:
                raise RuntimeError("Tx preimage mismatch")

            keynbr = 0xFF

            if is_taproot:
                tap_hash = bip340_tagged_hash(b"TapSighash", pre_hash)
                (tx_sig, sw1, sw2) = client.cc.card_sign_schnorr_hash(
                    keynbr, list(tap_hash)
                )
                if sw1 != 0x90 or sw2 != 0x00:
                    raise UserFacingException(
                        _(
                            "Satochip failed to sign Taproot transaction (error 0x{:02x}{:02x})"
                        ).format(sw1, sw2)
                    )
                tx_sig = bytes(tx_sig)
                sighash = txin.sighash if txin.sighash is not None else Sighash.DEFAULT
                tx_sig = tx_sig + Sighash.to_sigbytes(sighash)
            else:
                (tx_sig, sw1, sw2) = client.cc.card_sign_transaction(
                    keynbr, tx_hash_list
                )
                if sw1 != 0x90 or sw2 != 0x00:
                    raise UserFacingException(
                        _(
                            "Satochip failed to sign transaction (error 0x{:02x}{:02x})"
                        ).format(sw1, sw2)
                    )
                tx_sig = bytes(tx_sig)
                # enforce low-S (BIP 62)
                r, s = ecc.get_r_and_s_from_ecdsa_der_sig(tx_sig)
                if s > ecc.CURVE_ORDER // 2:
                    s = ecc.CURVE_ORDER - s
                tx_sig = ecc.ecdsa_der_sig_from_r_and_s(r, s)
                tx_sig = tx_sig + Sighash.to_sigbytes(Sighash.ALL)

            tx.add_signature_to_txin(txin_idx=i, signing_pubkey=my_pubkey, sig=tx_sig)

        tx.raw = tx.serialize()

    @runs_in_hwd_thread
    def sign_message(self, keystore, sequence, message):
        return keystore.sign_message(sequence, message, None)

    @runs_in_hwd_thread
    def show_address(self, wallet, address, keystore=None):
        if keystore is None:
            keystore = wallet.get_keystore()
        if not self.show_address_helper(wallet, address, keystore):
            return
        if type(wallet) is not Standard_Wallet:
            keystore.handler.show_error(
                _(
                    "This function is only available for standard wallets when using {}."
                ).format(self.device)
            )
            return
        sequence = wallet.get_address_index(address)
        txin_type = wallet.get_txin_type(address)
        keystore.show_address(sequence, txin_type)

    # -- wizard integration -------------------------------------------------

    def wizard_entry_for_device(
        self, device_info: "DeviceInfo", *, new_wallet: bool
    ) -> str:
        label_str = (device_info.label or "").lower()
        if "blocked" in label_str:
            return "satochip_blocked"

        device_state = device_info.initialized
        if new_wallet:
            if device_state is None:
                return "satochip_not_setup"
            elif device_state is False:
                return "satochip_not_seeded"
            else:
                return "satochip_start"
        else:
            if device_state is None:
                return "satochip_recover_setup"
            elif device_state is False:
                return "satochip_recover_seed"
            else:
                return "satochip_unlock"

    def extend_wizard(self, wizard: "NewWalletWizard"):
        views = {
            "satochip_start": {
                "next": "satochip_xpub",
            },
            "satochip_xpub": {
                "next": lambda d: (
                    wizard.wallet_password_view(d)
                    if wizard.last_cosigner(d)
                    else "multisig_cosigner_keystore"
                ),
                "accept": wizard.maybe_master_pubkey,
                "last": lambda d: (
                    wizard.is_single_password() and wizard.last_cosigner(d)
                ),
            },
            "satochip_not_setup": {
                "next": "satochip_do_setup",
            },
            "satochip_do_setup": {
                "next": "satochip_not_seeded",
            },
            "satochip_not_seeded": {
                "next": lambda d: (
                    "satochip_have_seed"
                    if d.get("satochip_seed_method") == "import"
                    else "satochip_generate_seed"
                ),
            },
            "satochip_generate_seed": {
                "next": lambda d: (
                    "satochip_have_ext"
                    if wizard.wants_ext(d)
                    else "satochip_import_seed"
                ),
            },
            "satochip_import_seed": {
                "next": "satochip_success_seed",
            },
            "satochip_success_seed": {
                "next": "satochip_start",
            },
            "satochip_unlock": {
                "last": True,
            },
            "satochip_recover_setup": {
                "next": "satochip_recover_seed",
            },
            "satochip_recover_seed": {
                "last": True,
            },
        }
        wizard.navmap_merge(views)
