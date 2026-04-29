"""Satochip plugin: keystore, plugin registration, and wizard integration."""

import time
from typing import TYPE_CHECKING

import electrum_ecc as ecc
from electrum_ecc.util import bip340_tagged_hash

from electrum.bitcoin import var_int
from electrum.i18n import _
from electrum.plugin import Device, runs_in_hwd_thread
from electrum.keystore import (
    Hardware_KeyStore,
    bip39_to_seed,
    bip39_is_checksum_valid,
)
try:
    from electrum.keystore import ScriptTypeNotSupported
except ImportError:
    from electrum.base_wizard import ScriptTypeNotSupported
from electrum.transaction import Sighash
from electrum.util import UserFacingException
from electrum.crypto import sha256d
from electrum.bip32 import convert_bip32_intpath_to_strpath
from electrum.logging import get_logger

try:
    from electrum.hw_wallet import HW_PluginBase
except ImportError:
    from ..hw_wallet import HW_PluginBase

from .client import SatochipClient, _BLOCKED_SUFFIX, _bip32path2bytes

if TYPE_CHECKING:
    from electrum.plugin import DeviceInfo
    from electrum.wallet import Standard_Wallet
    from electrum.wizard import NewWalletWizard

_logger = get_logger(__name__)

SATOCHIP_VID = 0
SATOCHIP_PID = 0

try:
    from smartcard.System import readers as list_pcsc_readers
    from smartcard.Exceptions import CardConnectionException

    SMARTCARD = True
except Exception as e:
    if not (isinstance(e, ModuleNotFoundError) and e.name == "smartcard"):
        _logger.exception("error importing satochip plugin deps")
    SMARTCARD = False


class FactoryResetAlreadyDone(UserFacingException):
    pass


class FactoryResetInProgress(UserFacingException):
    def __init__(self, message, remaining_steps=0):
        super().__init__(message)
        self.remaining_steps = remaining_steps


class FactoryResetCardNotRemoved(UserFacingException):
    pass


def _classify_reader(name: str) -> str:
    n = name.lower()
    if any(t in n for t in ("nfc", "contactless", "picc")):
        return "NFC"
    if any(t in n for t in ("contact", "smart card", "smartcard")):
        return "Contact"
    return ""


def _reader_brand(reader_name: str) -> str:
    first = reader_name.strip().split()[0] if reader_name.strip() else ""
    return first if len(first) <= 12 else ""


def _format_transport(reader_name: str) -> str:
    cls = _classify_reader(reader_name)
    brand = _reader_brand(reader_name)
    if brand and cls:
        return f"{brand} {cls}"
    if cls:
        return cls
    if brand:
        return brand
    return "smartcard"


# ---------------------------------------------------------------------------
# SatochipKeyStore
# ---------------------------------------------------------------------------


class SatochipKeyStore(Hardware_KeyStore):
    hw_type = "satochip"
    device = "Satochip"
    plugin: "SatochipPlugin"

    def __init__(self, d):
        super().__init__(d)
        self.ux_busy = False
        self._satochip_authentikey = d.get("satochip_authentikey", None)
        self._expected_device = None

    def dump(self):
        d = Hardware_KeyStore.dump(self)
        d["satochip_authentikey"] = self._satochip_authentikey
        return d

    def get_client(
        self, force_pair=True, *, devices=None,
        allow_user_interaction=True,
    ):
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
            from .exceptions import WrongCardError
            raise WrongCardError(
                _(
                    "This card does not match your wallet. "
                    "Please connect the card that was used to create "
                    "this wallet."
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
            _(
                "Encryption and decryption are not implemented by {}"
            ).format(self.device)
        )

    def sign_message(self, sequence, message, password, *, script_type=None):
        message_byte = message.encode("utf8")
        client = self.get_client()

        address_path = self.get_derivation_prefix() + "/%d/%d" % sequence
        _logger.info(f"sign_message: path={address_path}")

        with client.run_flow():
            if not client.verify_PIN():
                return b""
            keynbr = 0xFF
            (depth, bytepath) = _bip32path2bytes(address_path)
            (pubkey, chaincode) = (
                client.cc.card_bip32_get_extendedkey(bytepath)
            )
            (_r1, _r2, _r3, compsig) = client.cc.card_sign_message(
                keynbr, pubkey, message_byte
            )
            if compsig == b"":
                self.handler.show_error(_("Wrong signature!"))
            return bytes(compsig)

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
        address_path = self.get_derivation_prefix() + "/%d/%d" % sequence

        with client.run_flow():
            if not client.verify_PIN():
                return
            (depth, bytepath) = _bip32path2bytes(address_path)
            (pubkey, chaincode) = (
                client.cc.card_bip32_get_extendedkey(bytepath)
            )
            pubkey_hex = pubkey.get_public_key_bytes(compressed=True).hex()
            address = bitcoin.pubkey_to_address(txin_type, pubkey_hex)
            self.handler.show_message(
                _("Address:") + f" {address}\n"
                + _("Derivation:") + f" {address_path}"
            )


# ---------------------------------------------------------------------------
# SatochipPlugin
# ---------------------------------------------------------------------------


class SatochipPlugin(HW_PluginBase):
    keystore_class = SatochipKeyStore
    minimum_library = (0, 0, 0)
    maximum_library = (3, 0)
    DEVICE_IDS = ((SATOCHIP_VID, SATOCHIP_PID),)
    SUPPORTED_XTYPES = (
        "standard",
        "p2wpkh-p2sh",
        "p2wpkh",
        "p2wsh-p2sh",
        "p2wsh",
        "p2tr",
    )
    firmware_URL = "https://satochip.io"
    libraries_URL = "https://pypi.org/project/pyscard/"

    MIN_TAPROOT_VERSION = 14

    def __init__(self, parent, config, name):
        super().__init__(parent, config, name)
        self.libraries_available = self.check_libraries_available()
        if not self.libraries_available:
            return
        self.device_manager().register_enumerate_func(
            self.detect_smartcard_reader
        )

    def get_library_version(self):
        try:
            from importlib.metadata import version
            return version("pyscard")
        except Exception:
            return "unknown"

    @runs_in_hwd_thread
    def detect_smartcard_reader(self):
        try:
            pcsc_readers = list_pcsc_readers()
        except Exception:
            return []

        devices = []
        for idx, reader in enumerate(pcsc_readers):
            reader_name = str(reader)
            devices.append(
                Device(
                    path=f"/satochip/{idx}",
                    interface_number=idx,
                    id_=f"/satochip/{idx}",
                    product_key=(SATOCHIP_VID, SATOCHIP_PID),
                    usage_page=0,
                    transport_ui_string=_format_transport(reader_name),
                )
            )
        return devices

    @runs_in_hwd_thread
    def create_client(self, device, handler):
        try:
            return SatochipClient(self, handler, device)
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
                _(
                    "This type of script is not supported with {}."
                ).format(self.device)
            )
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        client.handler = self.create_handler(wizard)
        return client.get_xpub(derivation, xtype)

    def get_client(
        self, keystore, force_pair=True, *,
        devices=None, allow_user_interaction=True,
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
        from ..hw_wallet.cmdline import CmdLineHandler

        return CmdLineHandler()

    # -- device setup -------------------------------------------------------

    def setup_device(self, device_info, wizard, purpose):
        device_id = device_info.device.id_
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        if not client:
            raise Exception(_("The device was disconnected."))
        client.handler = self.create_handler(wizard)

        try:
            time.sleep(0.3)
            if not client._ensure_card_connection():
                raise UserFacingException(
                    _("Cannot communicate with the card.")
                )
            (_r1, _r2, _r3, status) = client.cc.card_get_status()
            if status.get("setup_done"):
                return
        except UserFacingException:
            raise
        except Exception:
            pass

    def _generate_puk(self):
        from os import urandom
        return list(urandom(16))

    @runs_in_hwd_thread
    def _setup_device(self, settings, device_id, handler):
        if isinstance(settings, tuple):
            pin_str, card_label = settings
        else:
            pin_str, card_label = settings, ""

        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        if not client:
            raise Exception(_("The device was disconnected."))

        with client.run_flow():
            from os import urandom

            pin_0 = list(pin_str.encode("utf-8"))
            client.cc.set_pin(0, pin_0)

            pin_tries_0 = 0x05
            ublk_tries_0 = 0x01
            ublk_0 = self._generate_puk()
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
                    _("Failed to set up the card. Please try again.")
                )

            client.verify_PIN()

            if card_label:
                try:
                    client.cc.card_set_label(card_label)
                except Exception:
                    _logger.debug("card_set_label failed", exc_info=True)

    @runs_in_hwd_thread
    def _import_seed(self, settings, device_id, handler):
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

        with client.run_flow():
            client.verify_PIN()

            authentikey = client.cc.card_bip32_import_seed(masterseed_list)
            if authentikey:
                _logger.info("Seed imported successfully.")

    # -- signing ------------------------------------------------------------

    @runs_in_hwd_thread
    def sign_transaction(self, keystore, tx, prev_tx):
        client = self.get_client(keystore)

        with client.run_flow():
            client.verify_PIN()

            segwit_tx = False

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
                    raise UserFacingException(_("Coinbase not supported"))

                if script_type in (
                    "p2wpkh", "p2wsh", "p2wpkh-p2sh",
                    "p2wsh-p2sh", "p2tr",
                ):
                    segwit_tx = True

                my_pubkey, input_path = (
                    keystore.find_my_pubkey_in_txinout(txin)
                )
                if not input_path:
                    raise UserFacingException(
                        _("No matching pubkey for sign_transaction")
                    )
                input_path = convert_bip32_intpath_to_strpath(input_path)

                is_taproot = script_type == "p2tr"
                if is_taproot and not client.supports_taproot():
                    raise UserFacingException(
                        _(
                            "Your Satochip does not support Taproot. "
                            "Taproot requires firmware v0.14 or newer."
                        )
                    )

                (_depth, bytepath) = _bip32path2bytes(input_path)
                client.cc.card_bip32_get_extendedkey(bytepath)

                pre_tx = tx.serialize_preimage(i)
                pre_hash = sha256d(pre_tx)
                (
                    _r1, _r2, _r3, tx_hash_list, _needs_2fa
                ) = client.cc.card_parse_transaction(
                    pre_tx, segwit_tx
                )
                tx_hash = bytearray(tx_hash_list)
                if pre_hash != tx_hash:
                    raise RuntimeError("Tx preimage mismatch")

                keynbr = 0xFF

                if is_taproot:
                    (
                        _tweak_resp, tw1, tw2
                    ) = client.cc.card_taproot_tweak_privkey(
                        keynbr, None, bypass_flag=False
                    )
                    if tw1 != 0x90 or tw2 != 0x00:
                        raise UserFacingException(
                            _("Failed to tweak key for Taproot signing.")
                        )
                    tap_hash = bip340_tagged_hash(b"TapSighash", pre_hash)
                    (tx_sig, sw1, sw2) = client.cc.card_sign_schnorr_hash(
                        keynbr, list(tap_hash)
                    )
                    if sw1 != 0x90 or sw2 != 0x00:
                        raise UserFacingException(
                            _(
                                "Failed to sign this Taproot "
                                "transaction. Please try again."
                            )
                        )
                    tx_sig = bytes(tx_sig)
                    sighash = (
                        txin.sighash
                        if txin.sighash is not None
                        else Sighash.DEFAULT
                    )
                    tx_sig = tx_sig + Sighash.to_sigbytes(sighash)
                else:
                    (tx_sig, sw1, sw2) = client.cc.card_sign_transaction(
                        keynbr, tx_hash_list
                    )
                    if sw1 != 0x90 or sw2 != 0x00:
                        raise UserFacingException(
                            _(
                                "Failed to sign the transaction. "
                                "Please try again."
                            )
                        )
                    tx_sig = bytes(tx_sig)
                    r, s = ecc.get_r_and_s_from_ecdsa_der_sig(tx_sig)
                    if s > ecc.CURVE_ORDER // 2:
                        s = ecc.CURVE_ORDER - s
                    tx_sig = ecc.ecdsa_der_sig_from_r_and_s(r, s)
                    tx_sig = tx_sig + Sighash.to_sigbytes(Sighash.ALL)

                tx.add_signature_to_txin(
                    txin_idx=i, signing_pubkey=my_pubkey, sig=tx_sig,
                )

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
                    "This function is only available for "
                    "standard wallets when using {}."
                ).format(self.device)
            )
            return
        sequence = wallet.get_address_index(address)
        txin_type = wallet.get_txin_type(address)
        keystore.show_address(sequence, txin_type)

    # -- wizard integration -------------------------------------------------

    @staticmethod
    def _next_seed_method(d):
        return (
            "satochip_have_seed"
            if d.get("satochip_seed_method") == "import"
            else "satochip_generate_seed"
        )

    @staticmethod
    def _next_seed_ext(wizard, d):
        return (
            "satochip_have_ext"
            if wizard.wants_ext(d)
            else "satochip_import_seed"
        )

    def wizard_entry_for_device(
        self, device_info: "DeviceInfo", *, new_wallet: bool
    ) -> str:
        label_str = device_info.label or ""
        if label_str.endswith(_BLOCKED_SUFFIX):
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
                "next": self._next_seed_method,
            },
            "satochip_generate_seed": {
                "next": lambda d: self._next_seed_ext(wizard, d),
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
