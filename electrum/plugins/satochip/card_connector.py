"""
Inlined from pysatochip/CardConnector.py with Electrum-native dependencies.
2FA, SeedKeeper, Satodime, and Satocash code paths removed.
"""

from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.Exceptions import CardConnectionException, CardRequestTimeoutException
from smartcard.util import toHexString, toBytes

from .jc_constants import JCconstants
from .card_data_parser import CardDataParser
from .tx_parser import TxParser
from .secure_channel import SecureChannel
from electrum_ecc import ECPubkey
from electrum.crypto import sha256d

import hashlib
from electrum.logging import get_logger

logger = get_logger(__name__)

MSG_WARNING = (
    "Before you request coins to be sent to addresses in this "
    "wallet, ensure you can pair with your device, or that you have "
    "its seed (and passphrase, if any).  Otherwise all coins you "
    "receive will be unspendable."
)


def msg_magic(message: bytes) -> bytes:
    """Bitcoin message signing prefix."""
    length = bytes.fromhex(var_int(len(message)))
    return b"\x18Bitcoin Signed Message:\n" + length + message


def var_int(i):
    if i < 0xFD:
        return int_to_hex(i)
    elif i <= 0xFFFF:
        return "fd" + int_to_hex(i, 2)
    elif i <= 0xFFFFFFFF:
        return "fe" + int_to_hex(i, 4)
    else:
        return "ff" + int_to_hex(i, 8)


def int_to_hex(i, length=1):
    s = hex(i)[2:].rstrip("L")
    s = "0" * (2 * length - len(s)) + s
    return s


# simple observer that will print on the console the card connection events.
class LogCardConnectionObserver(CardConnectionObserver):
    def update(self, cardconnection, ccevent):
        if "connect" == ccevent.type:
            logger.info("connecting to" + repr(cardconnection.getReader()))
        elif "disconnect" == ccevent.type:
            logger.info("disconnecting from" + repr(cardconnection.getReader()))
        elif "command" == ccevent.type:
            if ccevent.args[0][1] in (
                JCconstants.INS_SETUP,
                JCconstants.INS_SET_2FA_KEY,
                JCconstants.INS_BIP32_IMPORT_SEED,
                JCconstants.INS_BIP32_RESET_SEED,
                JCconstants.INS_CREATE_PIN,
                JCconstants.INS_VERIFY_PIN,
                JCconstants.INS_CHANGE_PIN,
                JCconstants.INS_UNBLOCK_PIN,
            ):
                logger.debug(
                    f"> {toHexString(ccevent.args[0][0:5])}{(len(ccevent.args[0]) - 5) * ' *'}"
                )
            else:
                logger.debug(f"> {toHexString(ccevent.args[0])}")
        elif "response" == ccevent.type:
            if [] == ccevent.args[0]:
                logger.debug(f"< [] {toHexString(ccevent.args[-2:])}")
            else:
                logger.debug(
                    f"< {toHexString(ccevent.args[0])} {toHexString(ccevent.args[-2:])}"
                )


# a card observer that detects inserted/removed cards and initiate connection
class RemovalObserver(CardObserver):
    """A simple card observer that is notified
    when cards are inserted/removed from the system and
    prints the list of cards
    """

    def __init__(self, cc):
        self.cc = cc
        self.observer = LogCardConnectionObserver()

    def update(self, observable, actions):
        (addedcards, removedcards) = actions
        for card in addedcards:
            if card.atr == [
                59,
                141,
                1,
                128,
                251,
                160,
                0,
                0,
                3,
                151,
                66,
                84,
                70,
                89,
                4,
                1,
                207,
            ]:
                continue  # Ignore Windows Hello for Business virtual device
            logger.info(f"+Inserted: {toHexString(card.atr)}")
            self.cc.card_present = True
            self.cc.cardservice = card
            self.cc.cardservice.connection = card.createConnection()
            self.cc.cardservice.connection.connect()
            self.cc.cardservice.connection.addObserver(self.observer)
            self.cc._detect_protocol()

            # get CPLC
            try:
                (response_CPLC, sw1, sw2) = self.cc.card_get_CPLC()
                logger.debug(f"DEBUG CPLC: {bytes(response_CPLC).hex()}")
                (response_IIN, sw1, sw2) = self.cc.card_get_IIN()
                logger.debug(f"DEBUG IIN: {bytes(response_IIN).hex()}")
                (response_CIN, sw1, sw2) = self.cc.card_get_CIN()
                logger.debug(f"DEBUG CIN: {bytes(response_CIN).hex()}")
                self.cc.UID = response_CPLC + response_IIN + response_CIN
                logger.debug(f"DEBUG UID: {bytes(self.cc.UID).hex()}")
                self.cc.UID_SHA1 = hashlib.sha1(bytes(self.cc.UID)).hexdigest()
                logger.debug(f"DEBUG UID_SHA1: {self.cc.UID_SHA1}")
            except Exception as exc:
                logger.warning(f"Error during CPLC/IIN/CIN: {repr(exc)}")

            # select applet
            try:
                (response, sw1, sw2) = self.cc.card_select()
                if sw1 != 0x90 or sw2 != 0x00:
                    self.cc.card_disconnect()
                    break

                # During factory reset, we should not send other commands than reset...
                if not self.cc.mode_factory_reset:
                    (response, sw1, sw2, status) = self.cc.card_get_status()
                    if (sw1 != 0x90 or sw2 != 0x00) and (sw1 != 0x9C or sw2 != 0x04):
                        self.cc.card_disconnect()
                        break
                    if self.cc.needs_secure_channel and not getattr(
                        self.cc.sc, "initialized_secure_channel", False
                    ):
                        self.cc.card_initiate_secure_channel()

                # todo: skip or not for reset_factory?
                if self.cc.client is not None:
                    self.cc.client.request("update_status", True)

            except Exception as exc:
                logger.warning(f"Error during connection: {repr(exc)}")
                if self.cc.client is not None:
                    msg = f"Exception while selecting card! \nOnly {self.cc.card_filter} cards are supported"
                    self.cc.client.request("show_error", msg)

        for card in removedcards:
            logger.info(f"-Removed: {toHexString(card.atr)}")
            self.cc.card_disconnect()


class CardConnector:
    # CardConnector supports Satochip only (SeedKeeper/Satodime/Satocash removed)
    SELECT = [0x00, 0xA4, 0x04, 0x00]
    SATOCHIP_AID = [0x53, 0x61, 0x74, 0x6F, 0x43, 0x68, 0x69, 0x70]  # SatoChip

    def __init__(self, client=None, card_filter=None):
        logger.debug("In __init__")
        self.logger = logger
        self.parser = CardDataParser()
        self.client = client
        if self.client is not None:
            self.client.cc = self
        self.cardtype = AnyCardType()
        # 2FA support removed for initial release
        self.needs_2FA = None
        self.is_seeded = None
        self.needsPIN = None
        self.setup_done = None
        self.needs_secure_channel = None
        self.mode_factory_reset = False  # set to True when performing factory reset
        self.sc = None
        # cache PIN
        self.pin_nbr = None
        self.pin = None
        self.card_filter = card_filter
        self._protocol = None  # set during card connection
        self.card_type = "card"
        self.cert_pem = None
        # cache protocol version (version x.y => 256*x+y)
        self.protocol_version = 0
        self.nfc_policy = None
        self.feature_schnorr_policy = None
        self.feature_nostr_policy = None
        self.feature_liquid_policy = None

        # cardservice
        self.cardservice = None  # will be instantiated when a card is inserted
        try:
            self.cardrequest = CardRequest(timeout=0, cardType=self.cardtype)
            self.cardservice = self.cardrequest.waitforcard()
            self.card_present = True
        except CardRequestTimeoutException:
            self.card_present = False
        # monitor if a card is inserted or removed
        self.cardmonitor = CardMonitor()
        self.cardobserver = RemovalObserver(self)
        self.cardmonitor.addObserver(self.cardobserver)

    def set_mode_factory_reset(self, mode_factory_reset):
        """WARNING: setting mode_factory_reset to True allows to reset the card to factory and erase all data!"""
        self.mode_factory_reset = mode_factory_reset

    def _detect_protocol(self):
        """Detect the active protocol from the current connection."""
        from smartcard.CardConnection import CardConnection

        try:
            inner = self.cardservice.connection
            if hasattr(inner, "component"):
                inner = inner.component
            proto = inner.getProtocol()
            # Validate against known CardConnection constants
            if proto in (
                CardConnection.T0_protocol,
                CardConnection.T1_protocol,
                CardConnection.RAW_protocol,
            ):
                self._protocol = proto
            else:
                # Default to T=1 (most smartcards including Satochip use T=1)
                self._protocol = CardConnection.T1_protocol
        except Exception:
            from smartcard.CardConnection import CardConnection

            self._protocol = CardConnection.T1_protocol

    def _do_transmit(self, apdu):
        """Transmit APDU with explicit protocol for pyscard compatibility."""
        from smartcard.CardConnection import CardConnection

        protocol = self._protocol or CardConnection.T1_protocol
        return self.cardservice.connection.transmit(apdu, protocol)

    ###########################################
    #             Applet management           #
    ###########################################

    def card_transmit(self, plain_apdu):
        logger.debug("In card_transmit")

        while self.card_present:
            # encrypt apdu
            ins = plain_apdu[1]
            if self.needs_secure_channel and ins not in [
                0xA4,
                0x81,
                0x82,
                0xFF,
                JCconstants.INS_GET_STATUS,
            ]:
                apdu = self.card_encrypt_secure_channel(plain_apdu)
            else:
                apdu = plain_apdu

            # transmit apdu
            (response, sw1, sw2) = self._do_transmit(apdu)

            # PIN authentication is required
            if sw1 == 0x9C and sw2 == 0x06:
                (response, sw1, sw2) = self.card_verify_PIN_simple()
            # secure channel not initialized
            elif sw1 == 0x9C and sw2 == 0x21:
                logger.error("In card_transmit secure channel not initialized (0x9C21)")
                self.card_initiate_secure_channel()
            # decrypt response
            elif sw1 == 0x90 and sw2 == 0x00:
                if self.needs_secure_channel and ins not in [
                    0xA4,
                    0x81,
                    0x82,
                    0xFF,
                    JCconstants.INS_GET_STATUS,
                ]:
                    response = self.card_decrypt_secure_channel(response)
                return response, sw1, sw2
            else:
                return response, sw1, sw2

        # no card present
        raise CardNotPresentError("No card found! Please insert card!")

    def card_get_ATR(self):
        logger.debug("In card_get_ATR()")
        return self.cardservice.connection.getATR()

    def card_get_CPLC(self):
        logger.debug("In card_get_CPLC")
        cla = 0x80
        ins = 0xCA
        p1 = 0x9F
        p2 = 0x7F
        apdu = [cla, ins, p1, p2]
        response, sw1, sw2 = self._do_transmit(apdu)
        return response, sw1, sw2

    def card_get_IIN(self):
        logger.debug("In card_get_IIN")
        cla = 0x80
        ins = 0xCA
        p1 = 0x00
        p2 = 0x42
        apdu = [cla, ins, p1, p2]
        response, sw1, sw2 = self._do_transmit(apdu)
        return response, sw1, sw2

    def card_get_CIN(self):
        logger.debug("In card_get_CIN")
        cla = 0x80
        ins = 0xCA
        p1 = 0x00
        p2 = 0x45
        apdu = [cla, ins, p1, p2]
        response, sw1, sw2 = self._do_transmit(apdu)
        return response, sw1, sw2

    def card_disconnect(self):
        logger.debug("In card_disconnect()")
        self.pin = None
        self.pin_nbr = None
        self.is_seeded = None
        self.needs_2FA = None
        self.setup_done = None
        self.needs_secure_channel = None
        self.card_present = False
        self.card_type = "card"
        if self.cardservice:
            self.cardservice.connection.disconnect()
            self.cardservice = None
        if self.client is not None:
            self.client.request("update_status", False)
        # reset authentikey
        self.parser.authentikey = None
        self.parser.authentikey_coordx = None
        self.parser.authentikey_from_storage = None

    def card_select(self):
        logger.debug("In card_select")

        # Satochip only (SeedKeeper/Satodime/Satocash removed)
        if self.card_filter is None:
            self.card_filter = ["satochip"]
        elif isinstance(self.card_filter, str):
            self.card_filter = [self.card_filter]

        # try to connect to each allowed applet sequentially
        for card_applet in self.card_filter:
            try:
                if card_applet == "satochip":
                    return self.card_select_satochip()
            except CardSelectError:
                pass

        # no suitable card found
        raise CardSelectError("No suitable card found", ins=0xA4)

    def card_select_satochip(self):
        apdu = (
            CardConnector.SELECT
            + [len(CardConnector.SATOCHIP_AID)]
            + CardConnector.SATOCHIP_AID
        )
        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            raise CardSelectError("CardSelect error", ins=0xA4)
        self.card_type = "Satochip"
        logger.debug("Found a Satochip!")
        return response, sw1, sw2

    def card_get_status(self):
        logger.debug("In card_get_status")
        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_GET_STATUS
        p1 = 0x00
        p2 = 0x00
        apdu = [cla, ins, p1, p2]
        response, sw1, sw2 = self.card_transmit(apdu)
        d = {}
        if sw1 == 0x90 and sw2 == 0x00:
            # card applet version
            d["protocol_major_version"] = response[0]
            d["protocol_minor_version"] = response[1]
            d["applet_major_version"] = response[2]
            d["applet_minor_version"] = response[3]
            d["protocol_version"] = (d["protocol_major_version"] << 8) + d[
                "protocol_minor_version"
            ]
            self.protocol_version = d["protocol_version"]  # cache version
            # PIN/PUK status
            if len(response) >= 8:
                d["PIN0_remaining_tries"] = response[4]
                d["PUK0_remaining_tries"] = response[5]
                d["PIN1_remaining_tries"] = response[6]
                d["PUK1_remaining_tries"] = response[7]
                self.needs_2FA = d["needs2FA"] = False  # 2FA support removed
            # 2FA status
            if len(response) >= 9:
                self.needs_2FA = d["needs2FA"] = False  # 2FA support removed
            # seed status (satochip)
            if len(response) >= 10:
                self.is_seeded = d["is_seeded"] = False if response[9] == 0x00 else True
            # setup status
            if len(response) >= 11:
                self.setup_done = d["setup_done"] = (
                    False if response[10] == 0x00 else True
                )
            else:
                self.setup_done = d["setup_done"] = True
            # secure channel status
            if len(response) >= 12:
                self.needs_secure_channel = d["needs_secure_channel"] = (
                    False if response[11] == 0x00 else True
                )
            else:
                self.needs_secure_channel = d["needs_secure_channel"] = False
            # NFC policy
            if len(response) >= 13:
                self.nfc_policy = d["nfc_policy"] = response[12]
            else:
                self.nfc_policy = d["nfc_policy"] = 0x00
            # optional features policy
            if len(response) >= 16:
                self.feature_schnorr_policy = d["feature_schnorr_policy"] = response[13]
                self.feature_nostr_policy = d["feature_nostr_policy"] = response[14]
                self.feature_liquid_policy = d["feature_liquid_policy"] = response[15]
            else:
                self.feature_schnorr_policy = d["feature_schnorr_policy"] = None
                self.feature_nostr_policy = d["feature_nostr_policy"] = None
                self.feature_liquid_policy = d["feature_liquid_policy"] = None

        elif sw1 == 0x9C and sw2 == 0x04:
            self.setup_done = d["setup_done"] = False
            self.is_seeded = d["is_seeded"] = False
            self.needs_secure_channel = d["needs_secure_channel"] = False

        else:
            logger.warning(
                f"Unknown error in get_status() (error code {hex(256 * sw1 + sw2)})"
            )

        return response, sw1, sw2, d

    ###########################################
    #         Generic applet methods          #
    ###########################################

    def card_get_label(self):
        logger.debug("In card_get_label")
        cla = JCconstants.CardEdge_CLA
        ins = 0x3D
        p1 = 0x00
        p2 = 0x01  # get
        apdu = [cla, ins, p1, p2]
        response, sw1, sw2 = self.card_transmit(apdu)

        if sw1 == 0x90 and sw2 == 0x00:
            try:
                label = bytes(response[1:]).decode("utf8")
            except UnicodeDecodeError:
                logger.warning("UnicodeDecodeError while decoding card label!")
                label = str(bytes(response[1:]))
        elif sw1 == 0x6D and sw2 == 0x00:  # unsupported by the card
            label = "(none)"
        else:
            logger.warning(f"Error while recovering card label: {hex(256 * sw1 + sw2)}")
            label = "(unknown)"

        return response, sw1, sw2, label

    def card_set_label(self, label):
        logger.debug("In card_set_label")
        cla = JCconstants.CardEdge_CLA
        ins = 0x3D
        p1 = 0x00
        p2 = 0x00  # set

        label_list = list(label.encode("utf8"))
        data = [len(label_list)] + label_list
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data
        response, sw1, sw2 = self.card_transmit(apdu)

        return response, sw1, sw2

    def card_setup(
        self,
        pin_tries0,
        ublk_tries0,
        pin0,
        ublk0,
        pin_tries1,
        ublk_tries1,
        pin1,
        ublk1,
        memsize,
        memsize2,
        create_object_ACL,
        create_key_ACL,
        create_pin_ACL,
        option_flags=0,
        hmacsha160_key=None,
        amount_limit=0,
    ):

        logger.debug("In card_setup")

        # check pin format
        if type(pin0) == str:
            pin0 = list(pin0.encode("utf-8"))
        elif type(pin0) == bytes:
            pin0 = list(pin0)

        if type(ublk0) == str:
            ublk0 = list(ublk0.encode("utf-8"))
        elif type(ublk0) == bytes:
            ublk0 = list(ublk0)

        if type(pin1) == str:
            pin1 = list(pin1.encode("utf-8"))
        elif type(pin1) == bytes:
            pin1 = list(pin1)

        if type(ublk1) == str:
            ublk1 = list(ublk1.encode("utf-8"))
        elif type(ublk1) == bytes:
            ublk1 = list(ublk1)

        pin = [0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30]  # default pin
        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_SETUP
        p1 = 0
        p2 = 0
        apdu = [cla, ins, p1, p2]

        if option_flags == 0:
            optionsize = 0
        elif option_flags & 0x8000 == 0x8000:
            optionsize = 30
        else:
            optionsize = 2
        lc = (
            16 + len(pin) + len(pin0) + len(pin1) + len(ublk0) + len(ublk1) + optionsize
        )

        apdu += [lc]
        apdu += [len(pin)] + pin
        apdu += [pin_tries0, ublk_tries0, len(pin0)] + pin0 + [len(ublk0)] + ublk0
        apdu += [pin_tries1, ublk_tries1, len(pin1)] + pin1 + [len(ublk1)] + ublk1
        apdu += [memsize >> 8, memsize & 0x00FF, memsize2 >> 8, memsize2 & 0x00FF]
        apdu += [create_object_ACL, create_key_ACL, create_pin_ACL]
        if option_flags != 0:
            apdu += [option_flags >> 8, option_flags & 0x00FF]
            if hmacsha160_key is not None:
                apdu += hmacsha160_key
            else:
                apdu += [0x00] * 20
            for i in reversed(range(8)):
                apdu += [(amount_limit >> (8 * i)) & 0xFF]

        # send apdu (contains sensitive data!)
        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            self.set_pin(0, pin0)  # cache PIN value
            self.setup_done = True

        return response, sw1, sw2

    ###########################################
    #              BIP32 commands             #
    ###########################################

    def card_bip32_import_seed(self, seed):
        """Import a seed into the device

        Returns:
        authentikey: ECPubkey object that identifies the device
        """
        if type(seed) is str:
            seed = list(bytes.fromhex(seed))
        elif type(seed) is bytes:
            seed = list(seed)

        logger.debug("In card_bip32_import_seed")
        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_BIP32_IMPORT_SEED
        p1 = len(seed)
        p2 = 0x00
        lc = len(seed)
        apdu = [cla, ins, p1, p2, lc] + seed

        # send apdu (contains sensitive data!)
        response, sw1, sw2 = self.card_transmit(apdu)

        authentikey = None
        if sw1 == 0x90 and sw2 == 0x00:
            authentikey = self.card_bip32_set_authentikey_pubkey(response)
            authentikey_hex = authentikey.get_public_key_bytes(compressed=True).hex()
            logger.debug(
                "[card_bip32_import_seed] authentikey_card= " + authentikey_hex
            )
            self.is_seeded = True

        elif sw1 == 0x9C and sw2 == 0x17:
            logger.error("Error during secret import: card is already seeded (0x9C17)")
            raise CardError("Secure import failed: card is already seeded (0x9C17)!")
        elif sw1 == 0x9C and sw2 == 0x0F:
            logger.error("Error during secret import: invalid parameter (0x9C0F)")
            raise CardError(f"Error during secret import: invalid parameter (0x9C0F)")

        return authentikey

    def card_export_authentikey(self):
        """Export the device authentikey.

        Returns:
        authentikey: ECPubkey object that identifies the device
        """
        logger.debug("In card_export_authentikey")
        cla = JCconstants.CardEdge_CLA
        ins = 0xAD
        p1 = 0x00
        p2 = 0x00
        apdu = [cla, ins, p1, p2]

        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            authentikey = self.parser.parse_bip32_get_authentikey(response)
            return authentikey
        elif sw1 == 0x9C and sw2 == 0x04:
            logger.info(
                "card_bip32_get_authentikey(): Satochip is not initialized => Raising error!"
            )
            raise UninitializedSeedError(
                "Satochip is not initialized! You should create a new wallet!\n\n"
                + MSG_WARNING
            )
        else:
            logger.warning(
                f"Unexpected error during authentikey export (error code {hex(256 * sw1 + sw2)})"
            )
            raise UnexpectedSW12Error(
                f"Unexpected error during authentikey export (error code {hex(256 * sw1 + sw2)})"
            )

    def card_bip32_get_authentikey(self):
        """Return the authentikey."""
        logger.debug("In card_bip32_get_authentikey")
        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_BIP32_GET_AUTHENTIKEY
        p1 = 0x00
        p2 = 0x00
        apdu = [cla, ins, p1, p2]

        response, sw1, sw2 = self.card_transmit(apdu)
        if sw1 == 0x9C and sw2 == 0x14:
            raise UninitializedSeedError(
                "Satochip seed is not initialized!\n " + MSG_WARNING
            )
        if sw1 == 0x9C and sw2 == 0x04:
            raise UninitializedSeedError(
                "Satochip is not initialized! You should create a new wallet!\n\n"
                + MSG_WARNING
            )
        authentikey = None
        if sw1 == 0x90 and sw2 == 0x00:
            authentikey = self.card_bip32_set_authentikey_pubkey(response)
            self.is_seeded = True
        return authentikey

    def card_bip32_set_authentikey_pubkey(self, response):
        """Allows to compute coordy of authentikey externally to optimize computation time-out."""
        logger.debug("In card_bip32_set_authentikey_pubkey")
        cla = JCconstants.CardEdge_CLA
        ins = 0x75
        p1 = 0x00
        p2 = 0x00

        authentikey = self.parser.parse_bip32_get_authentikey(response)
        if authentikey:
            coordy = authentikey.get_public_key_bytes(compressed=False)
            coordy = list(coordy[33:])
            data = response + [len(coordy) & 0xFF00, len(coordy) & 0x00FF] + coordy
            lc = len(data)
            apdu = [cla, ins, p1, p2, lc] + data
            response, sw1, sw2 = self.card_transmit(apdu)
        return authentikey

    def card_bip32_get_extendedkey(self, path, sid=None, option_flags=0x40):
        """Get the BIP32 extended key for given path."""
        if type(path) == str:
            (depth, path) = self.parser.bip32path2bytes(path)

        logger.debug("In card_bip32_get_extendedkey")
        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_BIP32_GET_EXTENDED_KEY
        p1 = len(path) // 4
        p2 = option_flags
        lc = len(path)

        data = list(path)
        if sid is not None:
            data = data + [(sid >> 8) % 256, sid % 256]
        lc = len(data)

        apdu = [cla, ins, p1, p2, lc] + data

        if self.parser.authentikey is None:
            self.card_bip32_get_authentikey()

        while True:
            response, sw1, sw2 = self.card_transmit(apdu)

            if sw1 == 0x9C and sw2 == 0x01:
                logger.info("[card_bip32_get_extendedkey] Reset memory...")
                apdu[3] = apdu[3] ^ 0x80
                response, sw1, sw2 = self.card_transmit(apdu)
                apdu[3] = apdu[3] & 0x7F
            if sw1 != 0x90 or sw2 != 0x00:
                raise UnexpectedSW12Error(
                    f"Unexpected error  (error code {hex(256 * sw1 + sw2)})"
                )
            if sw1 == 0x90 and sw2 == 0x00:
                if (option_flags & 0x04) == 0x04:  # BIP85
                    entropy_bytes = self.parser.parse_bip32_get_extendedkey_bip85(
                        response
                    )
                    return entropy_bytes
                elif (option_flags & 0x02) == 0x00:  # BIP32 pubkey
                    if (response[32] & 0x80) == 0x80:
                        logger.info(
                            "[card_bip32_get_extendedkey] Child Derivation optimization..."
                        )
                        pubkey, chaincode = self.parser.parse_bip32_get_extendedkey(
                            response
                        )
                        coordy = pubkey.get_public_key_bytes(compressed=False)
                        coordy = list(coordy[33:])
                        authcoordy = self.parser.authentikey.get_public_key_bytes(
                            compressed=False
                        )
                        authcoordy = list(authcoordy[33:])
                        data = (
                            response
                            + [len(coordy) & 0xFF00, len(coordy) & 0x00FF]
                            + coordy
                        )
                        apdu_opt = [cla, 0x74, 0x00, 0x00, len(data)]
                        apdu_opt = apdu_opt + data
                        response_opt, sw1_opt, sw2_opt = self.card_transmit(apdu_opt)

                    pubkey, chaincode = self.parser.parse_bip32_get_extendedkey(
                        response
                    )
                    return pubkey, chaincode
                else:  # BIP32 privkey
                    privkey, chaincode = self.parser.parse_bip32_get_extended_privkey(
                        response
                    )
                    return privkey, chaincode

    ###########################################
    #            Signing commands             #
    ###########################################

    def card_sign_message(self, keynbr, pubkey, message, chalresponse=None):
        """Sign the message with the device. The chalresponse parameter is unused (2FA removed)."""
        logger.debug("In card_sign_message")
        if type(message) == str:
            message = message.encode("utf8")

        # 2FA support removed: hmac always empty
        hmac_data = b""

        chunk = 128
        buffer_offset = 0
        buffer_left = len(message)

        # CIPHER_INIT
        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_SIGN_MESSAGE
        p1 = keynbr
        p2 = JCconstants.OP_INIT
        lc = 0x4
        apdu = [cla, ins, p1, p2, lc]
        for i in reversed(range(4)):
            apdu += [((buffer_left >> (8 * i)) & 0xFF)]

        response, sw1, sw2 = self.card_transmit(apdu)

        # CIPHER PROCESS/UPDATE
        while buffer_left > chunk:
            p2 = JCconstants.OP_PROCESS
            lc = 2 + chunk
            apdu = [cla, ins, p1, p2, lc]
            apdu += [((chunk >> 8) & 0xFF), (chunk & 0xFF)]
            apdu += message[buffer_offset : (buffer_offset + chunk)]
            buffer_offset += chunk
            buffer_left -= chunk
            response, sw1, sw2 = self.card_transmit(apdu)

        # CIPHER FINAL/SIGN
        chunk = buffer_left
        p2 = JCconstants.OP_FINALIZE
        lc = 2 + chunk + len(hmac_data)
        apdu = [cla, ins, p1, p2, lc]
        apdu += [((chunk >> 8) & 0xFF), (chunk & 0xFF)]
        apdu += message[buffer_offset : (buffer_offset + chunk)] + hmac_data
        buffer_offset += chunk
        buffer_left -= chunk
        response, sw1, sw2 = self.card_transmit(apdu)

        if sw1 != 0x90 or sw2 != 0x00:
            logger.warning(
                f"Unexpected error in card_sign_message() (error code {hex(256 * sw1 + sw2)})"
            )
            compsig = b""
        else:
            hash_value = sha256d(msg_magic(message))
            compsig = self.parser.parse_message_signature(response, hash_value, pubkey)

        return response, sw1, sw2, compsig

    def card_parse_transaction(self, transaction: bytes, is_segwit=False):
        """Parse a transaction to be signed by the device."""
        logger.debug("In card_parse_transaction")
        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_PARSE_TRANSACTION
        p1 = JCconstants.OP_INIT
        p2 = 0x01 if is_segwit else 0x00

        txparser = TxParser(transaction)
        while not txparser.is_parsed():
            chunk = (
                txparser.parse_segwit_transaction()
                if is_segwit
                else txparser.parse_transaction()
            )
            lc = len(chunk)
            apdu = [cla, ins, p1, p2, lc]
            apdu += chunk

            response, sw1, sw2 = self.card_transmit(apdu)

            p1 = JCconstants.OP_PROCESS

        (tx_hash, needs_2fa) = self.parser.parse_parse_transaction(response)

        return response, sw1, sw2, tx_hash, needs_2fa

    def card_sign_transaction(self, keynbr, txhash, chalresponse=None):
        """Sign the transaction in the device. The chalresponse parameter is unused (2FA removed)."""
        logger.debug("In card_sign_transaction")
        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_SIGN_TRANSACTION
        p1 = keynbr
        p2 = 0x00

        if len(txhash) != 32:
            raise ValueError(
                "Wrong txhash length: " + str(len(txhash)) + "(should be 32)"
            )
        # 2FA support removed: chalresponse always None
        data = list(txhash)
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data

        response, sw1, sw2 = self.card_transmit(apdu)
        return response, sw1, sw2

    def card_sign_schnorr_hash(self, keynbr, txhash, chalresponse=None):
        """Sign the transaction hash using schnorr signature."""
        logger.debug("In card_sign_schnorr_hash")

        cla = JCconstants.CardEdge_CLA
        ins = 0x7B
        p1 = keynbr
        p2 = 0x00

        if len(txhash) != 32:
            raise ValueError(
                "Wrong txhash length: " + str(len(txhash)) + "(should be 32)"
            )
        data = list(txhash)

        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data

        response, sw1, sw2 = self.card_transmit(apdu)
        return response, sw1, sw2

    def card_taproot_tweak_privkey(self, keynbr, tweak, bypass_flag: bool = False):
        """Tweak the private key stored in the Satochip."""
        logger.debug("in card_taproot_tweak_privkey")

        cla = JCconstants.CardEdge_CLA
        ins = 0x7C
        p1 = keynbr
        p2 = 0x00 if not bypass_flag else 0x01

        if tweak is None:
            tweak = 32 * [0]

        if len(tweak) != 32:
            raise ValueError("Wrong tweak length (should be 32)")

        data = [len(tweak)] + tweak
        lc = len(data)
        apdu = [cla, ins, p1, p2, lc] + data

        response, sw1, sw2 = self.card_transmit(apdu)
        return response, sw1, sw2

    ###########################################
    #                PIN commands             #
    ###########################################

    def card_verify_PIN_simple(self, pin=None):
        """Verify card PIN."""
        logger.debug("In card_verify_PIN_simple")

        if not self.card_present:
            raise CardNotPresentError("No card found! Please insert card!")

        if pin is not None:
            if type(pin) == str:
                pin_0 = list(pin.encode("utf-8"))
            elif type(pin) == bytes:
                pin_0 = list(pin)
            else:
                raise PinRequiredError(
                    f"PIN should be a String or Bytes, not {type(pin)}"
                )
        else:
            if self.pin is not None:
                pin_0 = self.pin
            else:
                raise PinRequiredError("Device cannot be unlocked without PIN code!")

        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_VERIFY_PIN
        apdu = [cla, ins, 0x00, 0x00, len(pin_0)] + pin_0

        if self.needs_secure_channel:
            apdu = self.card_encrypt_secure_channel(apdu)
        response, sw1, sw2 = self._do_transmit(apdu)

        if sw1 == 0x9C and sw2 == 0x21:
            logger.error(
                "In card_verify_PIN_simple secure channel not initialized (0x9C21)"
            )
            self.card_initiate_secure_channel()
            apdu = [cla, ins, 0x00, 0x00, len(pin_0)] + pin_0
            apdu = self.card_encrypt_secure_channel(apdu)
            response, sw1, sw2 = self._do_transmit(apdu)

        if sw1 == 0x90 and sw2 == 0x00:
            self.set_pin(0, pin_0)
            return response, sw1, sw2
        elif sw1 == 0x63 and (sw2 & 0xC0) == 0xC0:
            logger.error("In card_verify_PIN_simple wrong PIN!")
            self.set_pin(0, None)
            pin_left = sw2 & ~0xC0
            raise WrongPinError(f"Wrong PIN! {pin_left} tries remaining!", pin_left)
        elif sw1 == 0x9C and sw2 == 0x02:
            logger.error("In card_verify_PIN_simple wrong PIN!")
            self.set_pin(0, None)
            response2, sw1b, sw2b, d = self.card_get_status()
            pin_left = d.get("PIN0_remaining_tries", -1)
            raise WrongPinError(f"Wrong PIN! {pin_left} tries remaining!", pin_left)
        elif sw1 == 0x9C and sw2 == 0x0C:
            logger.error("In card_verify_PIN_simple Blocked PIN!")
            self.set_pin(0, None)
            msg = (
                f"Too many failed attempts! Your device has been blocked! \n\n"
                f"You need your PUK code to unblock it (error code {hex(256 * sw1 + sw2)})"
            )
            raise PinBlockedError(msg)
        elif sw1 == 0x9C and sw2 == 0x04:
            logger.error("In card_verify_PIN_simple setup not done (code 0x9C04)")
            raise CardSetupNotDoneError(
                "Failed to verify PIN: setup not done (code 0x9C04)"
            )
        else:
            self.set_pin(0, None)
            msg = f"Please check your card! Unexpected error (error code {hex(256 * sw1 + sw2)})"
            raise UnexpectedSW12Error(msg, sw1, sw2)

    def set_pin(self, pin_nbr, pin):
        self.pin_nbr = pin_nbr
        self.pin = pin

    def is_pin_set(self):
        return self.pin is not None

    def card_change_PIN(self, pin_nbr, old_pin, new_pin):
        logger.debug("In card_change_PIN")
        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_CHANGE_PIN
        p1 = pin_nbr
        p2 = 0x00
        lc = 1 + len(old_pin) + 1 + len(new_pin)
        apdu = (
            [cla, ins, p1, p2, lc] + [len(old_pin)] + old_pin + [len(new_pin)] + new_pin
        )
        response, sw1, sw2 = self.card_transmit(apdu)

        if sw1 == 0x90 and sw2 == 0x00:
            self.set_pin(pin_nbr, new_pin)
        elif sw1 == 0x63 and (sw2 & 0xC0) == 0xC0:
            self.set_pin(pin_nbr, None)
            pin_left = sw2 & ~0xC0
            raise WrongPinError(
                ("Wrong PIN! {} tries remaining!").format(pin_left), pin_left
            )
        elif sw1 == 0x9C and sw2 == 0x02:
            self.set_pin(pin_nbr, None)
            response2, sw1b, sw2b, d = self.card_get_status()
            pin_left = d.get("PIN0_remaining_tries", -1)
            raise WrongPinError(
                ("Wrong PIN! {} tries remaining!").format(pin_left), pin_left
            )
        elif sw1 == 0x9C and sw2 == 0x0C:
            msg = (
                f"Too many failed attempts! Your device has been blocked! \n\n"
                f"You need your PUK code to unblock it (error code {hex(256 * sw1 + sw2)})"
            )
            raise PinBlockedError(msg)

        return response, sw1, sw2

    def card_unblock_PIN(self, pin_nbr, ublk):
        logger.debug("In card_unblock_PIN")
        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_UNBLOCK_PIN
        p1 = pin_nbr
        p2 = 0x00
        lc = len(ublk)
        apdu = [cla, ins, p1, p2, lc] + ublk
        response, sw1, sw2 = self.card_transmit(apdu)

        if sw1 == 0x63 and (sw2 & 0xC0) == 0xC0:
            self.set_pin(pin_nbr, None)
            pin_left = sw2 & ~0xC0
            raise WrongPinError(
                ("Wrong PUK! {} tries remaining!").format(pin_left), pin_left
            )
        elif sw1 == 0x9C and sw2 == 0x02:
            self.set_pin(pin_nbr, None)
            response2, sw1b, sw2b, d = self.card_get_status()
            pin_left = d.get("PUK0_remaining_tries", -1)
            raise WrongPinError(
                ("Wrong PUK! {} tries remaining!").format(pin_left), pin_left
            )
        elif sw1 == 0x9C and sw2 == 0x0C:
            self.set_pin(pin_nbr, None)
            msg = f"Too many failed attempts. Your device has been blocked! (error code {hex(256 * sw1 + sw2)})"
            raise PinBlockedError(msg)
        elif sw1 == 0xFF and sw2 == 0x00:
            self.set_pin(pin_nbr, None)
            self.setup_done = False
            raise CardResetToFactoryError("CARD RESET TO FACTORY!")

        return response, sw1, sw2

    def card_logout_all(self):
        logger.debug("In card_logout_all")
        cla = JCconstants.CardEdge_CLA
        ins = JCconstants.INS_LOGOUT_ALL
        p1 = 0x00
        p2 = 0x00
        lc = 0
        apdu = [cla, ins, p1, p2, lc]
        response, sw1, sw2 = self.card_transmit(apdu)
        self.set_pin(0, None)
        return response, sw1, sw2

    ###########################################
    #            Secure Channel               #
    ###########################################

    def card_initiate_secure_channel(self):
        logger.debug("In card_initiate_secure_channel()")
        cla = JCconstants.CardEdge_CLA
        ins = 0x81
        p1 = 0x00
        p2 = 0x00

        self.sc = SecureChannel()
        pubkey = list(self.sc.sc_pubkey_serialized)
        lc = len(pubkey)  # 65
        apdu = [cla, ins, p1, p2, lc] + pubkey

        response, sw1, sw2 = self.card_transmit(apdu)

        peer_pubkey = self.parser.parse_initiate_secure_channel(response)
        peer_pubkey_bytes = peer_pubkey.get_public_key_bytes(compressed=False)
        self.sc.initiate_secure_channel(peer_pubkey_bytes)

        return peer_pubkey

    def card_encrypt_secure_channel(self, apdu):
        logger.debug("In card_encrypt_secure_channel()")
        cla = JCconstants.CardEdge_CLA
        ins = 0x82
        p1 = 0x00
        p2 = 0x00

        if apdu[1] in (
            JCconstants.INS_SETUP,
            JCconstants.INS_SET_2FA_KEY,
            JCconstants.INS_BIP32_IMPORT_SEED,
            JCconstants.INS_BIP32_RESET_SEED,
            JCconstants.INS_CREATE_PIN,
            JCconstants.INS_VERIFY_PIN,
            JCconstants.INS_CHANGE_PIN,
            JCconstants.INS_UNBLOCK_PIN,
        ):
            logger.debug(
                f"Plaintext C-APDU: {toHexString(apdu[0:5])}{(len(apdu) - 5) * ' *'}"
            )
        else:
            logger.debug(f"Plaintext C-APDU: {toHexString(apdu)}")

        iv, ciphertext, mac = self.sc.encrypt_secure_channel(bytes(apdu))
        data = (
            list(iv)
            + [len(ciphertext) >> 8, len(ciphertext) & 0xFF]
            + list(ciphertext)
            + [len(mac) >> 8, len(mac) & 0xFF]
            + list(mac)
        )
        lc = len(data)

        encrypted_apdu = [cla, ins, p1, p2, lc] + data

        return encrypted_apdu

    def card_decrypt_secure_channel(self, response):
        logger.debug("In card_decrypt_secure_channel")

        if len(response) == 0:
            return response
        elif len(response) < 18:
            raise SecureChannelError("Encrypted response has wrong length!")

        iv = bytes(response[0:16])
        size = ((response[16] & 0xFF) << 8) + (response[17] & 0xFF)
        ciphertext = bytes(response[18:])
        if len(ciphertext) != size:
            logger.warning(
                f"In card_decrypt_secure_channel: ciphertext has wrong length: expected {str(size)} got {str(len(ciphertext))}"
            )
            raise SecureChannelError("Ciphertext has wrong length!")

        plaintext = self.sc.decrypt_secure_channel(iv, ciphertext)

        logger.debug(f"Plaintext R-APDU: {toHexString(plaintext)}")

        return plaintext

    #################################
    #         PERSO PKI            #
    #################################


#################################
#         CARD  ERRORS          #
#################################


class ApduError(Exception):
    def __init__(self, message, sw1=0x00, sw2=0x00, ins=0x00, response=[]):
        super().__init__(message)
        self.sw1 = sw1
        self.sw2 = sw2
        self.ins = ins
        self.response = response


class CardSelectError(ApduError):
    def __init__(self, message, ins=0x00, response=[]):
        super().__init__(message, 0x6A, 0x82, ins, response)


class CardSetupNotDoneError(ApduError):
    def __init__(self, message, ins=0x00, response=[]):
        super().__init__(message, 0x9C, 0x04, ins, response)


class SecureChannelError(Exception):
    """Exception related to the secure channel"""

    pass


class UninitializedSeedError(Exception):
    """Raised when the device is not yet seeded"""

    pass


class UnexpectedSW12Error(Exception):
    """Raised when the device returns an unexpected error code"""

    def __init__(self, message, sw1=0x00, sw2=0x00):
        super().__init__(message)
        self.sw1 = sw1
        self.sw2 = sw2
        self.sw12hex = hex(sw1 * 256 + sw2)


class PinRequiredError(Exception):
    """Raised when the device needs a correct PIN to continue"""

    pass


class WrongPinError(Exception):
    """Raised when the provided PIN code is wrong"""

    def __init__(self, message, pin_left):
        super().__init__(message)
        self.pin_left = pin_left


class PinBlockedError(Exception):
    """Raised when the card PIN is blocked"""

    pass


class CardResetToFactoryError(Exception):
    """Raised when the card has been reset to factory"""

    pass


class CardNotPresentError(Exception):
    """Raised when the device is not present"""

    pass


class CardError(Exception):
    """Raised when the device returns an error code"""

    pass
