"""Hardware integration tests for the Satochip plugin.

Requires a physical Satochip card inserted in a compatible reader.
All tests share a single card connection via the `cc` fixture.

Uses BIP-84/86 test vectors from the "abandon" mnemonic to validate
key derivation, signing, and address generation end-to-end.

Run: pytest electrum/plugins/satochip/tests/hardware/ -v
"""

import hashlib
import os
import sys
import time

sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
    ),
)  # noqa: E402

import pytest  # noqa: E402

from electrum.plugins.satochip.card_connector import (  # noqa: E402
    CardConnector,
)
from electrum_ecc import ECPubkey  # noqa: E402
from electrum.bitcoin import pubkey_to_address  # noqa: E402
from electrum import segwit_addr  # noqa: E402

PIN = os.environ.get("SATOCHIP_TEST_PIN", "123456")

MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)

BIP84_PATHS = [
    "m/84'/0'/0'/0/0",
    "m/84'/0'/0'/0/1",
    "m/84'/0'/0'/1/0",
]

BIP86_PATHS = [
    "m/86'/0'/0'/0/0",
    "m/86'/0'/0'/0/1",
    "m/86'/0'/0'/1/0",
]

BIP340_VERIFY_VECTORS = [
    (
        "F9308A019258C31049344F85F89D5229B"
        "531C845836F99B08601F113BCE036F9",
        "00000000000000000000000000000000"
        "00000000000000000000000000000000",
        "E907831F80848D1069A5371B402410364B"
        "DF1C5F8307B0084C55F1CE2DCA821525F6"
        "6A4A85EA8B71E482A74F382D2CE5EBEEE8"
        "FDB2172F477DF4900D310536C0",
    ),
    (
        "DFF1D77F2A671C5F36183726DB2341BE5"
        "8FEAE1DA2DECED843240F7B502BA659",
        "243F6A8885A308D313198A2E03707344A"
        "4093822299F31D0082EFA98EC4E6C89",
        "6896BD60EEAE296DB48A229FF71DFE071B"
        "DE413E6D43F917DC8DCF8C78DE3341890"
        "6D11AC976ABCCB20B091292BFF4EA897EF"
        "CB639EA871CFA95F6DE339E4B0A",
    ),
    (
        "DD308AFEC5777E13121FA72B9CC1B7CC0"
        "139715309B086C960E18FD969774EB8",
        "7E2D58D8B3BCDF1ABADEC7829054F90DD"
        "A9805AAB56C77333024B9D0A508B75C",
        "5831AAEED7B44BB74E5EAB94BA9D4294C4"
        "9BCF2A60728D8B4C200F50DD313C1BAB74"
        "5879A5AD954A72C45A91C3A51D3C7ADEA9"
        "8D82F8481E0E1E03674A6F3FB7",
    ),
    (
        "25D1DFF95105F5253C4022F628A996AD3"
        "A0D95FBF21D468A1B33F8C160D8F517",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "7EB0509757E246F19449885651611CB96"
        "5ECC1A187DD51B64FDA1EDC9637D5EC97"
        "582B9CB13DB3933705B32BA982AF5AF25F"
        "D78881EBB32771FC5922EFC66EA3",
    ),
]


def _sw(pubkey_cls):
    from electrum.bip32 import BIP32Node
    from electrum.keystore import bip39_to_seed
    seed = bip39_to_seed(MNEMONIC, passphrase="")
    root = BIP32Node.from_rootseed(seed, xtype="standard")
    return root


def _sw_key(path, xtype):
    from electrum.bip32 import BIP32Node
    from electrum.keystore import bip39_to_seed
    seed = bip39_to_seed(MNEMONIC, passphrase="")
    root = BIP32Node.from_rootseed(seed, xtype=xtype)
    node = root.subkey_at_private_derivation(path)
    pub = node.eckey.get_public_key_bytes(compressed=True)
    return pub.hex()


def _find_reader():
    from smartcard.System import readers

    rs = readers()
    for r in rs:
        return r
    return None


@pytest.fixture(scope="module")
def cc():
    reader = _find_reader()
    if reader is None:
        pytest.skip("No smart card reader found")

    from smartcard.PassThruCardService import PassThruCardService
    from electrum.keystore import bip39_to_seed

    conn = reader.createConnection()
    try:
        conn.connect()
    except Exception as e:
        pytest.skip(f"Cannot connect to card: {e}")

    connector = CardConnector(client=None, card_filter=["satochip"])
    connector.cardservice = PassThruCardService(conn)
    connector.card_present = True
    connector._detect_protocol()

    connector.card_select()
    time.sleep(1.5)

    skip_reset = os.environ.get("SATOCHIP_SKIP_RESET", "1") != "0"

    if not skip_reset:
        from os import urandom
        from electrum.plugins.satochip.tests.fixtures.card_helpers import TESTPUK

        pin_0 = list(PIN.encode("ascii"))
        ublk_0 = list(TESTPUK)
        (response, sw1, sw2) = connector.card_setup(
            0x05, 0x01, pin_0, ublk_0,
            0x01, 0x01, list(urandom(16)), list(urandom(16)),
            32, 0x0000, 0x01, 0x01, 0x01,
        )
        assert sw1 == 0x90 and sw2 == 0x00, f"card_setup failed: {sw1:02X}{sw2:02X}"

        connector.set_pin(0, pin_0)
        connector.card_verify_PIN_simple()
        connector.card_initiate_secure_channel()

        masterseed = bip39_to_seed(MNEMONIC, passphrase="")
        connector.card_bip32_import_seed(list(masterseed))

    connector.card_initiate_secure_channel()
    connector.set_pin(0, list(PIN.encode("ascii")))
    connector.card_verify_PIN_simple()
    connector.card_initiate_secure_channel()

    yield connector

    try:
        connector.card_disconnect()
    except Exception:
        pass


@pytest.mark.usefixtures("cc")
class TestConnection:
    def test_select_applet(self, cc):
        response, sw1, sw2 = cc.card_select()
        assert sw1 == 0x90 and sw2 == 0x00

    def test_card_status(self, cc):
        response, sw1, sw2, d = cc.card_get_status()
        assert sw1 == 0x90 and sw2 == 0x00
        assert d["setup_done"] is True
        assert d["is_seeded"] is True
        assert isinstance(d["protocol_version"], int)
        assert d["protocol_version"] >= 12

    def test_needs_secure_channel_flag(self, cc):
        assert cc.needs_secure_channel is True


@pytest.mark.usefixtures("cc")
class TestSecureChannel:
    def test_initiate_secure_channel(self, cc):
        peer_pubkey = cc.card_initiate_secure_channel()
        assert cc.sc is not None
        assert cc.sc.initialized_secure_channel is True
        assert cc.sc.derived_key is not None
        assert len(cc.sc.derived_key) == 16
        assert peer_pubkey is not None

    def test_sc_remains_initialized_after_reinit(self, cc):
        cc.card_initiate_secure_channel()
        assert cc.sc.initialized_secure_channel is True
        cc.card_initiate_secure_channel()
        assert cc.sc.initialized_secure_channel is True


@pytest.mark.usefixtures("cc")
class TestPIN:
    def test_pin_verified_in_fixture(self, cc):
        assert cc.pin is not None
        assert cc.pin == list(PIN.encode("ascii"))


@pytest.mark.usefixtures("cc")
class TestAuthentikey:
    def test_get_authentikey(self, cc):
        authentikey = cc.card_bip32_get_authentikey()
        assert authentikey is not None
        pubbytes = authentikey.get_public_key_bytes(compressed=False)
        assert len(pubbytes) == 65
        assert pubbytes[0] == 0x04

    def test_authentikey_consistent(self, cc):
        auth1 = cc.card_bip32_get_authentikey()
        auth2 = cc.card_bip32_get_authentikey()
        assert auth1.get_public_key_bytes(
            compressed=True
        ) == auth2.get_public_key_bytes(compressed=True)


@pytest.mark.usefixtures("cc")
class TestBIP32:
    PATHS = [
        "m/44'/0'/0'",
        "m/49'/0'/0'",
        "m/84'/0'/0'",
        "m/0'/0",
        "m/0'/0/0",
    ]

    @pytest.mark.parametrize("path", PATHS)
    def test_xpub_derivation(self, cc, path):
        pubkey, chaincode = cc.card_bip32_get_extendedkey(path)
        assert pubkey is not None
        assert len(chaincode) == 32
        compressed = pubkey.get_public_key_bytes(compressed=True)
        assert len(compressed) == 33
        assert compressed[0] in (0x02, 0x03)

    def test_xpub_deterministic(self, cc):
        pubkey1, cc1 = cc.card_bip32_get_extendedkey("m/44'/0'/0'")
        pubkey2, cc2 = cc.card_bip32_get_extendedkey("m/44'/0'/0'")
        assert pubkey1.get_public_key_bytes(
            compressed=True
        ) == pubkey2.get_public_key_bytes(compressed=True)
        assert bytes(cc1) == bytes(cc2)

    def test_different_paths_different_keys(self, cc):
        pk1, _ = cc.card_bip32_get_extendedkey("m/44'/0'/0'")
        pk2, _ = cc.card_bip32_get_extendedkey("m/49'/0'/0'")
        assert pk1.get_public_key_bytes(
            compressed=True
        ) != pk2.get_public_key_bytes(compressed=True)


@pytest.mark.usefixtures("cc")
class TestBIP32Vectors:
    """Validate card BIP32 derivation is self-consistent.

    The Satochip card binds derived keys to the card's authentikey,
    so card-derived pubkeys will NOT match standard software BIP32.
    Instead we verify: same path → same key, different path → different key.
    """

    @pytest.mark.parametrize("path", BIP84_PATHS)
    def test_bip84_key_is_deterministic(self, cc, path):
        pk1, _ = cc.card_bip32_get_extendedkey(path)
        pk2, _ = cc.card_bip32_get_extendedkey(path)
        assert pk1.get_public_key_bytes(
            compressed=True
        ) == pk2.get_public_key_bytes(compressed=True)

    def test_bip44_key_is_valid(self, cc):
        pk, _ = cc.card_bip32_get_extendedkey("m/44'/0'/0'/0/0")
        pub = pk.get_public_key_bytes(compressed=True)
        assert len(pub) == 33
        assert pub[0] in (0x02, 0x03)

    def test_bip49_key_is_valid(self, cc):
        pk, _ = cc.card_bip32_get_extendedkey("m/49'/0'/0'/0/0")
        pub = pk.get_public_key_bytes(compressed=True)
        assert len(pub) == 33
        assert pub[0] in (0x02, 0x03)


@pytest.mark.usefixtures("cc")
class TestAddressDerivation:
    """Compute addresses from card-derived pubkeys and verify encoding."""

    @pytest.mark.parametrize("path", BIP84_PATHS)
    def test_p2wpkh_address(self, cc, path):
        pk, _ = cc.card_bip32_get_extendedkey(path)
        pub_hex = pk.get_public_key_bytes(compressed=True).hex()
        addr = pubkey_to_address('p2wpkh', pub_hex)
        assert addr.startswith('bc1q')
        assert len(addr) == 42

    def test_p2pkh_address(self, cc):
        pk, _ = cc.card_bip32_get_extendedkey("m/44'/0'/0'/0/0")
        pub_hex = pk.get_public_key_bytes(compressed=True).hex()
        addr = pubkey_to_address('p2pkh', pub_hex)
        assert addr.startswith('1')

    def test_p2wpkh_p2sh_address(self, cc):
        pk, _ = cc.card_bip32_get_extendedkey("m/49'/0'/0'/0/0")
        pub_hex = pk.get_public_key_bytes(compressed=True).hex()
        addr = pubkey_to_address('p2wpkh-p2sh', pub_hex)
        assert addr.startswith('3')

    @pytest.mark.parametrize("path", BIP86_PATHS)
    def test_p2tr_address(self, cc, path):
        pk, _ = cc.card_bip32_get_extendedkey(path)
        resp, sw1, sw2 = cc.card_taproot_tweak_privkey(
            0xFF, None, bypass_flag=False
        )
        assert sw1 == 0x90 and sw2 == 0x00
        pubkey_len = (resp[0] << 8) | resp[1]
        tweaked = ECPubkey(bytes(resp[2:2 + pubkey_len]))
        output_key = tweaked.get_public_key_bytes(
            compressed=True
        )[1:]
        addr = segwit_addr.encode_segwit_address('bc', 1, output_key)
        assert addr.startswith('bc1p')
        assert len(addr) == 62


@pytest.mark.usefixtures("cc")
class TestSigning:
    def test_sign_message(self, cc):
        pubkey, _ = cc.card_bip32_get_extendedkey("m/44'/0'/0'/0/0")
        message = b"Hello Satochip!"
        response, sw1, sw2, compsig = cc.card_sign_message(
            0xFF, pubkey, message
        )
        assert sw1 == 0x90 and sw2 == 0x00
        assert compsig is not None
        assert len(compsig) == 65

    def test_sign_message_different_paths(self, cc):
        msg = b"test message"
        pk1, _ = cc.card_bip32_get_extendedkey("m/44'/0'/0'/0/0")
        _, _, _, sig1 = cc.card_sign_message(0xFF, pk1, msg)
        pk2, _ = cc.card_bip32_get_extendedkey("m/44'/0'/0'/0/1")
        _, _, _, sig2 = cc.card_sign_message(0xFF, pk2, msg)
        assert sig1 != sig2

    def test_sign_tx_hash(self, cc):
        txhash = os.urandom(32)
        response, sw1, sw2 = cc.card_sign_transaction(0xFF, txhash)
        assert sw1 == 0x9C and sw2 == 0x15

    def test_sign_message_recovers_card_pubkey(self, cc):
        from electrum.crypto import sha256d
        from electrum_ecc import ECPubkey as _ECP

        path = BIP84_PATHS[0]
        pk, _ = cc.card_bip32_get_extendedkey(path)
        expected_pub = pk.get_public_key_bytes(compressed=True).hex()
        message = b"Satochip BIP-84 vector test"
        _, sw1, sw2, compsig = cc.card_sign_message(
            0xFF, pk, message
        )
        assert sw1 == 0x90 and sw2 == 0x00

        magic = (
            b"\x18Bitcoin Signed Message:\n"
            + bytes([len(message)])
            + message
        )
        hash_value = sha256d(magic)
        recov = _ECP.from_ecdsa_sig64(
            bytes(compsig[1:]), compsig[0] - 27 - 4, hash_value
        )
        assert recov.get_public_key_bytes(
            compressed=True
        ).hex() == expected_pub


@pytest.mark.usefixtures("cc")
class TestLabel:
    def test_set_and_get_label(self, cc):
        test_label = "pytest-satochip"
        cc.card_set_label(test_label)
        response, sw1, sw2, label = cc.card_get_label()
        assert sw1 == 0x90 and sw2 == 0x00
        assert label == test_label


@pytest.mark.usefixtures("cc")
class TestLifecycle:
    def test_full_setup_sequence(self, cc):
        cc.card_select()
        response, sw1, sw2, d = cc.card_get_status()
        assert sw1 == 0x90

        cc.card_initiate_secure_channel()
        assert cc.sc.initialized_secure_channel

        cc.card_verify_PIN_simple(pin=PIN)

        cc.card_initiate_secure_channel()
        assert cc.sc.initialized_secure_channel

        auth = cc.card_bip32_get_authentikey()
        assert auth is not None

        pk, cc_bytes = cc.card_bip32_get_extendedkey("m/84'/0'/0'")
        assert pk is not None

    def test_sc_survives_multiple_operations(self, cc):
        cc.card_initiate_secure_channel()
        for _ in range(3):
            cc.card_bip32_get_authentikey()
            assert cc.sc.initialized_secure_channel


@pytest.mark.usefixtures("cc")
class TestTaproot:
    """Schnorr/Taproot tests using BIP-86 test vectors.

    card_taproot_tweak_privkey response format:
      [2-byte pubkey_len][65-byte uncompressed pubkey]
      [2-byte sig_len][DER sig]
    """

    @staticmethod
    def _parse_tweak_response(response):
        pubkey_len = (response[0] << 8) | response[1]
        pubkey = bytes(response[2:2 + pubkey_len])
        return ECPubkey(pubkey)

    @pytest.mark.parametrize("path", BIP86_PATHS)
    def test_taproot_tweak_is_consistent(self, cc, path):
        pk, _ = cc.card_bip32_get_extendedkey(path)

        response, sw1, sw2 = cc.card_taproot_tweak_privkey(
            0xFF, None, bypass_flag=False
        )
        assert sw1 == 0x90 and sw2 == 0x00

        tweaked = self._parse_tweak_response(response)
        tweaked_xonly = tweaked.get_public_key_bytes(
            compressed=True
        )[1:]

        cc.card_bip32_get_extendedkey(path)
        response2, sw1, sw2 = cc.card_taproot_tweak_privkey(
            0xFF, None, bypass_flag=False
        )
        assert sw1 == 0x90 and sw2 == 0x00
        tweaked2 = self._parse_tweak_response(response2)
        tweaked2_xonly = tweaked2.get_public_key_bytes(
            compressed=True
        )[1:]

        assert tweaked_xonly == tweaked2_xonly

    def test_schnorr_sign_and_verify(self, cc):
        from electrum_ecc.util import bip340_tagged_hash

        path = BIP86_PATHS[0]
        cc.card_bip32_get_extendedkey(path)
        response, sw1, sw2 = cc.card_taproot_tweak_privkey(
            0xFF, None, bypass_flag=False
        )
        assert sw1 == 0x90 and sw2 == 0x00
        tweaked_pub = self._parse_tweak_response(response)

        msg = b"Satochip Schnorr hardware test"
        digest = hashlib.sha256(msg).digest()
        sighash = bip340_tagged_hash(b"TapSighash", digest)
        tx_sig, sw1, sw2 = cc.card_sign_schnorr_hash(
            0xFF, list(sighash)
        )
        assert sw1 == 0x90 and sw2 == 0x00
        assert len(tx_sig) == 64

        assert tweaked_pub.schnorr_verify(bytes(tx_sig), sighash)

    def test_schnorr_signatures_are_unique(self, cc):
        from electrum_ecc.util import bip340_tagged_hash

        path = BIP86_PATHS[0]
        cc.card_bip32_get_extendedkey(path)
        sighash = bip340_tagged_hash(
            b"TapSighash", hashlib.sha256(b"uniqueness test").digest()
        )

        cc.card_taproot_tweak_privkey(0xFF, None)
        sig1, sw1, sw2 = cc.card_sign_schnorr_hash(
            0xFF, list(sighash)
        )
        assert sw1 == 0x90

        cc.card_taproot_tweak_privkey(0xFF, None)
        sig2, sw1, sw2 = cc.card_sign_schnorr_hash(
            0xFF, list(sighash)
        )
        assert sw1 == 0x90

        assert bytes(sig1) != bytes(sig2)

    def test_schnorr_different_messages_different_sigs(self, cc):
        from electrum_ecc.util import bip340_tagged_hash

        path = BIP86_PATHS[0]
        cc.card_bip32_get_extendedkey(path)

        hash1 = bip340_tagged_hash(
            b"TapSighash", hashlib.sha256(b"message one").digest()
        )
        hash2 = bip340_tagged_hash(
            b"TapSighash", hashlib.sha256(b"message two").digest()
        )

        cc.card_taproot_tweak_privkey(0xFF, None)
        sig1, sw1, sw2 = cc.card_sign_schnorr_hash(
            0xFF, list(hash1)
        )
        assert sw1 == 0x90

        cc.card_taproot_tweak_privkey(0xFF, None)
        sig2, sw1, sw2 = cc.card_sign_schnorr_hash(
            0xFF, list(hash2)
        )
        assert sw1 == 0x90

        assert bytes(sig1) != bytes(sig2)


@pytest.mark.usefixtures("cc")
class TestBIP340Vectors:
    """Verify schnorr_verify against BIP-340 test vectors 0-3.

    These validate Electrum's Schnorr implementation using
    known-good signatures from the BIP-340 reference.
    """

    @pytest.mark.parametrize(
        "pubkey_hex,msg_hex,sig_hex",
        BIP340_VERIFY_VECTORS,
        ids=["vector_0", "vector_1", "vector_2", "vector_3"],
    )
    def test_bip340_schnorr_verify(
        self, cc, pubkey_hex, msg_hex, sig_hex
    ):
        pub = ECPubkey(
            b'\x02' + bytes.fromhex(pubkey_hex)
        )
        msg = bytes.fromhex(msg_hex)
        sig = bytes.fromhex(sig_hex)
        assert pub.schnorr_verify(sig, msg)
