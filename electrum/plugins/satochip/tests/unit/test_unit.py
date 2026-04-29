import os
import sys

import pytest

sys.path.insert(
    0,
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")),
)

from electrum.plugins.satochip.secure_channel import (
    SecureChannel,
    UninitializedSecureChannelError,
)
from electrum_ecc import ECPrivkey


class TestSecureChannelUnit:
    def test_init_creates_keypair(self):
        sc = SecureChannel()
        assert sc.sc_privkey is not None
        assert sc.sc_pubkey is not None
        assert sc.sc_pubkey_serialized is not None
        assert len(sc.sc_pubkey_serialized) == 65
        assert sc.initialized_secure_channel is False

    def test_initiate_with_peer_pubkey(self):
        sc = SecureChannel()
        peer_priv = ECPrivkey.generate_random_key()
        peer_pub_bytes = peer_priv.get_public_key_bytes(compressed=False)
        sc.initiate_secure_channel(peer_pub_bytes)
        assert sc.initialized_secure_channel is True
        assert sc.derived_key is not None
        assert len(sc.derived_key) == 16
        assert sc.mac_key is not None
        assert sc.shared_key is not None

    def test_encrypt_without_init_raises(self):
        sc = SecureChannel()
        with pytest.raises(UninitializedSecureChannelError):
            sc.encrypt_secure_channel(b"\x00\x01\x02\x03")

    def test_decrypt_without_init_raises(self):
        sc = SecureChannel()
        with pytest.raises(UninitializedSecureChannelError):
            sc.decrypt_secure_channel(b"\x00" * 16, b"\x00" * 16)

    def test_encrypt_decrypt_roundtrip(self):
        sc1 = SecureChannel()
        peer_priv = ECPrivkey.generate_random_key()
        peer_pub_bytes = peer_priv.get_public_key_bytes(compressed=False)
        sc1.initiate_secure_channel(peer_pub_bytes)

        plaintext = b"\x00\x02\x00\x00\x04\x01\x02\x03\x04"
        iv, ciphertext, mac = sc1.encrypt_secure_channel(plaintext)
        assert len(iv) == 16
        assert len(ciphertext) > 0
        assert len(mac) == 20

        decrypted = sc1.decrypt_secure_channel(iv, ciphertext)
        assert bytes(decrypted) == plaintext

    def test_ecdh_shared_secret_matches(self):
        sc1 = SecureChannel()
        sc2 = SecureChannel()

        sc1.initiate_secure_channel(sc2.sc_pubkey_serialized)
        sc2.initiate_secure_channel(sc1.sc_pubkey_serialized)

        assert sc1.shared_key == sc2.shared_key

    def test_iv_counter_increments(self):
        sc = SecureChannel()
        peer_priv = ECPrivkey.generate_random_key()
        peer_pub_bytes = peer_priv.get_public_key_bytes(compressed=False)
        sc.initiate_secure_channel(peer_pub_bytes)

        assert sc.sc_IVcounter == 1
        sc.encrypt_secure_channel(b"\x00" * 8)
        assert sc.sc_IVcounter == 3


class TestBip32PathConversion:
    def _path_to_bytes(self, bip32path):
        from electrum.bip32 import convert_bip32_path_to_list_of_uint32
        int_path = convert_bip32_path_to_list_of_uint32(bip32path)
        return len(int_path), b''.join(idx.to_bytes(4, 'big') for idx in int_path)

    def test_root(self):
        depth, path = self._path_to_bytes("m")
        assert depth == 0
        assert path == b""

    def test_single_hardened(self):
        depth, path = self._path_to_bytes("m/44'")
        assert depth == 1
        assert len(path) == 4
        assert path == (44 + 0x80000000).to_bytes(4, "big")

    def test_full_path(self):
        depth, path = self._path_to_bytes("m/44'/0'/0'/0/0")
        assert depth == 5
        assert len(path) == 20

    def test_without_m_prefix(self):
        depth, path = self._path_to_bytes("44'/0'/0'")
        assert depth == 3
        assert len(path) == 12

    def test_normal_index(self):
        depth, path = self._path_to_bytes("m/0")
        assert depth == 1
        assert path == (0).to_bytes(4, "big")


# ---------------------------------------------------------------------------
# _classify_reader / _reader_brand / _format_transport
# ---------------------------------------------------------------------------

from electrum.plugins.satochip.satochip import (
    _classify_reader,
    _reader_brand,
    _format_transport,
)


class TestClassifyReader:
    def test_nfc_keyword(self):
        assert _classify_reader("ACS ACR1252U USB NFC Reader") == "NFC"

    def test_contactless_keyword(self):
        assert _classify_reader("Broadcom Contactless Device") == "NFC"

    def test_picc_keyword(self):
        assert _classify_reader("Identive PICC Interface") == "NFC"

    def test_contact_keyword(self):
        assert _classify_reader("OMNIKEY AG Smart Card Reader USB") == "Contact"

    def test_smart_card_keyword(self):
        assert _classify_reader("Gemalto Smart Card Reader") == "Contact"

    def test_smartcard_keyword(self):
        assert _classify_reader("Generic SmartCard Reader") == "Contact"

    def test_unknown_reader(self):
        assert _classify_reader("SomeUnknownDevice 2000") == ""

    def test_empty_string(self):
        assert _classify_reader("") == ""

    def test_case_insensitive(self):
        assert _classify_reader("BROADCOM NFC DEVICE") == "NFC"


class TestReaderBrand:
    def test_short_first_word(self):
        assert _reader_brand("OMNIKEY AG Smart Card Reader USB") == "OMNIKEY"

    def test_long_first_word_ignored(self):
        # >12 chars → empty
        assert _reader_brand("AVERYLONGBRANDNAME Device") == ""

    def test_empty_name(self):
        assert _reader_brand("") == ""

    def test_exactly_12_chars(self):
        # exactly 12 chars — should be included
        brand = "A" * 12
        assert _reader_brand(f"{brand} device") == brand

    def test_exactly_13_chars_rejected(self):
        brand = "A" * 13
        assert _reader_brand(f"{brand} device") == ""


class TestFormatTransport:
    def test_contact_reader_with_brand(self):
        result = _format_transport("OMNIKEY AG Smart Card Reader USB")
        assert result == "OMNIKEY Contact"

    def test_nfc_reader_with_brand(self):
        result = _format_transport("ACS ACR1252U USB NFC Reader")
        assert result == "ACS NFC"

    def test_no_classification_returns_brand(self):
        result = _format_transport("OMNIKEY Unknown Device")
        assert result == "OMNIKEY"

    def test_no_brand_no_classification(self):
        result = _format_transport("AVERYLONGBRANDNAME Unknown")
        assert result == "smartcard"

    def test_brand_without_classification_no_brand(self):
        # >12 char first word, no classification → "smartcard"
        result = _format_transport("VERYLONGBRAND Unknown Device")
        assert result == "smartcard"

    def test_contact_reader_no_brand(self):
        # Long brand but has classification
        result = _format_transport("VERYLONGBRAND AG Smart Card Reader")
        assert result == "Contact"

    def test_fits_within_20_chars(self):
        result = _format_transport("OMNIKEY AG Smart Card Reader USB")
        assert len(result) <= 20

    def test_empty_reader_name(self):
        assert _format_transport("") == "smartcard"


# ---------------------------------------------------------------------------
# _get_device_identity / label / device_model_name
# ---------------------------------------------------------------------------

from unittest.mock import MagicMock, patch


def _make_client_with_status(status: dict, uid_sha1: str = "AABBCCDD1122334455"):
    with patch("electrum.plugins.satochip.satochip.list_pcsc_readers", return_value=[]):
        from electrum.plugins.satochip.satochip import SatochipClient
        plugin = MagicMock()
        plugin.device = "Satochip"
        client = SatochipClient.__new__(SatochipClient)
        client._soft_device_id = None
        client.device = "Satochip"
        client.handler = None
        client.hw_device = None
        client.reader_full_name = ""
        client.last_operation = float("inf")
        client._CARD_LABEL_SENTINELS = frozenset({"(none)", "(unknown)"})

        cc_mock = MagicMock()
        cc_mock.UID_SHA1 = uid_sha1
        cc_mock.card_get_label.return_value = (None, None, None, "")
        client.cc = cc_mock
    return client


class TestGetDeviceIdentity:
    def test_card_label_takes_priority(self):
        client = _make_client_with_status({})
        client.cc.card_get_label.return_value = (None, None, None, "savings")
        identity = client._get_device_identity()
        assert identity == "savings"

    def test_uid_fallback_when_no_label(self):
        client = _make_client_with_status({}, uid_sha1="DEADBEEF12345678")
        identity = client._get_device_identity()
        assert identity == "DEADBEEF"

    def test_empty_when_no_uid(self):
        client = _make_client_with_status({}, uid_sha1="")
        client.cc.UID_SHA1 = ""
        client.cc.parser = MagicMock()
        client.cc.parser.authentikey_coordx = None
        identity = client._get_device_identity()
        assert identity == ""

    def test_sentinel_label_skipped(self):
        client = _make_client_with_status({}, uid_sha1="DEADBEEF12345678")
        client.cc.card_get_label.return_value = (None, None, None, "(none)")
        identity = client._get_device_identity()
        assert identity == "DEADBEEF"

    def test_whitespace_label_skipped(self):
        client = _make_client_with_status({}, uid_sha1="DEADBEEF12345678")
        client.cc.card_get_label.return_value = (None, None, None, "   ")
        identity = client._get_device_identity()
        assert identity == "DEADBEEF"


class TestDeviceModelName:
    def test_returns_satochip(self):
        client = _make_client_with_status({})
        assert client.device_model_name() == "Satochip"


class TestLabelDisplay:
    def test_chooser_format_with_card_label(self):
        client = _make_client_with_status({})
        client.cc.card_get_label.return_value = (None, None, None, "savings")
        label = client._get_device_identity()
        model = client.device_model_name()
        descr = f"{label} [{model or 'satochip'}, initialized, OMNIKEY]"
        assert descr == "savings [Satochip, initialized, OMNIKEY]"

    def test_chooser_format_with_uid(self):
        client = _make_client_with_status({}, uid_sha1="DEADBEEF12345678")
        label = client._get_device_identity()
        model = client.device_model_name()
        descr = f"{label} [{model or 'satochip'}, wiped, OMNIKEY]"
        assert descr == "DEADBEEF [Satochip, wiped, OMNIKEY]"

    def test_three_bracket_fields(self):
        client = _make_client_with_status({}, uid_sha1="A1B2C3D40000")
        label = client._get_device_identity()
        model = client.device_model_name()
        transport = _format_transport("OMNIKEY AG Smart Card Reader USB")
        state = "initialized"
        descr = f"{label} [{model or 'satochip'}, {state}, {transport}]"
        parts = descr.split(" [")[1].rstrip("]").split(", ")
        assert len(parts) == 3

    def test_no_redundancy_with_uid(self):
        client = _make_client_with_status({}, uid_sha1="A1B2C3D40000")
        label = client._get_device_identity()
        assert "Satochip" not in label


# ---------------------------------------------------------------------------
# run_flow() context manager
# ---------------------------------------------------------------------------

from electrum.util import UserFacingException


class TestRunFlow:
    def _make_client(self):
        with patch("electrum.plugins.satochip.satochip.list_pcsc_readers", return_value=[]):
            from electrum.plugins.satochip.satochip import SatochipClient
            client = SatochipClient.__new__(SatochipClient)
            client._soft_device_id = None
            client.device = "Satochip"
            client.handler = MagicMock()
            client.hw_device = None
            client.reader_full_name = ""
            client.last_operation = float("inf")
            client.in_flow = False
            client.cc = MagicMock()
            return client

    def test_handler_finished_called_on_success(self):
        client = self._make_client()
        with client.run_flow():
            pass
        client.handler.finished.assert_called_once()

    def test_handler_finished_called_on_exception(self):
        client = self._make_client()
        with pytest.raises(RuntimeError):
            with client.run_flow():
                raise RuntimeError("boom")
        client.handler.finished.assert_called_once()

    def test_overlapping_flow_raises(self):
        client = self._make_client()
        with pytest.raises(RuntimeError, match="Overlapping"):
            with client.run_flow():
                with client.run_flow():
                    pass

    def test_card_not_present_converted(self):
        from electrum.plugins.satochip.exceptions import CardNotPresentError
        client = self._make_client()
        with pytest.raises(UserFacingException, match="Card not detected"):
            with client.run_flow():
                raise CardNotPresentError("no card")

    def test_used_called_after_flow(self):
        client = self._make_client()
        assert client.last_operation == float("inf")
        with client.run_flow():
            pass
        assert client.last_operation < float("inf")

    def test_in_flow_reset_after_flow(self):
        client = self._make_client()
        assert client.in_flow is False
        with client.run_flow():
            assert client.in_flow is True
        assert client.in_flow is False


# ---------------------------------------------------------------------------
# supports_taproot()
# ---------------------------------------------------------------------------


class TestSupportsTaproot:
    def _make_client(self, protocol_version=None, schnorr_policy=None):
        with patch("electrum.plugins.satochip.satochip.list_pcsc_readers", return_value=[]):
            from electrum.plugins.satochip.satochip import SatochipClient
            client = SatochipClient.__new__(SatochipClient)
            client._soft_device_id = None
            client.device = "Satochip"
            client.handler = MagicMock()
            client.hw_device = None
            client.reader_full_name = ""
            client.last_operation = float("inf")
            client.in_flow = False
            client.cc = MagicMock()
            client.cc.protocol_version = protocol_version
            if schnorr_policy is not None:
                client.cc.feature_schnorr_policy = schnorr_policy
            plugin = MagicMock()
            plugin.MIN_TAPROOT_VERSION = 14
            client.plugin = plugin
            return client

    def test_v012_not_supported(self):
        client = self._make_client(protocol_version=12)
        assert client.supports_taproot() is False

    def test_v014_supported(self):
        client = self._make_client(protocol_version=14, schnorr_policy=0)
        assert client.supports_taproot() is True

    def test_v014_schnorr_disabled(self):
        client = self._make_client(protocol_version=14, schnorr_policy=1)
        assert client.supports_taproot() is False

    def test_v014_schnorr_blocked(self):
        client = self._make_client(protocol_version=14, schnorr_policy=2)
        assert client.supports_taproot() is False

    def test_v015_supported(self):
        client = self._make_client(protocol_version=15, schnorr_policy=0)
        assert client.supports_taproot() is True

    def test_v014_no_policy_field_defaults_supported(self):
        client = self._make_client(protocol_version=14, schnorr_policy=None)
        del client.cc.feature_schnorr_policy
        assert client.supports_taproot() is True

    def test_none_protocol_returns_false(self):
        client = self._make_client(protocol_version=None)
        client.cc.card_get_status = MagicMock()
        client.cc.protocol_version = 12
        assert client.supports_taproot() is False
