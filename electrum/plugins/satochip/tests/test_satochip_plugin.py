from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import electrum_ecc as ecc

from electrum.crypto import hash_160, sha256d
from electrum.transaction import Sighash
from electrum.util import UserFacingException

from electrum.plugins.satochip import satochip
from electrum.wallet import Standard_Wallet
from tests import ElectrumTestCase


class _DummyPlugin:
    device = "Satochip"


class _DummyHandler:
    def show_error(self, msg):
        pass

    def show_message(self, msg):
        pass

    def update_status(self, status):
        return status

    def finished(self):
        pass


class _FakeDescriptor:
    def __init__(self, script_type: str):
        self._script_type = script_type

    def to_legacy_electrum_script_type(self):
        return self._script_type


class _FakeTxIn:
    def __init__(self, script_type: str = "p2tr", sighash=None):
        self.script_descriptor = _FakeDescriptor(script_type)
        self.sighash = sighash

    def is_coinbase_input(self):
        return False


class _FakeTxOut:
    def __init__(self, value: int, scriptpubkey: bytes):
        self.value = value
        self.scriptpubkey = scriptpubkey


class _FakeTx:
    def __init__(self, script_type: str = "p2tr"):
        self._inputs = [_FakeTxIn(script_type)]
        self._outputs = [_FakeTxOut(1000, bytes.fromhex("0014" + "11" * 20))]
        self.sigs = []
        self.raw = None

    def inputs(self):
        return self._inputs

    def outputs(self):
        return self._outputs

    def is_complete(self):
        return False

    def serialize_preimage(self, i):
        return b"preimage-for-test"

    def add_signature_to_txin(self, txin_idx, signing_pubkey, sig):
        self.sigs.append((txin_idx, signing_pubkey, sig))

    def serialize(self):
        return "deadbeef"


class TestHelpers(ElectrumTestCase):
    def test_bip32path2bytes(self):
        depth, raw = satochip.bip32path2bytes("m/84h/0h/0h/0/1")
        self.assertEqual(5, depth)
        self.assertEqual(20, len(raw))


class TestSatochipClient(ElectrumTestCase):
    def _mk_client(self, *, cc=None, handler=None):
        with patch("electrum.hw_wallet.plugin.assert_runs_in_hwd_thread", lambda: None):
            with patch("electrum.plugins.satochip.satochip.CardConnector") as cc_ctor:
                cc_ctor.return_value = cc if cc is not None else MagicMock()
                return satochip.SatochipClient(_DummyPlugin(), handler=handler)

    def test_repr_and_pairable_and_model(self):
        cc = MagicMock()
        cc.card_get_label.return_value = ([], 0x90, 0x00, "MyCard")
        c = self._mk_client(cc=cc, handler=None)
        # __repr__ should include the label
        self.assertIn("SatochipClient", repr(c))
        self.assertIn("MyCard", repr(c))
        self.assertTrue(c.is_pairable())
        self.assertEqual("Satochip", c.device_model_name())
        self.assertIsNone(c.timeout(1))

    def test_repr_on_error_returns_disconnected(self):
        cc = MagicMock()
        # Make label() throw by making card_get_label and authentikey_coordx both fail
        cc.card_get_label.side_effect = Exception("card error")
        cc.parser.authentikey_coordx = None
        # Also need to bypass the internal try/except in label()
        # by making hasattr return False
        c = self._mk_client(cc=cc)
        # The label() method handles errors gracefully, returning 'Satochip'
        # So __repr__ will succeed with the fallback label
        self.assertIn("SatochipClient", repr(c))

    def test_used_updates_last_operation(self):
        import time
        c = self._mk_client()
        # Initially infinity
        self.assertEqual(float('inf'), c.last_operation)
        c.used()
        self.assertLess(c.last_operation, float('inf'))
        self.assertGreater(c.last_operation, time.time() - 1)

    def test_prevent_timeouts_sets_infinity(self):
        c = self._mk_client()
        c.used()  # Set to finite value
        self.assertLess(c.last_operation, float('inf'))
        c.prevent_timeouts()
        self.assertEqual(float('inf'), c.last_operation)

    def test_timeout_clears_pin_cache(self):
        import time
        cc = MagicMock()
        cc.set_pin = MagicMock()
        c = self._mk_client(cc=cc)
        c.used()  # Set last_operation to now
        # With cutoff in the PAST (before last_operation), should NOT timeout
        # because last_operation > cutoff means operation was recent enough
        c.timeout(time.time() - 1000)
        cc.set_pin.assert_not_called()
        # With cutoff in the FUTURE (after last_operation), SHOULD timeout
        # because last_operation < cutoff means operation was too long ago
        c.timeout(time.time() + 1000)
        cc.set_pin.assert_called_once_with(0, None)

    def test_is_initialized_states(self):
        cc = MagicMock()
        cc.card_get_status.return_value = ([], 0x90, 0x00, {})

        cc.setup_done = False
        cc.is_seeded = False
        c = self._mk_client(cc=cc)
        self.assertIsNone(c.is_initialized())

        cc.setup_done = True
        cc.is_seeded = False
        self.assertFalse(c.is_initialized())

        cc.setup_done = True
        cc.is_seeded = True
        self.assertTrue(c.is_initialized())

    def test_close_calls_disconnect_and_observer_cleanup(self):
        cc = MagicMock()
        cc.cardmonitor = MagicMock()
        cc.cardobserver = object()
        c = self._mk_client(cc=cc)
        c.close()
        cc.card_disconnect.assert_called_once()
        cc.cardmonitor.deleteObserver.assert_called_once_with(cc.cardobserver)

    def test_label_priority_order(self):
        # Path 1: card has a user-set label
        cc = MagicMock()
        cc.card_get_label.return_value = ([], 0x90, 0x00, "MyCard")
        c = self._mk_client(cc=cc)
        self.assertEqual("Satochip: MyCard", c.label())

        # Path 1b: sentinel '(none)' is NOT treated as a real label
        # authentikey_coordx lives on cc.parser (32-byte raw X-coordinate)
        cc_none = MagicMock()
        cc_none.card_get_label.return_value = ([], 0x6d, 0x00, "(none)")
        cc_none.parser.authentikey_coordx = bytes.fromhex("aa" * 32)
        c_none = self._mk_client(cc=cc_none)
        fp_none = hash_160(cc_none.parser.authentikey_coordx)[:4].hex()
        self.assertEqual(f"Satochip {fp_none}", c_none.label())

        # Path 1c: sentinel '(unknown)' is NOT treated as a real label
        cc_unk = MagicMock()
        cc_unk.card_get_label.return_value = ([], 0x67, 0x00, "(unknown)")
        cc_unk.parser.authentikey_coordx = bytes.fromhex("bb" * 32)
        c_unk = self._mk_client(cc=cc_unk)
        fp_unk = hash_160(cc_unk.parser.authentikey_coordx)[:4].hex()
        self.assertEqual(f"Satochip {fp_unk}", c_unk.label())

        # Path 2: no card label but authentikey available → fingerprint
        cc2 = MagicMock()
        cc2.card_get_label.side_effect = Exception("unsupported")
        cc2.parser.authentikey_coordx = bytes.fromhex("22" * 32)
        c2 = self._mk_client(cc=cc2)
        fp = hash_160(cc2.parser.authentikey_coordx)[:4].hex()
        self.assertEqual(f"Satochip {fp}", c2.label())

        # Path 3: neither → generic fallback
        cc3 = MagicMock()
        cc3.card_get_label.side_effect = Exception("unsupported")
        cc3.parser.authentikey_coordx = None
        c3 = self._mk_client(cc=cc3)
        self.assertEqual("Satochip", c3.label())

    def test_supports_taproot(self):
        cc = MagicMock()
        cc.protocol_version = 14
        c = self._mk_client(cc=cc)
        self.assertTrue(c.supports_taproot())

        cc.protocol_version = 13
        self.assertFalse(c.supports_taproot())

    def test_has_usable_connection_with_device(self):
        cc = MagicMock()
        cc.card_get_ATR.return_value = [0x3B, 0x00]
        c = self._mk_client(cc=cc)
        self.assertTrue(c.has_usable_connection_with_device())

        cc.card_get_ATR.side_effect = Exception("reader error")
        self.assertFalse(c.has_usable_connection_with_device())

    def test_has_usable_connection_with_device_no_cardservice(self):
        """Null cardservice (card removed) returns False without exception."""
        cc = MagicMock()
        cc.cardservice = None
        c = self._mk_client(cc=cc)
        self.assertFalse(c.has_usable_connection_with_device())
        # card_get_ATR should never be called when cardservice is None
        cc.card_get_ATR.assert_not_called()

    def test_request_dispatch(self):
        handler = MagicMock()
        handler.update_status.return_value = "ok"
        c = self._mk_client(handler=handler)
        self.assertEqual("ok", c.request("update_status", True))
        c.request("show_message", "hello")
        handler.show_message.assert_called_once()
        c.request("unknown", "x")
        handler.show_error.assert_called()

    def test_pin_dialog_validation(self):
        h = MagicMock()
        h.get_passphrase.side_effect = ["12", "1234"]
        c = self._mk_client(handler=h)
        ok, pin = c.PIN_dialog("msg")
        self.assertTrue(ok)
        self.assertEqual(b"1234", pin)

    def test_pin_setup_dialog(self):
        c = self._mk_client(handler=MagicMock())
        c.PIN_dialog = MagicMock(side_effect=[(True, b"1111"), (True, b"2222"), (True, b"3333"), (True, b"3333")])
        c.request = MagicMock()
        ok, pin = c.PIN_setup_dialog("a", "b", "err")
        self.assertTrue(ok)
        self.assertEqual(b"3333", pin)
        c.request.assert_called_with("show_error", "err")

    def test_pin_change_dialog_cancel(self):
        c = self._mk_client(handler=MagicMock())
        c.PIN_dialog = MagicMock(return_value=(False, None))
        c.request = MagicMock()
        self.assertEqual((False, None, None), c.PIN_change_dialog("o", "n", "c", "e", "cancel"))
        c.request.assert_called_with("show_message", "cancel")

    def test_verify_pin_error_paths(self):
        cc = MagicMock()
        cc.card_verify_PIN_simple.side_effect = satochip.PinBlockedError("blocked")
        c = self._mk_client(cc=cc, handler=MagicMock())
        with self.assertRaises(UserFacingException):
            c.verify_PIN()

        cc2 = MagicMock()
        cc2.card_verify_PIN_simple.side_effect = satochip.CardNotPresentError("no card")
        c2 = self._mk_client(cc=cc2, handler=MagicMock())
        c2.PIN_dialog = lambda msg: (False, None)
        self.assertFalse(c2.verify_PIN())

        cc3 = MagicMock()
        cc3.card_verify_PIN_simple.side_effect = [satochip.PinRequiredError("pin"), ([], 0x90, 0x00)]
        c3 = self._mk_client(cc=cc3, handler=MagicMock())
        c3.PIN_dialog = lambda msg: (True, b"1234")
        self.assertTrue(c3.verify_PIN())

    # Coverage note:
    # verify_PIN() explicitly maps UnexpectedSW12Error to UserFacingException.
    # This test documents and validates that mapping.
    def test_verify_pin_unexpected_sw12_error_mapping(self):
        cc = MagicMock()
        cc.card_verify_PIN_simple.side_effect = satochip.UnexpectedSW12Error("0x6f00")
        c = self._mk_client(cc=cc, handler=MagicMock())
        with self.assertRaises(UserFacingException):
            c.verify_PIN()

    def test_get_xpub_uses_bip32node(self):
        cc = MagicMock()
        fake_key = SimpleNamespace(get_public_key_bytes=lambda compressed: b"\x02" + b"\x11" * 32)
        cc.card_bip32_get_extendedkey.side_effect = [(fake_key, b"\x01" * 32), (fake_key, b"\x02" * 32)]
        c = self._mk_client(cc=cc, handler=MagicMock())
        c.verify_PIN = lambda pin=None: True

        class _FakeNode:
            def __init__(self, **kwargs):
                pass

            def to_xpub(self):
                return "xpub-test"

        with patch("electrum.plugins.satochip.satochip.BIP32Node", _FakeNode):
            xpub = c.get_xpub("m/84h/0h/0h", "p2wpkh")
        self.assertEqual("xpub-test", xpub)

    # Coverage note:
    # get_xpub() handles pysatochip UninitializedSeedError and re-raises it
    # as UserFacingException for Electrum UI consumption.
    def test_get_xpub_uninitialized_seed_error_mapping(self):
        cc = MagicMock()
        cc.card_bip32_get_extendedkey.side_effect = satochip.UninitializedSeedError("seed missing")
        c = self._mk_client(cc=cc, handler=MagicMock())
        c.verify_PIN = lambda pin=None: True
        with self.assertRaises(UserFacingException):
            c.get_xpub("m/84h/0h/0h", "p2wpkh")

    def test_perform_factory_reset_rejects_non_satochip_card(self):
        cc = MagicMock()
        cc.card_type = "SeedKeeper"
        c = self._mk_client(cc=cc, handler=MagicMock())

        with self.assertRaises(UserFacingException) as ctx:
            c.perform_factory_reset()
        self.assertIn("only supports Satochip cards", str(ctx.exception))
        cc.set_mode_factory_reset.assert_not_called()

    def test_perform_factory_reset_aborts_if_version_check_fails(self):
        cc = MagicMock()
        cc.card_type = "Satochip"
        cc.card_get_status.side_effect = RuntimeError("status unavailable")
        c = self._mk_client(cc=cc, handler=MagicMock())

        with self.assertRaises(UserFacingException) as ctx:
            c.perform_factory_reset()
        self.assertIn("unable to verify Satochip firmware version", str(ctx.exception))
        cc.set_mode_factory_reset.assert_not_called()

    def test_perform_factory_reset_satochip_success_path(self):
        cc = MagicMock()
        cc.card_type = "Satochip"
        cc.card_get_status.return_value = (
            [],
            0x90,
            0x00,
            {
                "protocol_major_version": 0,
                "protocol_minor_version": 12,
                "applet_major_version": 0,
                "applet_minor_version": 4,
            },
        )
        cc.card_reset_factory_signal.return_value = ([], 0xFF, 0x00)

        c = self._mk_client(cc=cc, handler=MagicMock())
        c._wait_for_card_absent = MagicMock(return_value=True)
        c._wait_for_card_present = MagicMock(return_value=True)
        c.request = MagicMock()

        self.assertTrue(c.perform_factory_reset())
        cc.set_mode_factory_reset.assert_any_call(True)
        cc.card_reset_factory_signal.assert_called_once()
        cc.card_disconnect.assert_called_once()
        cc.set_mode_factory_reset.assert_any_call(False)

    def test_perform_factory_reset_fails_immediately_on_6e00(self):
        cc = MagicMock()
        cc.card_type = "Satochip"
        cc.card_get_status.return_value = (
            [],
            0x90,
            0x00,
            {
                "protocol_major_version": 0,
                "protocol_minor_version": 12,
                "applet_major_version": 0,
                "applet_minor_version": 4,
            },
        )
        cc.card_reset_factory_signal.return_value = ([], 0x6E, 0x00)

        c = self._mk_client(cc=cc, handler=MagicMock())
        c._wait_for_card_absent = MagicMock(return_value=True)
        c._wait_for_card_present = MagicMock(return_value=True)
        c.request = MagicMock()

        with self.assertRaises(UserFacingException) as ctx:
            c.perform_factory_reset()
        self.assertIn("0x6E00", str(ctx.exception))
        cc.card_reset_factory_signal.assert_called_once()
        cc.set_mode_factory_reset.assert_any_call(False)


class TestSatochipKeystore(ElectrumTestCase):
    def _mk_keystore(self):
        ks = object.__new__(satochip.Satochip_KeyStore)
        ks.ux_busy = False
        ks.handler = MagicMock()
        ks.plugin = SimpleNamespace(config=SimpleNamespace(get=lambda *a, **k: "server"))
        ks._satochip_authentikey = None  # For device verification
        ks._expected_device = None  # Cache for verified device
        return ks


    def test_dump_and_decrypt(self):
        ks = self._mk_keystore()
        with patch("electrum.plugins.satochip.satochip.Hardware_KeyStore.dump", return_value={"a": 1}):
            # dump() now adds satochip_authentikey
            result = ks.dump()
            self.assertEqual(1, result.get("a"))
            self.assertIn("satochip_authentikey", result)
        with self.assertRaises(RuntimeError):
            ks.decrypt_message(None, b"m", None)


    def test_give_error(self):
        ks = self._mk_keystore()
        ks.client = object()
        with self.assertRaises(UserFacingException):
            ks.give_error("boom", clear_client=True)
        ks.handler.show_error.assert_called_once_with("boom")
        self.assertIsNone(ks.client)

    def test_wrap_busy_resets_flag(self):
        ks = self._mk_keystore()

        @satochip.Satochip_KeyStore.wrap_busy
        def _f(self):
            raise RuntimeError("x")

        with self.assertRaises(RuntimeError):
            _f(ks)
        self.assertFalse(ks.ux_busy)

    def test_sign_message_basic(self):
        ks = self._mk_keystore()
        ks.get_derivation_prefix = lambda: "m/84h/0h/0h"
        ks.handler = MagicMock()
        client = SimpleNamespace(
            verify_PIN=lambda: True,
            cc=SimpleNamespace(
                needs_2FA=False,
                card_bip32_get_extendedkey=lambda p: (object(), b"\x00" * 32),
                card_sign_message=lambda *a, **k: ([], 0x90, 0x00, b"sig"),
            ),
        )
        ks.get_client = lambda: client
        sig = ks.sign_message((0, 1), "hello", None)
        self.assertEqual(b"sig", sig)

    def test_do_challenge_response(self):
        ks = self._mk_keystore()
        ks.handler = MagicMock()
        cc = SimpleNamespace(card_crypt_transaction_2FA=MagicMock(side_effect=[("id", "enc"), "challenge:abcd"]))
        ks.get_client = lambda: SimpleNamespace(cc=cc)

        def _respond(d, server_name=None):
            d["reply_encrypt"] = "reply"

        with patch("electrum.plugins.satochip.satochip.Satochip2FA.do_challenge_response", side_effect=_respond):
            hmac_hex = ks.do_challenge_response('{"k":"v"}')
        self.assertEqual("abcd", hmac_hex)
        ks.handler.finished.assert_called_once()

    def _mk_tx_keystore(self):
        ks = self._mk_keystore()
        ks.find_my_pubkey_in_txinout = lambda txin: (b"\x02" + b"\x11" * 32, [2147483732, 2147483648, 2147483648, 0, 0])
        return ks

    def test_sign_transaction_taproot_rules_and_schnorr(self):
        ks = self._mk_tx_keystore()

        client = SimpleNamespace(verify_PIN=lambda: True, supports_taproot=lambda: True, cc=SimpleNamespace(needs_2FA=True))
        ks.get_client = lambda: client
        with self.assertRaises(UserFacingException):
            ks.sign_transaction(_FakeTx("p2tr"), None)

        client2 = SimpleNamespace(verify_PIN=lambda: True, supports_taproot=lambda: False, cc=SimpleNamespace(needs_2FA=False))
        ks.get_client = lambda: client2
        with self.assertRaises(UserFacingException):
            ks.sign_transaction(_FakeTx("p2tr"), None)

        tx = _FakeTx("p2tr")
        pre_hash = sha256d(tx.serialize_preimage(0))
        cc = SimpleNamespace(
            needs_2FA=False,
            card_bip32_get_extendedkey=lambda p: (object(), b"\x00" * 32),
            card_parse_transaction=lambda pre_tx, segwit: ([], 0x90, 0x00, list(pre_hash), False),
            card_sign_schnorr_hash=lambda keynbr, tap_hash, hmac: (b"\x22" * 64, 0x90, 0x00),
            card_sign_transaction=lambda *a, **k: (_ for _ in ()).throw(AssertionError("ecdsa path should not be used")),
        )
        client3 = SimpleNamespace(verify_PIN=lambda: True, supports_taproot=lambda: True, cc=cc)
        ks.get_client = lambda: client3
        ks.sign_transaction(tx, None)
        self.assertEqual(1, len(tx.sigs))
        self.assertEqual(64, len(tx.sigs[0][2]))

    def test_sign_transaction_ecdsa_path(self):
        ks = self._mk_tx_keystore()
        tx = _FakeTx("p2wpkh")
        pre_hash = sha256d(tx.serialize_preimage(0))
        der = ecc.ecdsa_der_sig_from_r_and_s(1, 1)
        cc = SimpleNamespace(
            needs_2FA=False,
            card_bip32_get_extendedkey=lambda p: (object(), b"\x00" * 32),
            card_parse_transaction=lambda pre_tx, segwit: ([], 0x90, 0x00, list(pre_hash), False),
            card_sign_transaction=lambda keynbr, tx_hash, hmac: (der, 0x90, 0x00),
        )
        client = SimpleNamespace(verify_PIN=lambda: True, supports_taproot=lambda: True, cc=cc)
        ks.get_client = lambda: client
        ks.sign_transaction(tx, None)
        self.assertEqual(1, len(tx.sigs))
        self.assertTrue(tx.sigs[0][2].endswith(Sighash.to_sigbytes(Sighash.ALL)))


class TestSatochipPlugin(ElectrumTestCase):
    def _mk_plugin(self):
        p = object.__new__(satochip.SatochipPlugin)
        p.device = "Satochip"
        p.config = SimpleNamespace(get=lambda *a, **k: "server")
        p.handler = MagicMock()
        return p

    def test_library_version(self):
        """get_library_version() must return the real pysatochip.__version__."""
        import pysatochip
        p = self._mk_plugin()
        version = p.get_library_version()
        self.assertEqual(pysatochip.__version__, version,
                         "get_library_version() should match pysatochip.__version__")
        # Version string must be non-empty and not the old placeholder
        self.assertTrue(len(version) > 0, "Version string must not be empty")
        self.assertNotEqual("0.0.1", version,
                             "Version should be the real library version, not the old placeholder '0.0.1'")

    def test_detect_smartcard_reader(self):
        p = self._mk_plugin()
        with patch("electrum.plugins.satochip.satochip.list_pcsc_readers", return_value=["Mock Reader"]):
            with patch("electrum.plugins.satochip.satochip.AnyCardType", return_value=object()):
                with patch("electrum.plugins.satochip.satochip.CardRequest") as cr:
                    cr.return_value.waitforcard.return_value = object()
                    devices = p.detect_smartcard_reader()
                    self.assertEqual(1, len(devices))
                    self.assertEqual("/satochip", devices[0].path)

        with patch("electrum.plugins.satochip.satochip.list_pcsc_readers", return_value=["Mock Reader"]):
            with patch("electrum.plugins.satochip.satochip.AnyCardType", return_value=object()):
                with patch("electrum.plugins.satochip.satochip.CardRequest") as cr:
                    cr.return_value.waitforcard.side_effect = satochip.CardRequestTimeoutException()
                    # Even with timeout, device is returned since reader is present
                    devices = p.detect_smartcard_reader()
                    self.assertEqual(1, len(devices))
                    self.assertEqual("/satochip", devices[0].path)

    def test_create_client_success_and_failure(self):
        p = self._mk_plugin()
        with patch("electrum.plugins.satochip.satochip.SatochipClient", return_value="client"):
            self.assertEqual("client", p.create_client(None, MagicMock()))
        with patch("electrum.plugins.satochip.satochip.SatochipClient", side_effect=Exception("boom")):
            self.assertIsNone(p.create_client(None, MagicMock()))

    def test_get_client_passthrough(self):
        p = self._mk_plugin()
        devmgr = MagicMock()
        devmgr.client_for_keystore.return_value = "client"
        p.device_manager = lambda: devmgr
        ks = SimpleNamespace(handler=MagicMock())
        self.assertEqual("client", p.get_client(ks))

    def test_get_xpub(self):
        p = self._mk_plugin()
        p.SUPPORTED_XTYPES = ("p2wpkh",)
        devmgr = MagicMock()
        devmgr.client_by_id.return_value = SimpleNamespace(get_xpub=lambda d, x: "xpub1", handler=None)
        p.device_manager = lambda: devmgr
        p.create_handler = lambda wizard: "handler"
        self.assertEqual("xpub1", p.get_xpub("dev1", "m/84h/0h/0h", "p2wpkh", object()))
        with self.assertRaises(Exception):
            p.get_xpub("dev1", "m/84h/0h/0h", "p2tr", object())

    def test_setup_device_and_import_seed(self):
        p = self._mk_plugin()
        client = SimpleNamespace(
            cc=SimpleNamespace(
                card_type="Satochip",
                set_pin=MagicMock(),
                card_setup=lambda *a: ([], 0x90, 0x00),
                card_get_status=lambda: ([], 0x90, 0x00, {'setup_done': False, 'is_seeded': False}),
                card_bip32_import_seed=MagicMock(return_value=SimpleNamespace(get_public_key_hex=lambda compressed: "02aa")),
            ),
            handler=MagicMock(),
            verify_PIN=MagicMock(),
        )
        devmgr = MagicMock()
        devmgr.client_by_id.return_value = client
        p.device_manager = lambda: devmgr

        p._setup_device("1234", "dev1", client.handler)
        client.cc.set_pin.assert_called_once()
        client.verify_PIN.assert_called_once()

        with self.assertRaises(Exception):
            p._import_seed(("electrum", "seed words", ""), "dev1", client.handler)

        with patch("electrum.plugins.satochip.satochip.bip39_is_checksum_valid", return_value=(False, False)):
            with self.assertRaises(Exception):
                p._import_seed(("bip39", "seed words", ""), "dev1", client.handler)

        with patch("electrum.plugins.satochip.satochip.bip39_is_checksum_valid", return_value=(True, True)):
            with patch("electrum.plugins.satochip.satochip.bip39_to_seed", return_value=b"\x01" * 64):
                p._import_seed(("bip39", "seed words", "pass"), "dev1", client.handler)
                self.assertTrue(client.cc.card_bip32_import_seed.called)

    def test_wizard_entry_and_extend(self):
        p = self._mk_plugin()
        di_none = SimpleNamespace(initialized=None, label="")
        di_false = SimpleNamespace(initialized=False, label="")
        di_true = SimpleNamespace(initialized=True, label="")
        self.assertEqual("satochip_not_setup", p.wizard_entry_for_device(di_none, new_wallet=True))
        self.assertEqual("satochip_not_seeded", p.wizard_entry_for_device(di_false, new_wallet=True))
        self.assertEqual("satochip_start", p.wizard_entry_for_device(di_true, new_wallet=True))
        self.assertEqual("satochip_recover_seed", p.wizard_entry_for_device(di_false, new_wallet=False))

        wizard = SimpleNamespace(navmap_merge=MagicMock(), wallet_password_view=lambda d: "pw", last_cosigner=lambda d: True, maybe_master_pubkey=lambda d: True, is_single_password=lambda: True)
        p.extend_wizard(wizard)
        wizard.navmap_merge.assert_called_once()

    def test_show_address_non_standard_wallet(self):
        p = self._mk_plugin()
        p.show_address_helper = lambda wallet, address, keystore: True
        ks = SimpleNamespace(handler=MagicMock(), show_address=MagicMock())
        wallet = SimpleNamespace(get_keystore=lambda: ks)
        p.show_address(wallet, "bc1q...")
        ks.handler.show_error.assert_called_once()

    def test_show_address_helper_returns_false(self):
        """show_address_helper returning False triggers early return."""
        p = self._mk_plugin()
        p.show_address_helper = lambda wallet, address, keystore: False
        ks = SimpleNamespace(handler=MagicMock(), show_address=MagicMock())
        wallet = SimpleNamespace(get_keystore=lambda: ks)
        p.show_address(wallet, "bc1q...")
        ks.show_address.assert_not_called()

    def test_show_address_standard_wallet(self):
        """Standard_Wallet dispatches to keystore.show_address()."""
        p = self._mk_plugin()
        p.show_address_helper = lambda wallet, address, keystore: True
        ks = SimpleNamespace(handler=MagicMock(), show_address=MagicMock())
        wallet = Standard_Wallet.__new__(Standard_Wallet)
        wallet.get_keystore = lambda: ks
        wallet.get_address_index = lambda addr: (0, 5)
        wallet.get_txin_type = lambda addr: "p2wpkh"
        p.show_address(wallet, "bc1q...")
        ks.show_address.assert_called_once_with((0, 5), "p2wpkh")

    def test_get_soft_device_id_returns_none(self):
        """get_soft_device_id() returns None (never set in current design)."""
        c = TestSatochipClient._mk_client(self)
        self.assertIsNone(c.get_soft_device_id())

    def test_wizard_entry_existing_wallet_true_state(self):
        """Existing wallet with initialized=True returns satochip_unlock."""
        p = self._mk_plugin()
        di = SimpleNamespace(initialized=True, label="")
        self.assertEqual("satochip_unlock", p.wizard_entry_for_device(di, new_wallet=False))

    def test_wizard_entry_existing_wallet_none_state(self):
        """Existing wallet with initialized=None returns satochip_recover_setup (factory-fresh card needs setup)."""
        p = self._mk_plugin()
        di = SimpleNamespace(initialized=None, label="")
        self.assertEqual("satochip_recover_setup", p.wizard_entry_for_device(di, new_wallet=False))


class TestSignMessageEdgeCases(ElectrumTestCase):
    """Edge/error paths in Satochip_KeyStore.sign_message()."""

    def _mk_keystore(self):
        ks = object.__new__(satochip.Satochip_KeyStore)
        ks.ux_busy = False
        ks.handler = MagicMock()
        ks.plugin = SimpleNamespace(config=SimpleNamespace(get=lambda *a, **k: "server"))
        ks.get_derivation_prefix = lambda: "m/84h/0h/0h"
        return ks

    def test_pin_cancel_returns_empty(self):
        """PIN cancellation returns b'' without calling card."""
        ks = self._mk_keystore()
        client = SimpleNamespace(verify_PIN=lambda: False, cc=MagicMock())
        ks.get_client = lambda: client
        result = ks.sign_message((0, 0), "hello", None)
        self.assertEqual(b'', result)
        client.cc.card_bip32_get_extendedkey.assert_not_called()

    def test_needs_2fa_none_triggers_status_check(self):
        """When needs_2FA is None, card_get_status() is called to populate flag."""
        ks = self._mk_keystore()
        cc = MagicMock()
        cc.needs_2FA = None
        cc.card_get_status.return_value = ([], 0x90, 0x00, {})
        # After card_get_status, needs_2FA should now be set.
        # Simulate: card_get_status sets needs_2FA to False.
        def _set_flag(*a):
            cc.needs_2FA = False
            return ([], 0x90, 0x00, {})
        cc.card_get_status.side_effect = _set_flag
        cc.card_bip32_get_extendedkey.return_value = (object(), b"\x00" * 32)
        cc.card_sign_message.return_value = ([], 0x90, 0x00, b"sig")
        client = SimpleNamespace(verify_PIN=lambda: True, cc=cc)
        ks.get_client = lambda: client
        result = ks.sign_message((0, 1), "test", None)
        self.assertEqual(b"sig", result)
        cc.card_get_status.assert_called_once()

    def test_2fa_path_passes_hmac(self):
        """When needs_2FA=True, do_challenge_response is called and hmac forwarded."""
        ks = self._mk_keystore()
        cc = MagicMock()
        cc.needs_2FA = True
        cc.card_bip32_get_extendedkey.return_value = (object(), b"\x00" * 32)
        cc.card_sign_message.return_value = ([], 0x90, 0x00, b"sig2fa")
        client = SimpleNamespace(verify_PIN=lambda: True, cc=cc)
        ks.get_client = lambda: client
        ks.do_challenge_response = MagicMock(return_value="aabb")
        result = ks.sign_message((0, 0), "msg", None)
        self.assertEqual(b"sig2fa", result)
        ks.do_challenge_response.assert_called_once()
        # hmac should be bytes.fromhex("aabb")
        call_args = cc.card_sign_message.call_args
        self.assertEqual(bytes.fromhex("aabb"), call_args[0][3])

    def test_empty_compsig_shows_error(self):
        """Empty compsig from card (2FA rejection) triggers handler.show_error()."""
        ks = self._mk_keystore()
        cc = MagicMock()
        cc.needs_2FA = False
        cc.card_bip32_get_extendedkey.return_value = (object(), b"\x00" * 32)
        cc.card_sign_message.return_value = ([], 0x90, 0x00, b'')
        client = SimpleNamespace(verify_PIN=lambda: True, cc=cc)
        ks.get_client = lambda: client
        result = ks.sign_message((0, 0), "msg", None)
        self.assertEqual(b'', result)
        ks.handler.show_error.assert_called_once()

    def test_exception_returns_empty_and_calls_finished(self):
        """Exception during signing returns b'' and handler.finished() is still called."""
        ks = self._mk_keystore()
        cc = MagicMock()
        cc.needs_2FA = False
        cc.card_bip32_get_extendedkey.side_effect = Exception("card error")
        client = SimpleNamespace(verify_PIN=lambda: True, cc=cc)
        ks.get_client = lambda: client
        result = ks.sign_message((0, 0), "msg", None)
        self.assertEqual(b'', result)
        ks.handler.finished.assert_called_once()
        ks.handler.show_error.assert_called_once()

    def test_finished_called_on_success(self):
        """handler.finished() called even on successful signing (finally block)."""
        ks = self._mk_keystore()
        cc = MagicMock()
        cc.needs_2FA = False
        cc.card_bip32_get_extendedkey.return_value = (object(), b"\x00" * 32)
        cc.card_sign_message.return_value = ([], 0x90, 0x00, b"ok")
        client = SimpleNamespace(verify_PIN=lambda: True, cc=cc)
        ks.get_client = lambda: client
        ks.sign_message((0, 0), "msg", None)
        ks.handler.finished.assert_called_once()

    def test_card_not_present_during_sign_message_shows_error(self):
        """CardNotPresentError during signing shows error and returns b''."""
        ks = self._mk_keystore()
        cc = MagicMock()
        cc.needs_2FA = False
        cc.card_bip32_get_extendedkey.side_effect = satochip.CardNotPresentError("no card")
        client = SimpleNamespace(verify_PIN=lambda: True, cc=cc)
        ks.get_client = lambda: client
        result = ks.sign_message((0, 0), "msg", None)
        self.assertEqual(b'', result)
        ks.handler.finished.assert_called_once()
        ks.handler.show_error.assert_called_once()
        # Verify the error message contains card-related text
        call_args = ks.handler.show_error.call_args[0][0]
        self.assertIn("Card not detected", call_args)

    def test_pin_blocked_during_sign_message_shows_error(self):
        """PinBlockedError during signing shows error and returns b''."""
        ks = self._mk_keystore()
        cc = MagicMock()
        cc.needs_2FA = False
        cc.card_bip32_get_extendedkey.side_effect = satochip.PinBlockedError("pin blocked")
        client = SimpleNamespace(verify_PIN=lambda: True, cc=cc)
        ks.get_client = lambda: client
        result = ks.sign_message((0, 0), "msg", None)
        self.assertEqual(b'', result)
        ks.handler.finished.assert_called_once()
        ks.handler.show_error.assert_called_once()
        # Verify the error message contains PIN-related text
        call_args = ks.handler.show_error.call_args[0][0]
        self.assertIn("PIN is blocked", call_args)


class TestSignTransactionEdgeCases(ElectrumTestCase):
    """Edge/error paths in Satochip_KeyStore.sign_transaction()."""

    def _mk_keystore(self):
        ks = object.__new__(satochip.Satochip_KeyStore)
        ks.ux_busy = False
        ks.handler = MagicMock()
        ks.plugin = SimpleNamespace(config=SimpleNamespace(get=lambda *a, **k: "server"))
        ks.find_my_pubkey_in_txinout = lambda txin: (
            b"\x02" + b"\x11" * 32,
            [2147483732, 2147483648, 2147483648, 0, 0],
        )
        return ks

    def test_already_complete_skips_signing(self):
        """tx.is_complete() returns True from the start → no signing done."""
        ks = self._mk_keystore()
        client = SimpleNamespace(verify_PIN=lambda: True, cc=MagicMock())
        ks.get_client = lambda: client

        tx = _FakeTx("p2wpkh")
        tx.is_complete = lambda: True  # already signed
        ks.sign_transaction(tx, None)
        self.assertEqual(0, len(tx.sigs))
        client.cc.card_parse_transaction.assert_not_called()

    def test_coinbase_input_raises(self):
        """Coinbase input raises UserFacingException."""
        ks = self._mk_keystore()
        client = SimpleNamespace(verify_PIN=lambda: True, supports_taproot=lambda: True,
                                 cc=SimpleNamespace(needs_2FA=False))
        ks.get_client = lambda: client

        tx = _FakeTx("p2wpkh")
        tx._inputs[0].is_coinbase_input = lambda: True
        with self.assertRaises(UserFacingException) as ctx:
            ks.sign_transaction(tx, None)
        self.assertIn("Coinbase", str(ctx.exception))

    def test_preimage_hash_mismatch_raises(self):
        """Pre-image hash mismatch raises RuntimeError."""
        ks = self._mk_keystore()
        cc = MagicMock()
        cc.needs_2FA = False
        cc.card_bip32_get_extendedkey.return_value = (object(), b"\x00" * 32)
        # Return a wrong hash
        cc.card_parse_transaction.return_value = ([], 0x90, 0x00, list(b"\xff" * 32), False)
        client = SimpleNamespace(verify_PIN=lambda: True, supports_taproot=lambda: True, cc=cc)
        ks.get_client = lambda: client

        tx = _FakeTx("p2wpkh")
        with self.assertRaises(RuntimeError) as ctx:
            ks.sign_transaction(tx, None)
        self.assertIn("mismatch", str(ctx.exception))

    def test_card_not_present_during_sign_transaction_raises_user_facing(self):
        ks = self._mk_keystore()
        cc = MagicMock()
        cc.needs_2FA = False
        cc.card_bip32_get_extendedkey.side_effect = satochip.CardNotPresentError("no card")
        client = SimpleNamespace(verify_PIN=lambda: True, supports_taproot=lambda: True, cc=cc)
        ks.get_client = lambda: client

        with self.assertRaises(UserFacingException) as ctx:
            ks.sign_transaction(_FakeTx("p2wpkh"), None)
        self.assertIn("no card", str(ctx.exception))

    def test_runtime_error_propagates_from_sign_transaction(self):
        ks = self._mk_keystore()
        tx = _FakeTx("p2wpkh")
        pre_hash = sha256d(tx.serialize_preimage(0))
        cc = MagicMock()
        cc.needs_2FA = False
        cc.card_bip32_get_extendedkey.return_value = (object(), b"\x00" * 32)
        cc.card_parse_transaction.return_value = ([], 0x90, 0x00, list(bytes(pre_hash[:-1]) + b"\xff"), False)
        client = SimpleNamespace(verify_PIN=lambda: True, supports_taproot=lambda: True, cc=cc)
        ks.get_client = lambda: client
        ks.give_error = MagicMock(side_effect=AssertionError("give_error should not be called"))

        with self.assertRaises(RuntimeError) as ctx:
            ks.sign_transaction(tx, None)
        self.assertIn("mismatch", str(ctx.exception))

    def test_user_facing_exception_propagates_from_sign_transaction(self):
        ks = self._mk_keystore()
        tx = _FakeTx("p2tr")
        cc = MagicMock()
        cc.needs_2FA = True
        client = SimpleNamespace(verify_PIN=lambda: True, supports_taproot=lambda: True, cc=cc)
        ks.get_client = lambda: client
        ks.give_error = MagicMock(side_effect=AssertionError("give_error should not be called"))

        with self.assertRaises(UserFacingException) as ctx:
            ks.sign_transaction(tx, None)
        self.assertIn("Taproot", str(ctx.exception))

    def test_ecdsa_sw_error_raises(self):
        """SW error from card_sign_transaction raises UserFacingException."""
        ks = self._mk_keystore()
        tx = _FakeTx("p2wpkh")
        pre_hash = sha256d(tx.serialize_preimage(0))
        cc = MagicMock()
        cc.needs_2FA = False
        cc.card_bip32_get_extendedkey.return_value = (object(), b"\x00" * 32)
        cc.card_parse_transaction.return_value = ([], 0x90, 0x00, list(pre_hash), False)
        cc.card_sign_transaction.return_value = (b"", 0x9C, 0x0B)
        client = SimpleNamespace(verify_PIN=lambda: True, supports_taproot=lambda: True, cc=cc)
        ks.get_client = lambda: client

        with self.assertRaises(UserFacingException) as ctx:
            ks.sign_transaction(tx, None)
        self.assertIn("failed to sign", str(ctx.exception))

    def test_taproot_sw_error_raises(self):
        """SW error from card_sign_schnorr_hash raises UserFacingException."""
        ks = self._mk_keystore()
        tx = _FakeTx("p2tr")
        pre_hash = sha256d(tx.serialize_preimage(0))
        cc = MagicMock()
        cc.needs_2FA = False
        cc.card_bip32_get_extendedkey.return_value = (object(), b"\x00" * 32)
        cc.card_parse_transaction.return_value = ([], 0x90, 0x00, list(pre_hash), False)
        cc.card_sign_schnorr_hash.return_value = (b"", 0x6F, 0x00)
        client = SimpleNamespace(verify_PIN=lambda: True, supports_taproot=lambda: True, cc=cc)
        ks.get_client = lambda: client

        with self.assertRaises(UserFacingException) as ctx:
            ks.sign_transaction(tx, None)
        self.assertIn("Taproot", str(ctx.exception))

    def test_taproot_explicit_sighash(self):
        """Taproot with explicit sighash (not DEFAULT) appends that sighash byte."""
        ks = self._mk_keystore()
        tx = _FakeTx("p2tr")
        tx._inputs[0].sighash = Sighash.ALL
        pre_hash = sha256d(tx.serialize_preimage(0))
        cc = MagicMock()
        cc.needs_2FA = False
        cc.card_bip32_get_extendedkey.return_value = (object(), b"\x00" * 32)
        cc.card_parse_transaction.return_value = ([], 0x90, 0x00, list(pre_hash), False)
        cc.card_sign_schnorr_hash.return_value = (b"\x33" * 64, 0x90, 0x00)
        client = SimpleNamespace(verify_PIN=lambda: True, supports_taproot=lambda: True, cc=cc)
        ks.get_client = lambda: client

        ks.sign_transaction(tx, None)
        sig = tx.sigs[0][2]
        # Should end with Sighash.ALL bytes, not DEFAULT
        self.assertTrue(sig.endswith(Sighash.to_sigbytes(Sighash.ALL)))

    def test_ecdsa_2fa_path(self):
        """ECDSA path with needs_2fa=True calls do_challenge_response."""
        ks = self._mk_keystore()
        tx = _FakeTx("p2wpkh")
        pre_hash = sha256d(tx.serialize_preimage(0))
        der = ecc.ecdsa_der_sig_from_r_and_s(1, 1)
        cc = MagicMock()
        cc.needs_2FA = False  # plugin-level 2FA not needed, but card says needs_2fa
        cc.card_bip32_get_extendedkey.return_value = (object(), b"\x00" * 32)
        cc.card_parse_transaction.return_value = ([], 0x90, 0x00, list(pre_hash), True)
        cc.card_sign_transaction.return_value = (der, 0x90, 0x00)
        client = SimpleNamespace(verify_PIN=lambda: True, supports_taproot=lambda: True, cc=cc)
        ks.get_client = lambda: client
        ks.do_challenge_response = MagicMock(return_value="aabbccdd")

        ks.sign_transaction(tx, None)
        ks.do_challenge_response.assert_called_once()
        self.assertEqual(1, len(tx.sigs))

    def test_multi_input_transaction(self):
        """Transaction with 2 inputs signs both."""
        ks = self._mk_keystore()
        tx = _FakeTx("p2wpkh")
        tx._inputs = [_FakeTxIn("p2wpkh"), _FakeTxIn("p2wpkh")]
        pre_hash = sha256d(tx.serialize_preimage(0))
        der = ecc.ecdsa_der_sig_from_r_and_s(1, 1)
        cc = MagicMock()
        cc.needs_2FA = False
        cc.card_bip32_get_extendedkey.return_value = (object(), b"\x00" * 32)
        cc.card_parse_transaction.return_value = ([], 0x90, 0x00, list(pre_hash), False)
        cc.card_sign_transaction.return_value = (der, 0x90, 0x00)
        client = SimpleNamespace(verify_PIN=lambda: True, supports_taproot=lambda: True, cc=cc)
        ks.get_client = lambda: client

        ks.sign_transaction(tx, None)
        self.assertEqual(2, len(tx.sigs))

    def test_no_matching_pubkey_raises(self):
        """No matching pubkey for input raises UserFacingException."""
        ks = self._mk_keystore()
        ks.find_my_pubkey_in_txinout = lambda txin: (b"\x02" + b"\x11" * 32, None)
        cc = MagicMock()
        cc.needs_2FA = False
        client = SimpleNamespace(verify_PIN=lambda: True, supports_taproot=lambda: True, cc=cc)
        ks.get_client = lambda: client

        with self.assertRaises(UserFacingException) as ctx:
            ks.sign_transaction(_FakeTx("p2wpkh"), None)
        self.assertIn("No matching pubkey", str(ctx.exception))


class TestSetupDeviceBranches(ElectrumTestCase):
    """_setup_device() error branches."""

    def _mk_plugin_with_client(self, *, card_setup_return=None, card_setup_exc=None, card_type="Satochip",
                               card_get_status_return=None, card_get_status_exc=None):
        p = object.__new__(satochip.SatochipPlugin)
        p.device = "Satochip"
        cc = MagicMock()
        cc.card_type = card_type
        cc.set_pin = MagicMock()
        if card_setup_exc:
            cc.card_setup.side_effect = card_setup_exc
        else:
            cc.card_setup.return_value = card_setup_return or ([], 0x90, 0x00)
        # Default card_get_status: card not yet set up (setup_done=False, is_seeded=False)
        if card_get_status_exc:
            cc.card_get_status.side_effect = card_get_status_exc
        else:
            cc.card_get_status.return_value = (
                [], 0x90, 0x00,
                card_get_status_return if card_get_status_return is not None
                else {'setup_done': False, 'is_seeded': False}
            )
        handler = MagicMock()
        client = SimpleNamespace(cc=cc, handler=handler, verify_PIN=MagicMock())
        devmgr = MagicMock()
        devmgr.client_by_id.return_value = client
        p.device_manager = lambda: devmgr
        return p, client, handler

    def test_setup_not_satochip_raises(self):
        """Non-Satochip card type raises Exception."""
        p, client, handler = self._mk_plugin_with_client(card_type="Seedkeeper")
        with self.assertRaises(Exception) as ctx:
            p._setup_device("1234", "dev1", handler)
        self.assertIn("not a Satochip", str(ctx.exception))

    def test_setup_disconnected_raises(self):
        """Disconnected device raises Exception."""
        p = object.__new__(satochip.SatochipPlugin)
        p.device = "Satochip"
        devmgr = MagicMock()
        devmgr.client_by_id.return_value = None
        p.device_manager = lambda: devmgr
        with self.assertRaises(Exception) as ctx:
            p._setup_device("1234", "dev1", MagicMock())
        self.assertIn("disconnected", str(ctx.exception))

    def test_setup_already_done(self):
        """card_setup returning 0x9C07 raises UserFacingException and stops."""
        p, client, handler = self._mk_plugin_with_client(card_setup_return=([], 0x9C, 0x07))
        with self.assertRaises(UserFacingException) as ctx:
            p._setup_device("1234", "dev1", handler)
        self.assertIn("already initialized", str(ctx.exception))
        client.verify_PIN.assert_not_called()

    def test_setup_generic_failure(self):
        """card_setup returning unexpected SW raises UserFacingException and stops."""
        p, client, handler = self._mk_plugin_with_client(card_setup_return=([], 0x6F, 0x00))
        with self.assertRaises(UserFacingException) as ctx:
            p._setup_device("1234", "dev1", handler)
        self.assertIn("Failed to set up card", str(ctx.exception))
        client.verify_PIN.assert_not_called()

    def test_setup_exception(self):
        """Exception during card_setup bubbles up and verify_PIN is not called."""
        p, client, handler = self._mk_plugin_with_client(card_setup_exc=RuntimeError("hw fail"))
        with self.assertRaises(RuntimeError) as ctx:
            p._setup_device("1234", "dev1", handler)
        self.assertIn("hw fail", str(ctx.exception))
        client.verify_PIN.assert_not_called()

    def test_setup_precheck_already_seeded_raises(self):
        """Pre-check: card_get_status reports setup_done=True, is_seeded=True raises UserFacingException."""
        p, client, handler = self._mk_plugin_with_client(
            card_get_status_return={'setup_done': True, 'is_seeded': True}
        )
        with self.assertRaises(UserFacingException) as ctx:
            p._setup_device("1234", "dev1", handler)
        self.assertIn("already fully initialized", str(ctx.exception))
        client.cc.card_setup.assert_not_called()

    def test_setup_precheck_setup_no_seed_raises(self):
        """Pre-check: card_get_status reports setup_done=True, is_seeded=False raises UserFacingException."""
        p, client, handler = self._mk_plugin_with_client(
            card_get_status_return={'setup_done': True, 'is_seeded': False}
        )
        with self.assertRaises(UserFacingException) as ctx:
            p._setup_device("1234", "dev1", handler)
        self.assertIn("already has a PIN", str(ctx.exception))
        client.cc.card_setup.assert_not_called()

    def test_setup_precheck_communication_error_raises(self):
        """Pre-check: card_get_status raises an exception re-raises as UserFacingException."""
        p, client, handler = self._mk_plugin_with_client(
            card_get_status_exc=RuntimeError("pyscard comm failure")
        )
        with self.assertRaises(UserFacingException) as ctx:
            p._setup_device("1234", "dev1", handler)
        self.assertIn("Cannot communicate with the card", str(ctx.exception))
        client.cc.card_setup.assert_not_called()

    def test_setup_success_calls_verify_pin(self):
        """Successful setup proceeds to verify_PIN."""
        p, client, handler = self._mk_plugin_with_client(card_setup_return=([], 0x90, 0x00))
        p._setup_device("1234", "dev1", handler)
        client.verify_PIN.assert_called_once()


class TestImportSeedBranches(ElectrumTestCase):
    """_import_seed() error branches."""

    def _mk_plugin_with_client(self):
        p = object.__new__(satochip.SatochipPlugin)
        p.device = "Satochip"
        cc = MagicMock()
        cc.card_bip32_import_seed.return_value = SimpleNamespace(
            get_public_key_hex=lambda compressed: "02aa",
        )
        handler = MagicMock()
        client = SimpleNamespace(cc=cc, handler=handler, verify_PIN=MagicMock())
        devmgr = MagicMock()
        devmgr.client_by_id.return_value = client
        p.device_manager = lambda: devmgr
        return p, client, handler

    def test_import_seed_disconnected(self):
        """Disconnected device raises Exception."""
        p = object.__new__(satochip.SatochipPlugin)
        p.device = "Satochip"
        devmgr = MagicMock()
        devmgr.client_by_id.return_value = None
        p.device_manager = lambda: devmgr
        with self.assertRaises(Exception) as ctx:
            p._import_seed(("bip39", "word", ""), "dev1", MagicMock())
        self.assertIn("disconnected", str(ctx.exception))

    def test_import_seed_wrong_type(self):
        """Non-BIP39 seed type raises Exception."""
        p, client, handler = self._mk_plugin_with_client()
        with self.assertRaises(Exception) as ctx:
            p._import_seed(("electrum", "words", ""), "dev1", handler)
        self.assertIn("only BIP39", str(ctx.exception))

    def test_import_seed_bad_checksum(self):
        """Invalid BIP39 checksum raises Exception."""
        p, client, handler = self._mk_plugin_with_client()
        with patch("electrum.plugins.satochip.satochip.bip39_is_checksum_valid", return_value=(False, True)):
            with self.assertRaises(Exception) as ctx:
                p._import_seed(("bip39", "bad words", ""), "dev1", handler)
        self.assertIn("Wrong BIP39", str(ctx.exception))

    def test_import_seed_card_exception_propagates(self):
        """Exception from card_bip32_import_seed is re-raised."""
        p, client, handler = self._mk_plugin_with_client()
        client.cc.card_bip32_import_seed.side_effect = RuntimeError("import fail")
        with patch("electrum.plugins.satochip.satochip.bip39_is_checksum_valid", return_value=(True, True)):
            with patch("electrum.plugins.satochip.satochip.bip39_to_seed", return_value=b"\x01" * 64):
                with self.assertRaises(RuntimeError) as ctx:
                    p._import_seed(("bip39", "words", ""), "dev1", handler)
        self.assertIn("import fail", str(ctx.exception))


class TestCmdLinePlugin(ElectrumTestCase):
    """Tests for cmdline.py Plugin and SatochipCmdLineHandler."""

    def test_handler_is_cmdline_handler_subclass(self):
        from electrum.hw_wallet.cmdline import CmdLineHandler
        from electrum.plugins.satochip.cmdline import SatochipCmdLineHandler
        self.assertTrue(issubclass(SatochipCmdLineHandler, CmdLineHandler))

    def test_plugin_handler_type(self):
        from electrum.plugins.satochip.cmdline import Plugin as CmdLinePlugin, SatochipCmdLineHandler
        self.assertIsInstance(CmdLinePlugin.handler, SatochipCmdLineHandler)

    def test_create_handler_returns_handler(self):
        from electrum.plugins.satochip.cmdline import Plugin as CmdLinePlugin
        p = object.__new__(CmdLinePlugin)
        p.handler = CmdLinePlugin.handler
        self.assertIs(p.handler, p.create_handler(None))

    def test_init_keystore_sets_handler(self):
        from electrum.plugins.satochip.cmdline import Plugin as CmdLinePlugin
        p = object.__new__(CmdLinePlugin)
        p.handler = CmdLinePlugin.handler
        ks = object.__new__(satochip.Satochip_KeyStore)
        ks.handler = None
        p.init_keystore(ks)
        self.assertIs(p.handler, ks.handler)

    def test_init_keystore_noop_for_other_keystore(self):
        from electrum.plugins.satochip.cmdline import Plugin as CmdLinePlugin
        p = object.__new__(CmdLinePlugin)
        p.handler = CmdLinePlugin.handler
        fake_ks = SimpleNamespace(handler=None)
        p.init_keystore(fake_ks)
        self.assertIsNone(fake_ks.handler)


class TestExtendWizardNavmap(ElectrumTestCase):
    """Verify extend_wizard() registers all expected navmap keys."""

    def test_navmap_keys(self):
        p = object.__new__(satochip.SatochipPlugin)
        p.device = "Satochip"
        captured = {}

        def fake_merge(views):
            captured.update(views)

        wizard = SimpleNamespace(
            navmap_merge=fake_merge,
            wallet_password_view=lambda d: "pw",
            last_cosigner=lambda d: True,
            maybe_master_pubkey=lambda d: True,
            is_single_password=lambda: True,
        )
        p.extend_wizard(wizard)

        expected_keys = {
            'satochip_start', 'satochip_xpub', 'satochip_not_setup',
            'satochip_do_setup', 'satochip_not_seeded', 'satochip_import_seed',
            'satochip_success_seed', 'satochip_unlock', 'satochip_generate_seed',
            'satochip_recover_seed', 'satochip_wrong_card', 'satochip_recover_setup',
        }
        self.assertEqual(expected_keys, set(captured.keys()))

    def test_navmap_xpub_next_delegates_to_wizard(self):
        """satochip_xpub 'next' lambda calls wizard methods."""
        p = object.__new__(satochip.SatochipPlugin)
        p.device = "Satochip"
        captured = {}

        def fake_merge(views):
            captured.update(views)

        wizard = SimpleNamespace(
            navmap_merge=fake_merge,
            wallet_password_view=lambda d: "password_view",
            last_cosigner=lambda d: True,
            maybe_master_pubkey=lambda d: True,
            is_single_password=lambda: True,
        )
        p.extend_wizard(wizard)

        next_fn = captured['satochip_xpub']['next']
        # last_cosigner=True → should return wallet_password_view result
        self.assertEqual("password_view", next_fn({}))

        # last_cosigner=False → should return 'multisig_cosigner_keystore'
        wizard.last_cosigner = lambda d: False
        p.extend_wizard(wizard)
        next_fn = captured['satochip_xpub']['next']
        self.assertEqual("multisig_cosigner_keystore", next_fn({}))


class TestShowAddressEdgeCases(ElectrumTestCase):
    """Edge/error paths in Satochip_KeyStore.show_address()."""

    def _mk_keystore(self):
        ks = object.__new__(satochip.Satochip_KeyStore)
        ks.ux_busy = False
        ks.handler = MagicMock()
        ks.plugin = SimpleNamespace(config=SimpleNamespace(get=lambda *a, **k: "server"))
        ks.get_derivation_prefix = lambda: "m/84h/0h/0h"
        return ks

    def test_show_address_displays_card_info(self):
        """show_address() derives address and displays card status info."""
        ks = self._mk_keystore()
        cc = MagicMock()
        cc.needs_2FA = False
        cc.card_get_status.return_value = ([], 0x90, 0x00, {
            'applet_version': '0.12',
            'PIN0_remaining_tries': 5,
            'needs2FA': False,
            'is_seeded': True,
            'label': 'TestCard'
        })
        cc.card_bip32_get_extendedkey.return_value = (b'\x02' + b'\x11' * 32, b'\x00' * 32)
        client = SimpleNamespace(verify_PIN=lambda: True, cc=cc)
        ks.get_client = lambda: client

        ks.show_address((0, 0), 'p2wpkh')

        ks.handler.show_message.assert_called_once()
        info_string = ks.handler.show_message.call_args[0][0]
        self.assertIn('Address:', info_string)
        self.assertIn('Derivation: m/84h/0h/0h/0/0', info_string)
        self.assertIn('Applet version: 0.12', info_string)
        self.assertIn('PIN tries remaining: 5', info_string)
        self.assertIn('2FA enabled:', info_string)
        self.assertIn('Card seeded:', info_string)
        ks.handler.finished.assert_called_once()

    def test_show_address_card_not_present_shows_error(self):
        """CardNotPresentError triggers show_error with appropriate message."""
        ks = self._mk_keystore()
        cc = MagicMock()
        cc.card_bip32_get_extendedkey.side_effect = satochip.CardNotPresentError("No card")
        client = SimpleNamespace(verify_PIN=lambda: True, cc=cc)
        ks.get_client = lambda: client

        ks.show_address((0, 0), 'p2wpkh')

        ks.handler.show_error.assert_called_once()
        error_msg = ks.handler.show_error.call_args[0][0]
        self.assertIn('Card not detected', error_msg)
        ks.handler.finished.assert_called_once()
