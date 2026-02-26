from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from . import ElectrumTestCase
from electrum.plugins.satochip import qt as satochip_qt
from electrum.plugins.satochip import satochip


class TestSatochipQtSettings(ElectrumTestCase):
    def _mk_dialog(self):
        d = satochip_qt.SatochipSettingsDialog.__new__(satochip_qt.SatochipSettingsDialog)
        d.window = MagicMock()
        d.config = SimpleNamespace(get=lambda key, default=None: "server1")
        return d

    def test_change_card_label_paths(self):
        d = self._mk_dialog()
        client = SimpleNamespace(verify_PIN=lambda: False, cc=SimpleNamespace(card_set_label=MagicMock()))
        d.change_card_label(client)
        client.cc.card_set_label.assert_not_called()

        d2 = self._mk_dialog()
        client2 = SimpleNamespace(verify_PIN=lambda: True, cc=SimpleNamespace(card_set_label=MagicMock(return_value=([], 0x90, 0x00))))
        d2.change_card_label_dialog = lambda _c, _m: None
        d2.change_card_label(client2)
        d2.window.show_message.assert_called()

        d3 = self._mk_dialog()
        client3 = SimpleNamespace(verify_PIN=lambda: True, cc=SimpleNamespace(card_set_label=MagicMock(return_value=([], 0x90, 0x00))))
        d3.change_card_label_dialog = lambda _c, _m: "mylabel"
        d3.change_card_label(client3)
        d3.window.show_message.assert_called_with("Card label changed successfully!")

        d4 = self._mk_dialog()
        client4 = SimpleNamespace(verify_PIN=lambda: True, cc=SimpleNamespace(card_set_label=MagicMock(return_value=([], 0x6D, 0x00))))
        d4.change_card_label_dialog = lambda _c, _m: "mylabel"
        d4.change_card_label(client4)
        d4.window.show_error.assert_called_with("Error: card does not support label!")

    def test_set_2fa_paths(self):
        d = self._mk_dialog()
        client = SimpleNamespace(
            verify_PIN=lambda: True,
            handler=SimpleNamespace(yes_no_question=lambda _m: True),
            cc=SimpleNamespace(needs_2FA=True, card_set_2FA_key=MagicMock()),
        )
        d.set_2FA(client)
        client.cc.card_set_2FA_key.assert_not_called()

        d2 = self._mk_dialog()
        client2 = SimpleNamespace(
            verify_PIN=lambda: False,
            handler=SimpleNamespace(yes_no_question=lambda _m: True),
            cc=SimpleNamespace(needs_2FA=False, card_set_2FA_key=MagicMock()),
        )
        d2.set_2FA(client2)
        d2.window.show_error.assert_called_with("action cancelled by user")

        d3 = self._mk_dialog()
        client3 = SimpleNamespace(
            verify_PIN=lambda: True,
            handler=SimpleNamespace(yes_no_question=lambda _m: True),
            cc=SimpleNamespace(needs_2FA=False, card_set_2FA_key=MagicMock(return_value=([], 0x90, 0x00))),
        )
        with patch("electrum.plugins.satochip.qt.urandom", return_value=b"\x01" * 20):
            with patch("electrum.plugins.satochip.qt.QRDialog") as QRDialog:
                QRDialog.return_value.exec.return_value = 1
                d3.set_2FA(client3)
        client3.cc.card_set_2FA_key.assert_called_once()
        d3.window.show_message.assert_called_with("2FA enabled successfully!")

        d4 = self._mk_dialog()
        client4 = SimpleNamespace(
            verify_PIN=lambda: True,
            handler=SimpleNamespace(yes_no_question=lambda _m: True),
            cc=SimpleNamespace(needs_2FA=False, card_set_2FA_key=MagicMock(return_value=([], 0x9C, 0x0B))),
        )
        with patch("electrum.plugins.satochip.qt.urandom", return_value=b"\x01" * 20):
            with patch("electrum.plugins.satochip.qt.QRDialog") as QRDialog:
                QRDialog.return_value.exec.return_value = 1
                d4.set_2FA(client4)
        d4.window.show_error.assert_called()

    def test_reset_2fa_paths(self):
        d = self._mk_dialog()
        client = SimpleNamespace(verify_PIN=lambda: True, cc=SimpleNamespace(needs_2FA=False))
        d.reset_2FA(client)
        d.window.show_error.assert_called_with("2FA is already disabled!")

        d2 = self._mk_dialog()
        client2 = SimpleNamespace(verify_PIN=lambda: False, cc=SimpleNamespace(needs_2FA=True))
        d2.reset_2FA(client2)
        d2.window.show_error.assert_called_with("action cancelled by user")

        d3 = self._mk_dialog()
        cc3 = SimpleNamespace(
            needs_2FA=True,
            card_crypt_transaction_2FA=MagicMock(side_effect=[("id", "enc"), "challenge:abcd"]),
            card_reset_2FA_key=MagicMock(return_value=([], 0x90, 0x00)),
        )
        client3 = SimpleNamespace(verify_PIN=lambda: True, cc=cc3)

        def _respond(payload, server_name=None):
            payload["reply_encrypt"] = "reply"

        with patch("electrum.plugins.satochip.qt.Satochip2FA.do_challenge_response", side_effect=_respond):
            d3.reset_2FA(client3)
        d3.window.show_message.assert_called_with("2FA reset successfully!")
        self.assertFalse(client3.cc.needs_2FA)

        d4 = self._mk_dialog()
        cc4 = SimpleNamespace(
            needs_2FA=True,
            card_crypt_transaction_2FA=MagicMock(side_effect=[("id", "enc"), "challenge:abcd"]),
            card_reset_2FA_key=MagicMock(return_value=([], 0x9C, 0x17)),
        )
        client4 = SimpleNamespace(verify_PIN=lambda: True, cc=cc4)
        with patch("electrum.plugins.satochip.qt.Satochip2FA.do_challenge_response", side_effect=_respond):
            d4.reset_2FA(client4)
        d4.window.show_error.assert_called()

    def test_reset_seed_paths(self):
        d = self._mk_dialog()
        d.reset_seed_dialog = lambda msg: None
        client = SimpleNamespace(cc=SimpleNamespace(needs_2FA=False, card_reset_seed=MagicMock()))
        d.reset_seed(client)
        client.cc.card_reset_seed.assert_not_called()

        d2 = self._mk_dialog()
        d2.reset_seed_dialog = lambda msg: "1234"
        cc2 = SimpleNamespace(needs_2FA=False, card_reset_seed=MagicMock(return_value=([], 0x90, 0x00)))
        client2 = SimpleNamespace(cc=cc2)
        d2.reset_seed(client2)
        cc2.card_reset_seed.assert_called_once_with([49, 50, 51, 52], [])
        d2.window.show_message.assert_called()

        d3 = self._mk_dialog()
        d3.reset_seed_dialog = lambda msg: "1234"
        cc3 = SimpleNamespace(
            needs_2FA=True,
            parser=SimpleNamespace(authentikey_coordx=b"\x02" + b"\x11" * 32),
            card_crypt_transaction_2FA=MagicMock(side_effect=[("id", "enc"), "challenge:abcd"]),
            card_reset_seed=MagicMock(return_value=([], 0x90, 0x00)),
        )
        client3 = SimpleNamespace(cc=cc3)

        def _respond(payload, server_name=None):
            payload["reply_encrypt"] = "reply"

        with patch("electrum.plugins.satochip.qt.Satochip2FA.do_challenge_response", side_effect=_respond):
            d3.reset_seed(client3)
        cc3.card_reset_seed.assert_called_once()
        args, _kwargs = cc3.card_reset_seed.call_args
        self.assertEqual([49, 50, 51, 52], args[0])
        self.assertEqual(list(bytes.fromhex("abcd")), args[1])

    # Coverage note: card_verify_authenticity() uses card_export_perso_certificate()
    # then card_challenge_response_pki() to verify genuine-device PKI flow.
    def test_card_verify_authenticity_success_path(self):
        d = self._mk_dialog()
        cc = SimpleNamespace(
            card_export_perso_certificate=MagicMock(return_value="-----BEGIN CERTIFICATE-----..."),
            card_type="Satochip",
            card_challenge_response_pki=MagicMock(return_value=(True, "")),
        )
        client = SimpleNamespace(cc=cc)

        fake_validator = MagicMock()
        fake_validator.validate_certificate_chain.return_value = (
            True,
            b"device-pubkey",
            "ca",
            "subca",
            "device",
            "",
        )
        with patch("pysatochip.certificate_validator.CertificateValidator", return_value=fake_validator):
            is_ok, txt_ca, txt_subca, txt_device, txt_error = d.card_verify_authenticity(client)

        self.assertTrue(is_ok)
        self.assertEqual("", txt_error)
        self.assertEqual("ca", txt_ca)
        self.assertEqual("subca", txt_subca)
        self.assertEqual("device", txt_device)
        cc.card_challenge_response_pki.assert_called_once_with(b"device-pubkey")

    # Coverage note: Unsupported cert export (CardError) must map to user-facing text.
    def test_card_verify_authenticity_carderror(self):
        d = self._mk_dialog()
        cc = SimpleNamespace(card_export_perso_certificate=MagicMock(side_effect=satochip_qt.CardError("unsupported")))
        client = SimpleNamespace(cc=cc)
        is_ok, _ca, _subca, _dev, txt_error = d.card_verify_authenticity(client)
        self.assertFalse(is_ok)
        self.assertIn("feature unsupported", txt_error)

    # Coverage note: Card-not-present should map to a deterministic error message.
    def test_card_verify_authenticity_no_card(self):
        d = self._mk_dialog()
        cc = SimpleNamespace(card_export_perso_certificate=MagicMock(side_effect=satochip.CardNotPresentError("no card")))
        client = SimpleNamespace(cc=cc)
        is_ok, _ca, _subca, _dev, txt_error = d.card_verify_authenticity(client)
        self.assertFalse(is_ok)
        self.assertEqual("No card found! Please insert card.", txt_error)

    # Coverage note: UnexpectedSW12Error during cert export is explicitly handled.
    def test_card_verify_authenticity_unexpected_sw12_error(self):
        d = self._mk_dialog()
        cc = SimpleNamespace(card_export_perso_certificate=MagicMock(side_effect=satochip_qt.UnexpectedSW12Error("0x6f00")))
        client = SimpleNamespace(cc=cc)
        is_ok, _ca, _subca, _dev, txt_error = d.card_verify_authenticity(client)
        self.assertFalse(is_ok)
        self.assertIn("Exception during device certificate export", txt_error)

    # Coverage note: Empty cert must fail before certificate-chain validation.
    def test_card_verify_authenticity_empty_certificate(self):
        d = self._mk_dialog()
        cc = SimpleNamespace(card_export_perso_certificate=MagicMock(return_value="(empty)"))
        client = SimpleNamespace(cc=cc)
        is_ok, _ca, _subca, _dev, txt_error = d.card_verify_authenticity(client)
        self.assertFalse(is_ok)
        self.assertIn("Device certificate is empty", txt_error)
