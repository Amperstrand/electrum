"""Electrum upstream test harness for Satochip visual lifecycle testing.

Provides a real Electrum stack (config, plugins, daemon, wizard) and helpers
for driving real QENewWalletWizard instances with full chrome for pixel-perfect
screenshots.
"""

import os
import tempfile
from typing import Optional
from unittest.mock import MagicMock

from electrum.logging import get_logger

_logger = get_logger(__name__)


def create_config(tmpdir: Optional[str] = None):
    from electrum.simple_config import SimpleConfig
    tmpdir = tmpdir or tempfile.mkdtemp(prefix="satochip-visual-")
    config = SimpleConfig({"electrum_path": tmpdir})
    config.NETWORK_OFFLINE = True
    return config


class RealElectrumContext:
    def __init__(self, config):
        from electrum.plugin import Plugins
        from electrum.util import create_and_start_event_loop
        from electrum.daemon import Daemon

        self.config = config
        self.loop, self.loop_stopping_fut, self.loop_thread = (
            create_and_start_event_loop()
        )
        self.plugins = Plugins(config, gui_name="qt")
        self.plugins.load_plugin("satochip")
        self.daemon = Daemon(
            config,
            fd=None,
            listen_jsonrpc=False,
            start_network=False,
        )
        self.daemon._plugins = self.plugins

    def cleanup(self):
        try:
            self.daemon.stop()
        except Exception:
            pass
        try:
            self.loop.call_soon_threadsafe(
                self.loop_stopping_fut.set_result, None)
            self.loop_thread.join(timeout=5)
        except Exception:
            pass


class WizardDriver:
    def __init__(self, ctx, qapp, qtbot):
        self.ctx = ctx
        self.qapp = qapp
        self.qtbot = qtbot
        self._wizard = None

    def push_view(self, view_name: str, wizard_data: dict):
        from electrum.gui.qt.wizard.wallet import QENewWalletWizard
        import time

        wallet_path = os.path.join(
            tempfile.mkdtemp(prefix="satochip-wiz-"), "test_wallet"
        )
        wizard = QENewWalletWizard(
            config=self.ctx.config,
            app=self.qapp,
            plugins=self.ctx.plugins,
            daemon=self.ctx.daemon,
            path=wallet_path,
        )

        deadline = time.time() + 2.0
        while time.time() < deadline:
            self.qapp.processEvents()
            time.sleep(0.02)

        try:
            wizard.load_next_component(view_name, dict(wizard_data), {})
        except Exception:
            pass

        deadline = time.time() + 1.0
        while time.time() < deadline:
            self.qapp.processEvents()
            time.sleep(0.02)

        wizard.raise_()
        wizard.activateWindow()
        self.qapp.processEvents()
        time.sleep(0.1)

        if self._wizard is not None:
            try:
                self._wizard.close()
                self._wizard.deleteLater()
                self.qapp.processEvents()
            except Exception:
                pass
        self._wizard = wizard
        return wizard

    def teardown(self):
        if self._wizard is not None:
            try:
                self._wizard.close()
                self._wizard.deleteLater()
                self.qapp.processEvents()
            except Exception:
                pass
            self._wizard = None


def make_mock_device_info(
        reader_name="OMNIKEY AG Smart Card Reader USB"):
    device = MagicMock()
    device.path = reader_name
    device.interface_number = 0
    device.product_key = ("satochip",)
    info = MagicMock()
    info.device = device
    info.label = "Satochip"
    info.initialized = True
    info.plugin_name = "satochip"
    info.model_name = "Satochip"
    info.soft_device_id = "test-device-id"
    return info
