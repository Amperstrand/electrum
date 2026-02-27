# Satochip command line handler
#
# Enables Satochip to work when running Electrum from the command line (no GUI).
# Follows the same pattern as other hardware wallet plugins (coldcard, trezor, etc).
#
# References:
# - electrum/plugins/coldcard/cmdline.py
# - electrum/plugins/trezor/cmdline.py

from electrum.plugin import hook
from electrum.util import print_msg, raw_input, print_stderr
from electrum.logging import get_logger

from electrum.hw_wallet.cmdline import CmdLineHandler

from .satochip import SatochipPlugin
from .logging_utils import instrument_module_function_entries


_logger = get_logger(__name__)


class SatochipCmdLineHandler(CmdLineHandler):
    """CLI handler for Satochip - no Qt dialogs, just text prompts.
    
    This handler is used when Electrum is run without the GUI,
    enabling command-line wallet operations with Satochip hardware.
    
    Uses base CmdLineHandler implementations for passphrase/PIN prompts.
    """
    pass



class Plugin(SatochipPlugin):
    """Satochip plugin for command-line mode.
    
    Overrides the Qt handler with CLI handler when running in CLI mode.
    """
    
    handler = SatochipCmdLineHandler()

    @hook
    def init_keystore(self, keystore):
        """Inject CLI handler into keystore when running in CLI mode."""
        if not isinstance(keystore, self.keystore_class):
            return
        keystore.handler = self.handler

    def create_handler(self, window):
        """Return CLI handler (no window available in CLI mode)."""
        return self.handler


instrument_module_function_entries(_logger, globals(), __name__)


# EOF
