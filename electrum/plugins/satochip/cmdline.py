from electrum.plugin import hook
from electrum.i18n import _
from electrum.util import print_stderr
from electrum.hw_wallet import CmdLineHandler

from .satochip import SatochipPlugin


class SatochipCmdLineHandler(CmdLineHandler):
    def __init__(self):
        self.passphrase_on_device = False
        super().__init__()

    def get_passphrase(self, msg, confirm):
        import getpass

        print_stderr(msg)
        if self.passphrase_on_device and self.yes_no_question(
            _("Enter passphrase on device?")
        ):
            return None
        else:
            return getpass.getpass("")

    def get_pin(self, msg, confirm=False):
        return raw_input(msg).strip()

    def prompt_auth(self, msg):
        return False


class Plugin(SatochipPlugin):
    handler = SatochipCmdLineHandler()

    @hook
    def init_keystore(self, keystore):
        if not isinstance(keystore, self.keystore_class):
            return
        keystore.handler = self.handler

    def create_handler(self, window):
        return self.handler


# EOF
