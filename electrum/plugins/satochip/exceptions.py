"""Satochip card error classes."""


#################################
#         CARD  ERRORS          #
#################################


class ApduError(Exception):
    def __init__(self, message, sw1=0x00, sw2=0x00, ins=0x00, response=None):
        super().__init__(message)
        self.sw1 = sw1
        self.sw2 = sw2
        self.ins = ins
        self.response = response or []


class CardSelectError(ApduError):
    def __init__(self, message, ins=0x00, response=None):
        super().__init__(message, 0x6A, 0x82, ins, response or [])


class CardSetupNotDoneError(ApduError):
    def __init__(self, message, ins=0x00, response=None):
        super().__init__(message, 0x9C, 0x04, ins, response or [])


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


class CardNotPresentError(Exception):
    """Raised when the device is not present"""

    pass


class CardError(Exception):
    """Raised when the device returns an error code"""

    pass


class WrongCardError(Exception):
    """Raised when the connected card does not match the wallet"""

    pass
