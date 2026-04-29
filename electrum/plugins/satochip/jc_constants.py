"""Satochip JavaCard applet protocol constants.

Only the constants actually referenced by the plugin are retained.
The full source (including SeedKeeper/Satodime/Satocash constants and
secp256k1 curve parameters) is in the upstream Satochip-Applet repo.
"""


class JCconstants:
    CardEdge_CLA = 0xB0

    INS_GET_STATUS = 0x3C
    INS_CARD_LABEL = 0x3D
    INS_NFC_POLICY = 0x3E
    INS_NDEF = 0x3F
    INS_FEATURE_POLICY = 0x3A
    INS_SETUP = 0x2A
    INS_CREATE_PIN = 0x40
    INS_VERIFY_PIN = 0x42
    INS_CHANGE_PIN = 0x44
    INS_UNBLOCK_PIN = 0x46
    INS_SET_2FA_KEY = 0x79
    INS_BIP32_IMPORT_SEED = 0x6C
    INS_BIP32_RESET_SEED = 0x77
    INS_BIP32_GET_AUTHENTIKEY = 0x73
    INS_BIP32_SET_AUTHENTIKEY_PUBKEY = 0x75
    INS_BIP32_GET_EXTENDED_KEY = 0x6D
    INS_SIGN_MESSAGE = 0x6E
    INS_SIGN_TRANSACTION = 0x6F
    INS_PARSE_TRANSACTION = 0x71
    INS_SIGN_SCHNORR_HASH = 0x7B
    INS_TAPROOT_TWEAK_PRIVKEY = 0x7C
    INS_EXPORT_AUTHENTIKEY = 0xAD
    INS_INIT_SECURE_CHANNEL = 0x81
    INS_PROCESS_SECURE_CHANNEL = 0x82
    INS_RESET_TO_FACTORY = 0xFF

    OP_INIT = 0x01
    OP_PROCESS = 0x02
    OP_FINALIZE = 0x03
