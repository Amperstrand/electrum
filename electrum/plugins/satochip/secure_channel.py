"""Secure channel for Satochip card communication.

Implements ECDH key exchange on secp256k1 with AES-CBC encryption,
using Electrum-native crypto primitives.
"""

import hmac
from hashlib import sha1
from electrum.logging import get_logger
from os import urandom

from electrum_ecc import ECPrivkey, ECPubkey
from electrum.crypto import aes_encrypt_with_iv, aes_decrypt_with_iv


logger = get_logger(__name__)


class SecureChannel:
    def __init__(self):
        logger.debug("In __init__")
        self.initialized_secure_channel = False
        self.sc_privkey = None
        self.sc_pubkey = None
        self.sc_peer_pubkey = None
        self.sc_IV = None
        self.sc_IVcounter = None
        self.shared_key = None
        self.derived_key = None
        self.mac_key = None

        self.sc_privkey = ECPrivkey.generate_random_key()
        self.sc_pubkey = ECPubkey(
            self.sc_privkey.get_public_key_bytes(compressed=False)
        )
        self.sc_pubkey_serialized = self.sc_privkey.get_public_key_bytes(
            compressed=False
        )

    def initiate_secure_channel(self, peer_pubkey_bytes):
        logger.debug("In initiate_secure_channel()")

        self.sc_IVcounter = 1

        self.sc_peer_pubkey = ECPubkey(peer_pubkey_bytes)
        shared_point = self.sc_peer_pubkey * self.sc_privkey.secret_scalar
        self.shared_key = shared_point.x().to_bytes(32, byteorder="big")

        mac = hmac.new(self.shared_key, b"sc_key", sha1)
        self.derived_key = mac.digest()[:16]
        mac = hmac.new(self.shared_key, b"sc_mac", sha1)
        self.mac_key = mac.digest()

        self.initialized_secure_channel = True

    def encrypt_secure_channel(self, data_bytes):
        logger.debug("In encrypt_secure_channel()")
        if not self.initialized_secure_channel:
            raise UninitializedSecureChannelError(
                "Secure channel is not initialized"
            )

        key = self.derived_key
        iv = urandom(12) + (self.sc_IVcounter).to_bytes(4, byteorder="big")

        ciphertext = aes_encrypt_with_iv(key, iv, data_bytes)

        self.sc_IVcounter += 2

        data_to_mac = (
            iv
            + len(ciphertext).to_bytes(2, byteorder="big")
            + ciphertext
        )
        mac = hmac.new(self.mac_key, data_to_mac, sha1).digest()

        return (iv, ciphertext, mac)

    def decrypt_secure_channel(self, iv, ciphertext):
        logger.debug("In decrypt_secure_channel()")
        if not self.initialized_secure_channel:
            raise UninitializedSecureChannelError(
                "Secure channel is not initialized"
            )

        key = self.derived_key
        decrypted = aes_decrypt_with_iv(key, iv, bytes(ciphertext))

        return list(decrypted)


class UninitializedSecureChannelError(Exception):
    """Raised when the secure channel is not initialized"""

    pass
