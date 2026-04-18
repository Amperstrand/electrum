"""Secure channel for Satochip card communication.

Implements ECDH key exchange on secp256k1 with AES-CBC encryption,
using Electrum-native crypto primitives (electrum_ecc + cryptography).
"""

import hmac
import logging
from hashlib import sha1
from os import urandom

from electrum_ecc import ECPrivkey, ECPubkey

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as crypto_padding


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class SecureChannel:
    def __init__(self, loglevel=logging.WARNING):
        logger.setLevel(loglevel)
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

        # Generate ephemeral ECDH keypair
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

        # ECDH: shared secret is the x-coordinate of (peer_pubkey * local_privkey)
        self.sc_peer_pubkey = ECPubkey(peer_pubkey_bytes)
        shared_point = self.sc_peer_pubkey * self.sc_privkey.secret_scalar
        self.shared_key = shared_point.x().to_bytes(32, byteorder="big")

        # Key derivation with HMAC-SHA1
        mac = hmac.new(self.shared_key, b"sc_key", sha1)
        self.derived_key = mac.digest()[:16]
        mac = hmac.new(self.shared_key, b"sc_mac", sha1)
        self.mac_key = mac.digest()

        self.initialized_secure_channel = True

    def encrypt_secure_channel(self, data_bytes):
        logger.debug("In encrypt_secure_channel()")
        if not self.initialized_secure_channel:
            raise UninitializedSecureChannelError("Secure channel is not initialized")

        key = self.derived_key
        iv = urandom(12) + (self.sc_IVcounter).to_bytes(4, byteorder="big")

        # AES-CBC encryption with PKCS7 padding
        padder = crypto_padding.PKCS7(128).padder()
        padded_data = padder.update(data_bytes) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        self.sc_IVcounter += 2

        # MAC over (IV || ciphertext_length || ciphertext)
        data_to_mac = iv + len(ciphertext).to_bytes(2, byteorder="big") + ciphertext
        mac = hmac.new(self.mac_key, data_to_mac, sha1).digest()

        return (iv, ciphertext, mac)

    def decrypt_secure_channel(self, iv, ciphertext):
        logger.debug("In decrypt_secure_channel()")
        if not self.initialized_secure_channel:
            raise UninitializedSecureChannelError("Secure channel is not initialized")

        key = self.derived_key

        # AES-CBC decryption with PKCS7 unpadding
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = crypto_padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(padded_data) + unpadder.finalize()

        return list(decrypted)


class UninitializedSecureChannelError(Exception):
    """Raised when the secure channel is not initialized"""

    pass
