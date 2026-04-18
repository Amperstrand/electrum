"""
* Python API for the SatoChip Bitcoin Hardware Wallet
* (c) 2015 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
* Sources available on https://github.com/Toporin
*
* Copyright 2015 by Toporin (https://github.com/Toporin)
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.

Inlined from pysatochip/CardDataParser.py with Electrum-native dependencies.
"""

import base64
from hashlib import sha256
from struct import pack

from electrum_ecc import (
    ECPrivkey,
    ECPubkey,
    InvalidECPointException,
    CURVE_ORDER,
    ecdsa_sig64_from_der_sig,
    ecdsa_sig64_from_r_and_s,
    get_r_and_s_from_ecdsa_sig64,
)

from .jc_constants import (
    SIZE_ECCOORDX,
    SIZE_ENTROPY,
)

from electrum.logging import get_logger

logger = get_logger(__name__)

MSG_WARNING = (
    "Before you request bitcoins to be sent to addresses in this "
    "wallet, ensure you can pair with your device, or that you have "
    "its seed (and passphrase, if any).  Otherwise all bitcoins you "
    "receive will be unspendable."
)


class CardDataParser:
    def __init__(self):
        logger.debug("In __init__")
        self.authentikey = None
        self.authentikey_coordx = None
        self.authentikey_from_storage = None

    def bip32path2bytes(self, bip32path: str):
        splitPath = bip32path.split("/")
        splitPath = [x for x in splitPath if x]
        if splitPath and splitPath[0] == "m":
            splitPath = splitPath[1:]

        bytePath = b""
        depth = len(splitPath)
        for index in splitPath:
            if index.endswith("'"):
                bytePath += pack(">I", int(index.rstrip("'")) + 0x80000000)
            else:
                bytePath += pack(">I", int(index))

        return depth, bytePath

    def parse_bip32_get_authentikey(self, response):
        # response= [data_size | data | sig_size | signature]
        # where data is coordx
        logger.debug("In parse_bip32_get_authentikey")
        data_size = ((response[0] & 0xFF) << 8) + (response[1] & 0xFF)
        data = response[2 : (2 + data_size)]
        msg_size = 2 + data_size
        msg = response[0:msg_size]
        sig_size = ((response[msg_size] & 0xFF) << 8) + (response[msg_size + 1] & 0xFF)
        signature = response[(msg_size + 2) : (msg_size + 2 + sig_size)]

        if sig_size == 0:
            raise ValueError("Signature missing")
        # self-signed
        coordx = data
        self.authentikey = self.get_pubkey_from_signature(coordx, msg, signature)
        self.authentikey_coordx = coordx

        # if already initialized, check that authentikey match value retrieved from storage!
        if self.authentikey_from_storage is not None:
            if self.authentikey != self.authentikey_from_storage:
                raise ValueError(
                    "The seed used to create this wallet file no longer matches the seed of the Satochip device!\n\n"
                    + MSG_WARNING
                )

        return self.authentikey

    def parse_bip32_import_seed(self, response):
        # response= [data_size | data | sig_size | signature]
        # where data is coordx
        logger.debug("In parse_bip32_import_seed")
        return self.parse_bip32_get_authentikey(response)

    def parse_bip32_get_extendedkey(self, response):
        logger.debug("In parse_bip32_get_extendedkey")
        if self.authentikey is None:
            raise ValueError("Authentikey not set!")

        # double signature: first is self-signed, second by authentikey
        logger.debug(
            "[CardDataParser] parse_bip32_get_extendedkey: first signature recovery"
        )
        self.chaincode = bytearray(response[0:32])
        data_size = ((response[32] & 0x7F) << 8) + (response[33] & 0xFF)
        data = response[34 : (32 + 2 + data_size)]
        msg_size = 32 + 2 + data_size
        msg = response[0:msg_size]
        sig_size = ((response[msg_size] & 0xFF) << 8) + (response[msg_size + 1] & 0xFF)
        signature = response[(msg_size + 2) : (msg_size + 2 + sig_size)]
        if sig_size == 0:
            raise ValueError("Signature missing")
        # self-signed
        coordx = data
        self.pubkey = self.get_pubkey_from_signature(coordx, msg, signature)
        self.pubkey_coordx = coordx

        # second signature by authentikey
        logger.debug(
            "[CardDataParser] parse_bip32_get_extendedkey: second signature recovery"
        )
        msg2_size = msg_size + 2 + sig_size
        msg2 = response[0:msg2_size]
        sig2_size = ((response[msg2_size] & 0xFF) << 8) + (
            response[msg2_size + 1] & 0xFF
        )
        signature2 = response[(msg2_size + 2) : (msg2_size + 2 + sig2_size)]
        authentikey = self.get_pubkey_from_signature(
            self.authentikey_coordx, msg2, signature2
        )
        if authentikey != self.authentikey:
            raise ValueError(
                "The seed used to create this wallet file no longer matches the seed of the Satochip device!\n\n"
                + MSG_WARNING
            )

        return (self.pubkey, self.chaincode)

    def parse_bip32_get_extended_privkey(self, response):
        logger.debug("In parse_bip32_get_extended_privkey")
        if self.authentikey is None:
            raise ValueError("Authentikey not set!")

        # double signature: first is self-signed, second by authentikey
        logger.debug(
            "[CardDataParser] parse_bip32_get_extended_privkey: first signature recovery"
        )
        self.chaincode = bytearray(response[0:32])
        data_size = ((response[32] & 0x7F) << 8) + (response[33] & 0xFF)
        data = response[34 : (32 + 2 + data_size)]
        msg_size = 32 + 2 + data_size
        msg = response[0:msg_size]
        sig_size = ((response[msg_size] & 0xFF) << 8) + (response[msg_size + 1] & 0xFF)
        signature = response[(msg_size + 2) : (msg_size + 2 + sig_size)]
        if sig_size == 0:
            raise ValueError("Signature missing")
        # self-signed
        privkey_list = data
        self.privkey = ECPrivkey(bytes(privkey_list))

        # second signature by authentikey
        logger.debug(
            "[CardDataParser] parse_bip32_get_extended_privkey: second signature recovery"
        )
        msg2_size = msg_size + 2 + sig_size
        msg2 = response[0:msg2_size]
        sig2_size = ((response[msg2_size] & 0xFF) << 8) + (
            response[msg2_size + 1] & 0xFF
        )
        signature2 = response[(msg2_size + 2) : (msg2_size + 2 + sig2_size)]
        authentikey = self.get_pubkey_from_signature(
            self.authentikey_coordx, msg2, signature2
        )
        if authentikey != self.authentikey:
            raise ValueError(
                "The seed used to create this wallet file no longer matches the seed of the Satochip device!\n\n"
                + MSG_WARNING
            )

        return (self.privkey, self.chaincode)

    def parse_bip32_get_extendedkey_bip85(self, response):
        logger.debug("In parse_bip32_get_extendedkey_bip85")
        if self.authentikey is None:
            raise ValueError("Authentikey not set!")

        logger.debug(
            f"[CardDataParser] parse_bip32_get_extendedkey_bip85: response_hex: {bytes(response).hex()}"
        )

        # double signature: first is self-signed, second by authentikey
        logger.debug(
            "[CardDataParser] parse_bip32_get_extendedkey_bip85: first signature recovery"
        )
        entropy_size = ((response[0] & 0xFF) << 8) + (response[1] & 0xFF)
        entropy_bytes = bytes(response[2 : 2 + entropy_size])
        msg_size = 2 + entropy_size
        msg = response[0:msg_size]
        sig_size = ((response[msg_size] & 0xFF) << 8) + (response[msg_size + 1] & 0xFF)
        signature = response[(msg_size + 2) : (msg_size + 2 + sig_size)]
        if sig_size == 0:
            raise ValueError("Signature missing")

        # second signature by authentikey
        logger.debug(
            "[CardDataParser] parse_bip32_get_extendedkey_bip85: second signature recovery"
        )
        msg2_size = msg_size + 2 + sig_size
        msg2 = response[0:msg2_size]
        sig2_size = ((response[msg2_size] & 0xFF) << 8) + (
            response[msg2_size + 1] & 0xFF
        )
        signature2 = response[(msg2_size + 2) : (msg2_size + 2 + sig2_size)]
        authentikey = self.get_pubkey_from_signature(
            self.authentikey_coordx, msg2, signature2
        )
        if authentikey != self.authentikey:
            raise ValueError(
                "The seed used to create this wallet file no longer matches the seed of the Satochip device!\n\n"
                + MSG_WARNING
            )

        return entropy_bytes

    def parse_get_pubkey_from_keyslot(self, response):
        logger.debug("In parse_get_pubkey_from_keyslot")
        # response: [coordx_size(2b) | pubkey_coordx | sig_size(2b) | sig]
        data_size = ((response[0] & 0xFF) << 8) + (response[1] & 0xFF)
        data = response[2 : (2 + data_size)]
        msg_size = 2 + data_size
        msg = response[0:msg_size]
        sig_size = ((response[msg_size] & 0xFF) << 8) + (response[msg_size + 1] & 0xFF)
        signature = response[(msg_size + 2) : (msg_size + 2 + sig_size)]
        if sig_size == 0:
            raise ValueError("Signature missing")
        # self-signed
        coordx = data
        pubkey = self.get_pubkey_from_signature(coordx, msg, signature)
        return pubkey

    def parse_initiate_secure_channel(self, response):
        logger.debug("In parse_initiate_secure_channel")
        # double signature: first is self-signed, second by authentikey (optional)
        data_size = ((response[0] & 0xFF) << 8) + (response[1] & 0xFF)
        data = response[2 : (2 + data_size)]
        msg_size = 2 + data_size
        msg = response[0:msg_size]
        sig_size = ((response[msg_size] & 0xFF) << 8) + (response[msg_size + 1] & 0xFF)
        signature = response[(msg_size + 2) : (msg_size + 2 + sig_size)]
        if sig_size == 0:
            raise ValueError("Signature missing")
        # self-signed
        coordx = data
        self.pubkey = self.get_pubkey_from_signature(coordx, msg, signature)
        self.pubkey_coordx = coordx

        # second signature by authentikey (optional)
        msg2_size = msg_size + 2 + sig_size
        sig2_size = ((response[msg2_size] & 0xFF) << 8) + (
            response[msg2_size + 1] & 0xFF
        )
        if sig2_size > 0 and self.authentikey_coordx:
            msg2 = response[0:msg2_size]
            signature2 = response[(msg2_size + 2) : (msg2_size + 2 + sig2_size)]
            authentikey = self.get_pubkey_from_signature(
                self.authentikey_coordx, msg2, signature2
            )
            if authentikey.get_public_key_bytes(
                compressed=False
            ) != self.authentikey.get_public_key_bytes(compressed=False):
                raise ValueError(
                    "Recovered authentikey does not correspond to registered authentikey!"
                )
            logger.info(
                "In parse_initiate_secure_channel: successfuly recovered authentikey:"
                + authentikey.get_public_key_bytes(compressed=False).hex()
            )

        logger.info(
            "In parse_initiate_secure_channel: successfuly recovered pubkey:"
            + self.pubkey.get_public_key_bytes(compressed=False).hex()
        )
        return self.pubkey

    ##############
    def parse_message_signature(self, response, hash, pubkey):
        logger.debug("In parse_message_signature")

        coordx = pubkey.get_public_key_bytes()

        response = bytearray(response)
        recid = -1
        for id in range(4):
            compsig = self.parse_to_compact_sig(response, id, compressed=True)
            # remove header byte
            compsig2 = compsig[1:]

            try:
                pk = ECPubkey.from_ecdsa_sig64(compsig2, id, hash)
                pkbytes = pk.get_public_key_bytes(compressed=True)
            except InvalidECPointException:
                continue

            if coordx == pkbytes:
                recid = id
                break

        if recid == -1:
            raise ValueError("Unable to recover public key from signature")

        return compsig

    ##############
    def parse_rsv_from_dersig(self, dersig: bytes, hash: bytes, pubkey):
        """Takes in input the DER signature returned by Satochip and return the r, s, v and sigstring format."""
        logger.debug("In parse_rsv_from_dersig")
        coordx = pubkey.get_public_key_bytes()

        sigstring = ecdsa_sig64_from_der_sig(dersig)
        r, s = get_r_and_s_from_ecdsa_sig64(sigstring)
        # enforce low-S signature (BIP 62)
        if s > CURVE_ORDER // 2:
            logger.debug("In parse_rsv_from_dersig(): S is higher than CURVE_ORDER//2")
            s = CURVE_ORDER - s
            sigstring = ecdsa_sig64_from_r_and_s(r, s)

        # v
        recid = -1
        for id in range(4):
            try:
                pk = ECPubkey.from_ecdsa_sig64(sigstring, id, hash)
                pkbytes = pk.get_public_key_bytes(compressed=True)
                logger.debug("    =>parse_hash_signature - rec_pubkey:" + pkbytes.hex())
            except InvalidECPointException:
                continue

            if coordx == pkbytes:
                recid = id
                logger.debug(
                    "    =>parse_hash_signature - found good pubkey:" + pkbytes.hex()
                )
                break

        if recid == -1:
            raise ValueError("Unable to recover public key from signature")

        v = recid % 2
        sigstring = bytes([v]) + sigstring
        return (r, s, v, sigstring)

    ##############
    def get_pubkey_from_signature(self, coordx, data, sig):
        logger.debug("In get_pubkey_from_signature")
        data = bytearray(data)
        sig = bytearray(sig)
        coordx = bytearray(coordx)

        digest = sha256()
        digest.update(data)
        hash = digest.digest()

        recid = -1
        pubkey = None
        for id in range(4):
            compsig = self.parse_to_compact_sig(sig, id, compressed=True)
            # remove header byte
            compsig = compsig[1:]

            try:
                pk = ECPubkey.from_ecdsa_sig64(compsig, id, hash)
                pkbytes = pk.get_public_key_bytes(compressed=True)
            except InvalidECPointException:
                continue

            pkbytes = pkbytes[1:]

            if coordx == pkbytes:
                recid = id
                pubkey = pk
                break

        if recid == -1:
            raise ValueError("Unable to recover public key from signature")

        logger.debug("Signature verified!")
        return pubkey

    #######
    def verify_signature(self, data, sig, authentikey):
        logger.debug("In verify_signature")
        data = bytearray(data)
        sig = bytearray(sig)

        digest = sha256()
        digest.update(data)
        hash = digest.digest()

        recid = -1
        for id in range(4):
            compsig = self.parse_to_compact_sig(sig, id, compressed=True)
            # remove header byte
            compsig = compsig[1:]

            try:
                pk = ECPubkey.from_ecdsa_sig64(compsig, id, hash)
            except InvalidECPointException:
                continue

            if pk == authentikey:
                recid = id
                break

        if recid == -1:
            raise ValueError("Unable to recover authentikey from signature")

        return pk

    def get_trusted_pubkey(self, response):
        pubkey_size = response[0] * 256 + response[1]
        if pubkey_size != 65:
            raise RuntimeError(
                f"Error while recovering trusted pubkey: wrong pubkey size, expected 65 but received {pubkey_size}"
            )
        data = response[0 : (2 + pubkey_size)]
        sig_size = response[2 + pubkey_size] * 256 + response[2 + pubkey_size + 1]
        sig = response[(2 + pubkey_size + 2) : (2 + pubkey_size + 2 + sig_size)]

        pubkey_hex = bytes(response[2 : 2 + pubkey_size]).hex()
        logger.debug(
            f"Verifying sig for pubkey {pubkey_hex} using authentikey {self.authentikey.get_public_key_bytes(compressed=False).hex()}"
        )

        try:
            self.verify_signature(data, sig, self.authentikey)
        except Exception as ex:
            logger.error("Exception in get_trusted_pubkey: " + str(ex))

        return pubkey_hex

    ##############
    def parse_parse_transaction(self, response):
        """Satochip returns: [(hash_size+2)(2b) | tx_hash(32b) | need2fa(2b) | sig_size(2b) | sig(sig_size) | txcontext]"""
        logger.debug("In parse_to_compact_sig")
        offset = 0
        data_size = ((response[offset] & 0xFF) << 8) + (response[offset + 1] & 0xFF)
        txhash_size = data_size - 2
        offset += 2
        tx_hash = response[offset : (offset + txhash_size)]
        offset += txhash_size
        needs_2fa = ((response[offset] & 0xFF) << 8) + (response[offset + 1] & 0xFF)
        needs_2fa = False if (needs_2fa == 0) else True
        offset += 2
        sig_size = ((response[offset] & 0xFF) << 8) + (response[offset + 1] & 0xFF)
        sig_data = response[0 : data_size + 2]
        offset += 2
        if sig_size > 0 and self.authentikey_coordx:
            sig = response[offset : (offset + sig_size)]
            pubkey = self.get_pubkey_from_signature(
                self.authentikey_coordx, sig_data, sig
            )
            if pubkey != self.authentikey:
                raise Exception("signing key is not authentikey!")

        return (tx_hash, needs_2fa)

    def parse_to_compact_sig(self, sigin, recid, compressed):
        """convert a DER encoded signature to compact 65-byte format
        input is bytearray in DER format
        output is bytearray in compact 65-byte format
        http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
        https://bitcointalk.org/index.php?topic=215205.0
        """
        logger.debug("In parse_to_compact_sig")
        sigout = bytearray(65 * [0])
        # parse input
        first = sigin[0]
        if first != 0x30:
            raise ValueError("Wrong first byte!")
        lt = sigin[1]
        check = sigin[2]
        if check != 0x02:
            raise ValueError("Check byte should be 0x02")
        # extract r
        lr = sigin[3]
        for i in range(32):
            tmp = sigin[4 + lr - 1 - i]
            if lr >= (i + 1):
                sigout[32 - i] = tmp
            else:
                sigout[32 - i] = 0
        # extract s
        check = sigin[4 + lr]
        if check != 0x02:
            raise ValueError("Second check byte should be 0x02")
        ls = sigin[5 + lr]
        if lt != (lr + ls + 4):
            raise ValueError("Wrong lt value")
        for i in range(32):
            tmp = sigin[5 + lr + ls - i]
            if ls >= (i + 1):
                sigout[64 - i] = tmp
            else:
                sigout[64 - i] = 0
        # 1 byte header
        if recid > 3 or recid < 0:
            raise ValueError("Wrong recid value")
        if compressed:
            sigout[0] = 27 + recid + 4
        else:
            sigout[0] = 27 + recid

        return sigout

    #################################
    #                   PERSO PKI                 #
    #################################

    def convert_bytes_to_string_pem(self, cert_bytes):
        cert_bytes_b64 = base64.b64encode(bytes(cert_bytes))
        cert_b64 = cert_bytes_b64.decode("ascii")
        cert_pem = "-----BEGIN CERTIFICATE-----\r\n"
        cert_pem += "\r\n".join(
            [cert_b64[i : i + 64] for i in range(0, len(cert_b64), 64)]
        )
        cert_pem += "\r\n-----END CERTIFICATE-----"
        return cert_pem

