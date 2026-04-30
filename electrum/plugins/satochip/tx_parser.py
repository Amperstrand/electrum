"""Satochip transaction parser for JavaCard applet communication.

Serializes transactions into the format expected by the
Satochip JavaCard applet.
This is card-specific serialization that differs from
Electrum's transaction module.
"""

import hashlib
from enum import Enum, auto


class TxState(Enum):
    TX_START = auto()
    TX_PARSE_INPUT = auto()
    TX_PARSE_INPUT_SCRIPT = auto()
    TX_PARSE_OUTPUT = auto()
    TX_PARSE_OUTPUT_SCRIPT = auto()
    TX_PARSE_FINALIZE = auto()
    TX_END = auto()


class TxParser:
    CHUNK_SIZE = 128  # max chunk size of a script

    def __init__(self, rawTx):
        self.txData = rawTx[:]

        self.txRemainingInput = 0
        self.txCurrentInput = 0
        self.txRemainingOutput = 0
        self.txCurrentOutput = 0
        self.txAmount = 0
        self.txScriptRemaining = 0
        self.txOffset = 0
        self.txRemaining = len(rawTx)
        self.txState = TxState.TX_START

        self.txDigest = hashlib.sha256()
        self.singleHash = None
        self.doubleHash = None

        self.txChunk = b""

    def is_parsed(self):
        return self.txRemaining == 0

    def parse_transaction(self):
        self.txChunk = b""
        if self.txState == TxState.TX_START:
            # max 4+9 bytes accumulated
            self.parse_byte(4)  # version
            self.txRemainingInput = self.parse_var_int()
            self.txState = TxState.TX_PARSE_INPUT

        if self.txState == TxState.TX_PARSE_INPUT:
            # max 36+9 bytes accumulated
            if self.txRemainingInput == 0:
                self.txRemainingOutput = self.parse_var_int()
                self.txState = TxState.TX_PARSE_OUTPUT
            else:
                self.parse_byte(32)  # txOutHash
                self.parse_byte(4)  # txOutIndex
                self.txScriptRemaining = self.parse_var_int()
                self.txState = TxState.TX_PARSE_INPUT_SCRIPT
                self.txRemainingInput -= 1
                self.txCurrentInput += 1

        elif self.txState == TxState.TX_PARSE_INPUT_SCRIPT:
            # max MAX_CHUNK_SIZE+4 bytes accumulated
            chunkSize = (
                self.txScriptRemaining
                if self.txScriptRemaining < self.CHUNK_SIZE
                else self.CHUNK_SIZE
            )
            self.parse_byte(chunkSize)
            self.txScriptRemaining -= chunkSize
            if self.txScriptRemaining == 0:
                self.parse_byte(4)  # sequence
                self.txState = TxState.TX_PARSE_INPUT

        elif self.txState == TxState.TX_PARSE_OUTPUT:
            # max 8+9 bytes accumulated
            if self.txRemainingOutput == 0:
                self.parse_byte(4)  # locktime
                self.parse_byte(4)  # sighash
                self.txState = TxState.TX_END
            else:
                self.parse_byte(8)  # amount
                self.txScriptRemaining = self.parse_var_int()
                self.txState = TxState.TX_PARSE_OUTPUT_SCRIPT
                self.txRemainingOutput -= 1
                self.txCurrentOutput += 1

        elif self.txState == TxState.TX_PARSE_OUTPUT_SCRIPT:
            # max MAX_CHUNK_SIZE bytes accumulated
            chunkSize = (
                self.txScriptRemaining
                if self.txScriptRemaining < self.CHUNK_SIZE
                else self.CHUNK_SIZE
            )
            self.parse_byte(chunkSize)
            self.txScriptRemaining -= chunkSize

            if self.txScriptRemaining == 0:
                self.txState = TxState.TX_PARSE_OUTPUT

        elif self.txState == TxState.TX_END:
            pass

        # update hash
        self.txDigest.update(self.txChunk)
        if self.txState == TxState.TX_END:
            self.singleHash = self.txDigest.digest()
            self.txDigest = hashlib.sha256()
            self.txDigest.update(self.singleHash)
            self.doubleHash = self.txDigest.digest()

        return self.txChunk

    def parse_segwit_transaction(self):

        self.txChunk = b""
        if self.txState == TxState.TX_START:
            self.parse_byte(4)  # version
            self.parse_byte(32)  # hashPrevouts
            self.parse_byte(32)  # hashSequence
            # parse outpoint
            self.parse_byte(32)  # txOutHash
            self.parse_byte(4)  # txOutIndex
            # scriptcode= varint+script
            self.txScriptRemaining = self.parse_var_int()
            self.txState = TxState.TX_PARSE_INPUT_SCRIPT

        elif self.txState == TxState.TX_PARSE_INPUT_SCRIPT:
            # max MAX_CHUNK_SIZE+4 bytes accumulated
            chunkSize = (
                self.txScriptRemaining
                if self.txScriptRemaining < self.CHUNK_SIZE
                else self.CHUNK_SIZE
            )
            self.parse_byte(chunkSize)
            self.txScriptRemaining -= chunkSize
            if self.txScriptRemaining == 0:
                self.txState = TxState.TX_PARSE_FINALIZE

        elif self.txState == TxState.TX_PARSE_FINALIZE:
            self.parse_byte(8)  # amount
            self.parse_byte(4)  # nSequence
            self.parse_byte(32)  # hashOutputs
            self.parse_byte(4)  # nLocktime
            self.parse_byte(4)  # nHashType

            self.txState = TxState.TX_END

        elif self.txState == TxState.TX_END:
            pass

        # update hash
        self.txDigest.update(self.txChunk)
        if self.txState == TxState.TX_END:
            self.singleHash = self.txDigest.digest()
            self.txDigest = hashlib.sha256()
            self.txDigest.update(self.singleHash)
            self.doubleHash = self.txDigest.digest()

        return self.txChunk

    def parse_byte(self, length):
        if self.txOffset + length > len(self.txData):
            raise ValueError(
                f"tx_parser: read past end at offset {self.txOffset}"
                f"+{length} > {len(self.txData)}"
            )
        self.txChunk += self.txData[self.txOffset:(self.txOffset + length)]
        self.txOffset += length
        self.txRemaining -= length

    def parse_var_int(self):

        if self.txOffset >= len(self.txData):
            raise ValueError(
                f"tx_parser: var_int read past end at offset "
                f"{self.txOffset}"
            )

        first = 0xFF & self.txData[self.txOffset]
        val = 0
        le = 0
        if first < 253:
            # 8 bits
            val = first
            le = 1
        elif first == 253:
            # 16 bits
            val = (0xFF & self.txData[self.txOffset + 1]) | (
                (0xFF & self.txData[self.txOffset + 2]) << 8
            )
            le = 3
        elif first == 254:
            # 32 bits
            val = read_int32(self.txData, self.txOffset + 1)
            le = 5
        else:
            # 64 bits
            val = read_int64(self.txData, self.txOffset + 1)
            le = 9

        self.txChunk += self.txData[self.txOffset:(self.txOffset + le)]
        self.txOffset += le
        self.txRemaining -= le
        return val


def read_uint32(data, offset):
    out = 0
    for i in range(4):
        out |= (data[offset] & 0xFF) << (8 * i)
        offset += 1
    return out


def read_int32(data, offset):
    n = read_uint32(data, offset)
    if n >= 0x80000000:
        n -= 0x100000000
    return n


def read_int64(data, offset):
    out = 0
    for i in range(8):
        out |= (data[offset] & 0xFF) << (8 * i)
        offset += 1
    return out
