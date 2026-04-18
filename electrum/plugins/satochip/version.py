"""Satochip protocol version constants."""

# Satochip supported version tuple
# v0.4: getBIP32ExtendedKey also returns chaincode
# v0.5: Support for Segwit transaction
# v0.6: bip32 optimization: speed up computation during derivation of non-hardened child
# v0.8: support seed reset and pin change
# v0.9: patch message signing for alts
# v0.10: sign tx hash
# v0.11: support for (mandatory) secure channel
# v0.14: Schnorr signatures, nostr event signatures, Liquid-Bitcoin support (export Master Blinding Key)
# v0.15: support for MuSig2 (WIP)
SATOCHIP_PROTOCOL_MAJOR_VERSION = 0
SATOCHIP_PROTOCOL_MINOR_VERSION = 15
SATOCHIP_PROTOCOL_VERSION = (
    SATOCHIP_PROTOCOL_MAJOR_VERSION << 8
) + SATOCHIP_PROTOCOL_MINOR_VERSION

# SeedKeeper supported version tuple
# v 0.1: initial version
# v 0.2: WIP
SEEDKEEPER_PROTOCOL_MAJOR_VERSION = 0
SEEDKEEPER_PROTOCOL_MINOR_VERSION = 2
SEEDKEEPER_PROTOCOL_VERSION = (
    SEEDKEEPER_PROTOCOL_MAJOR_VERSION << 8
) + SEEDKEEPER_PROTOCOL_MINOR_VERSION

# Satodime supported version tuple
# v 0.1: initial version
SATODIME_PROTOCOL_MAJOR_VERSION = 0
SATODIME_PROTOCOL_MINOR_VERSION = 1
SATODIME_PROTOCOL_VERSION = (
    SATODIME_PROTOCOL_MAJOR_VERSION << 8
) + SATODIME_PROTOCOL_MINOR_VERSION

# Satocash supported version tuple
# v 0.1: initial version
SATOCASH_PROTOCOL_MAJOR_VERSION = 0
SATOCASH_PROTOCOL_MINOR_VERSION = 1
SATOCASH_PROTOCOL_VERSION = (
    SATOCASH_PROTOCOL_MAJOR_VERSION << 8
) + SATOCASH_PROTOCOL_MINOR_VERSION

# Satochip plugin version (for reference - different from pysatochip version)
SATODIME_MAJOR_VERSION = 0
SATODIME_MINOR_VERSION = 1
SATODIME_REVISION = 0
SATODIME_VERSION = (
    str(SATODIME_MAJOR_VERSION)
    + "."
    + str(SATODIME_MINOR_VERSION)
    + "."
    + str(SATODIME_REVISION)
)
