#!/bin/bash
#
# Run Electrum on macOS with a remote pcscd card reader
# This script:
# 1. Sets up SSH tunnel for remote pcscd Unix socket
# 2. Sets up library for macOS
# 3. Launches Electrum with correct environment
#
# Usage:
#   ./scripts/run_electrum_remote.sh [remote_host] [remote_socket]
#
# Example:
#   ./scripts/run_electrum_remote.sh root@192.168.13.202
#   ./scripts/run_electrum_remote.sh root@192.168.13.202 /run/pcscd/pcscd.comm

# Don't use set -e because we handle errors manually
REMOTE_HOST="${1:-root@192.168.13.202}"
REMOTE_SOCKET="${2:-/run/pcscd/pcscd.comm}"
LOCAL_SOCKET="/tmp/pcscd-remote.comm"

echo "=========================================="
echo "Electrum with Remote Card Reader"
echo "=========================================="
echo ""
echo "Remote host: $REMOTE_HOST"
echo "Remote socket: $REMOTE_SOCKET"
echo "Local socket: $LOCAL_SOCKET"
echo ""

echo "[1/3] Setting up SSH tunnel..."

# Always kill existing tunnel and recreate (more reliable)
pkill -f "ssh.*$LOCAL_SOCKET" 2>/dev/null || true
rm -f "$LOCAL_SOCKET" 2>/dev/null || true
sleep 0.5

# Start new SSH tunnel
ssh -f -N -o ExitOnForwardFailure=yes -o StreamLocalBindUnlink=yes \
    -L "$LOCAL_SOCKET:$REMOTE_SOCKET" "$REMOTE_HOST"
sleep 2

# Verify socket exists
if [ -S "$LOCAL_SOCKET" ]; then
    echo "SSH tunnel established: $LOCAL_SOCKET"
else
    echo "ERROR: SSH tunnel failed - check you can SSH to $REMOTE_HOST"
    exit 1
fi
# 2. Setup macOS library
echo ""
echo "[2/3] Setting up pcsc-lite library..."
rm -f /tmp/libpcsclite_real.so.1 2>/dev/null || true
cp /usr/local/opt/pcsc-lite/lib/libpcsclite_real.1.dylib /tmp/libpcsclite_real.so.1
echo "Library ready: /tmp/libpcsclite_real.so.1"

# 3. Test connection
echo ""
echo "[3/3] Testing card reader connection..."
export DYLD_LIBRARY_PATH=/tmp:$DYLD_LIBRARY_PATH
export PCSCLITE_CSOCK_NAME="$LOCAL_SOCKET"

python3 << 'PYTEST'
import os
import sys
import ctypes

lib = ctypes.CDLL("/usr/local/opt/pcsc-lite/lib/libpcsclite.1.dylib")
hContext = ctypes.c_uint32()
rv = lib.SCardEstablishContext(0, None, None, ctypes.byref(hContext))

if rv == 0:
    cch = ctypes.c_uint32(0)
    lib.SCardListReaders(hContext, None, None, ctypes.byref(cch))
    if cch.value > 0:
        buf = ctypes.create_string_buffer(cch.value)
        lib.SCardListReaders(hContext, None, buf, ctypes.byref(cch))
        readers = []
        current = bytearray()
        for b in buf.raw:
            if b == 0:
                if current:
                    readers.append(bytes(current).decode())
                    current = bytearray()
            else:
                current.append(b)
        print(f"SUCCESS: {len(readers)} reader(s) found:")
        for r in readers:
            print(f"  - {r}")
    else:
        print("WARNING: No readers found - is a card reader connected?")
    lib.SCardReleaseContext(hContext)
else:
    # Handle signed/unsigned conversion for error code
    rv_unsigned = rv & 0xFFFFFFFF
    print(f"ERROR: SCardEstablishContext failed: 0x{rv_unsigned:08x}")
    sys.exit(1)
PYTEST

# Check if Python test succeeded
if [ $? -ne 0 ]; then
    echo ""
    echo "Card reader test failed. Electrum may not detect your card."
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi
echo ""
echo "=========================================="
echo "Launching Electrum..."
echo "=========================================="
echo ""

# Run Electrum with signet and environment set
export ELECTRUM_FORCE_LOG_TO_FILE=1
exec env DYLD_LIBRARY_PATH=/tmp:$DYLD_LIBRARY_PATH PCSCLITE_CSOCK_NAME="$LOCAL_SOCKET" ./run_electrum --signet -v "$@"
