#!/usr/bin/env python3
"""Provision a blank Satochip card with TESTPIN/TESTPUK and import HUNGRY_MNEMONIC seed.

This script:
  1. Connects to the card via SSH tunnel socket (PCSCLITE_CSOCK_NAME)
  2. Calls card_setup() with TESTPIN/TESTPUK if not already done
  3. Imports HUNGRY_MNEMONIC seed if not already seeded
  4. Verifies the result

Usage:
    python3 scripts/setup_test_card.py
"""
from __future__ import annotations
import os
import sys

# Ensure repo root is on sys.path so 'electrum' package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
import time

# ── Constants ────────────────────────────────────────────────────────────────

TESTPIN = b'123456'
TESTPUK = b'12345678'

HUNGRY_MNEMONIC = "hungry type amount worth cloth breeze capable absent more wear manual audit"

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
_logger = logging.getLogger(__name__)


# ── Dummy card client ────────────────────────────────────────────────────────

class _DummyCardClient:
    """Minimal client stub for CardConnector — satisfies the interface without a GUI."""

    def request(self, req_type, *args):
        _logger.debug(f"_DummyCardClient.request({req_type!r}, {args!r})")
        return None


# ── Socket detection ─────────────────────────────────────────────────────────

def _detect_pcscd_socket() -> str | None:
    """Find the pcscd socket path; prefer the SSH tunnel socket."""
    candidates = [
        "/tmp/pcscd-remote.comm",
        "/run/pcscd/pcscd.comm",
    ]
    # Also honour explicit env var
    env_val = os.environ.get("PCSCLITE_CSOCK_NAME")
    if env_val:
        candidates.insert(0, env_val)

    for path in candidates:
        if os.path.exists(path):
            print(f"[socket] Found pcscd socket: {path}")
            return path
    return None


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    # ── Step 0: Set up socket ──────────────────────────────────────────────
    socket_path = _detect_pcscd_socket()
    if socket_path is None:
        print("ERROR: No pcscd socket found. Is the SSH tunnel active?")
        print("  Expected: /tmp/pcscd-remote.comm  (SSH tunnel)")
        print("  or:       /run/pcscd/pcscd.comm   (local pcscd)")
        return 1

    os.environ["PCSCLITE_CSOCK_NAME"] = socket_path
    print(f"[setup] Using pcscd socket: {socket_path}")

    # ── Step 1: Create CardConnector ───────────────────────────────────────
    try:
        from pysatochip.CardConnector import CardConnector
    except ImportError as e:
        print(f"ERROR: Cannot import pysatochip: {e}")
        print("  Install with: pip install pysatochip")
        return 1

    print("[setup] Creating CardConnector...")
    cc = CardConnector(_DummyCardClient(), logging.WARNING)

    # ── Step 2: Wait for card connection to stabilize ─────────────────────
    print("[setup] Waiting for card connection to stabilize...")
    status_ok = False
    for attempt in range(1, 6):
        try:
            resp, sw1, sw2, status_dict = cc.card_get_status()
            if sw1 == 0x90 and sw2 == 0x00:
                print(f"[setup] Card status OK (attempt {attempt})")
                print(f"  setup_done       = {cc.setup_done}")
                print(f"  is_seeded        = {cc.is_seeded}")
                print(f"  needs_secure_channel = {cc.needs_secure_channel}")
                status_ok = True
                break
            elif sw1 == 0x9C and sw2 == 0x04:
                # Not setup — that's fine, we'll set it up
                print(f"[setup] Card not setup yet (0x9C04) — will run card_setup()")
                cc.setup_done = False
                cc.is_seeded = False
                status_ok = True
                break
            else:
                print(f"[setup] Attempt {attempt}/5: unexpected SW=0x{sw1:02X}{sw2:02X}, retrying...")
        except Exception as e:
            print(f"[setup] Attempt {attempt}/5: {e}, retrying...")
        time.sleep(0.5)

    if not status_ok:
        print("ERROR: Could not get card status after 5 attempts.")
        cc.card_disconnect()
        return 1

    # ── Step 3: Initiate secure channel if needed ─────────────────────────
    if cc.needs_secure_channel:
        print("[setup] Initiating secure channel...")
        try:
            cc.card_initiate_secure_channel()
            print("[setup] Secure channel established.")
        except Exception as e:
            print(f"ERROR: Failed to initiate secure channel: {e}")
            cc.card_disconnect()
            return 1

    # ── Step 4: card_setup() if not already done ──────────────────────────
    if cc.setup_done:
        print("[setup] Card is already set up — skipping card_setup().")
    else:
        print("[setup] Running card_setup()...")

        pin_tries_0 = 0x05
        ublk_tries_0 = 0x01
        pin_0 = list(TESTPIN)    # b'123456'
        ublk_0 = list(TESTPUK)   # b'12345678'

        pin_tries_1 = 0x01
        ublk_tries_1 = 0x01
        pin_1 = list(os.urandom(16))
        ublk_1 = list(os.urandom(16))

        try:
            response, sw1, sw2 = cc.card_setup(
                pin_tries_0, ublk_tries_0, pin_0, ublk_0,
                pin_tries_1, ublk_tries_1, pin_1, ublk_1,
                32, 0,           # secmemsize, memsize
                0x01, 0x01, 0x01,  # create_object_ACL, create_key_ACL, create_pin_ACL
            )
        except Exception as e:
            print(f"ERROR: card_setup() raised: {e}")
            import traceback
            traceback.print_exc()
            cc.card_disconnect()
            return 1

        if sw1 == 0x90 and sw2 == 0x00:
            print("[setup] card_setup() succeeded!")
            cc.setup_done = True
        else:
            print(f"ERROR: card_setup() returned SW=0x{sw1:02X}{sw2:02X}")
            cc.card_disconnect()
            return 1

        # After setup, verify PIN by calling card_get_status again
        try:
            resp, sw1, sw2, status_dict = cc.card_get_status()
            if sw1 == 0x90 and sw2 == 0x00:
                print(f"[setup] Post-setup status: setup_done={cc.setup_done}, is_seeded={cc.is_seeded}")
        except Exception as e:
            print(f"[setup] Warning: post-setup status check failed: {e}")

        # Re-initiate secure channel if needed after setup
        if cc.needs_secure_channel:
            print("[setup] Re-initiating secure channel after setup...")
            try:
                cc.card_initiate_secure_channel()
                print("[setup] Secure channel established.")
            except Exception as e:
                print(f"ERROR: Failed to initiate secure channel post-setup: {e}")
                cc.card_disconnect()
                return 1

    # ── Step 5: Verify PIN before seed import ─────────────────────────────
    if not cc.setup_done:
        print("ERROR: setup_done is still False after card_setup(). Cannot proceed.")
        cc.card_disconnect()
        return 1

    # We need to verify PIN so the card allows seed import
    print("[setup] Verifying PIN...")
    try:
        response, sw1, sw2 = cc.card_verify_PIN_simple(pin=TESTPIN)
        if sw1 == 0x90 and sw2 == 0x00:
            print("[setup] PIN verified OK.")
        else:
            print(f"ERROR: PIN verification returned SW=0x{sw1:02X}{sw2:02X}")
            cc.card_disconnect()
            return 1
    except Exception as e:
        # card_verify_PIN_simple may call it differently; try the alternative
        print(f"[setup] PIN verify with signature failed ({e}), trying cc.pin/cc.pin_nbr approach...")
        cc.pin_nbr = 0
        cc.pin = list(TESTPIN)

    # ── Step 6: Import seed if not already seeded ─────────────────────────
    if cc.is_seeded:
        print("[setup] Card is already seeded — skipping seed import.")
    else:
        print("[setup] Importing HUNGRY_MNEMONIC seed...")

        try:
            from electrum.keystore import bip39_to_seed
        except ImportError as e:
            print(f"ERROR: Cannot import electrum.keystore: {e}")
            print("  Make sure electrum is installed or run from the repo root.")
            cc.card_disconnect()
            return 1

        masterseed = bip39_to_seed(HUNGRY_MNEMONIC, passphrase="")
        print(f"[setup] Derived masterseed ({len(masterseed)} bytes): {masterseed[:8].hex()}...")

        try:
            authentikey = cc.card_bip32_import_seed(list(masterseed))
        except Exception as e:
            print(f"ERROR: card_bip32_import_seed() raised: {e}")
            import traceback
            traceback.print_exc()
            cc.card_disconnect()
            return 1

        if authentikey is not None:
            authentikey_hex = authentikey.get_public_key_bytes(True).hex()
            print(f"[setup] Seed imported successfully!")
            print(f"[setup] Authentikey: {authentikey_hex}")
        else:
            print("ERROR: card_bip32_import_seed() returned None (seed import failed).")
            cc.card_disconnect()
            return 1

    # ── Step 7: Final verification ────────────────────────────────────────
    print("[setup] Final verification...")
    try:
        resp, sw1, sw2, status_dict = cc.card_get_status()
        if sw1 == 0x90 and sw2 == 0x00:
            print(f"[setup] Final status:")
            print(f"  setup_done = {cc.setup_done}")
            print(f"  is_seeded  = {cc.is_seeded}")
            if not cc.setup_done:
                print("ERROR: setup_done is False after provisioning!")
                cc.card_disconnect()
                return 1
            if not cc.is_seeded:
                print("ERROR: is_seeded is False after seed import!")
                cc.card_disconnect()
                return 1
        else:
            print(f"WARNING: Final status returned SW=0x{sw1:02X}{sw2:02X}")
    except Exception as e:
        print(f"WARNING: Final status check failed: {e}")

    # ── Done ──────────────────────────────────────────────────────────────
    print()
    print("=" * 60)
    print("  Card provisioning COMPLETE")
    print(f"  PIN  : {TESTPIN.decode()}")
    print(f"  PUK  : {TESTPUK.decode()}")
    print(f"  Seed : {HUNGRY_MNEMONIC[:40]}...")
    print("=" * 60)

    cc.card_disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(main())
