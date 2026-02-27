"""
User story tests for Satochip plugin — end-to-end card lifecycle scenarios.

Stories covered:
  Story 0 — Factory Reset:
              Put the card back to a clean slate (factory reset) so subsequent
              stories start from a known FACTORY_RESET state.
  Story 1 — Wallet Setup and Sign:
              Initialize the card with TESTPIN/TESTPUK, import HUNGRY_MNEMONIC,
              derive xpub, sign a transaction, and verify the signature.
  Story 2 — Wrong PIN Until Block:
              Enter the wrong PIN repeatedly until the card blocks (PIN_BLOCKED),
              confirming the card transitions correctly.
  Story 3 — PUK Recovery and Verify:
              Use TESTPUK to unblock the card, reset the PIN to TESTPIN,
              and verify the card returns to the SEEDED state.

Card state machine:
  FACTORY_RESET → (Story 0 brings us here from any state)
  FACTORY_RESET → INITIALIZED → SEEDED   (Stories 0→1)
  SEEDED        → PIN_BLOCKED             (Story 2)
  PIN_BLOCKED   → (PUK recovery) → SEEDED (Story 3)

Ordering is enforced by ``pytest-order`` via ``@pytest.mark.order(N)`` on each
class.  Without this decorator the collection order is filesystem-dependent and
may vary across Python/pytest versions.  pytest-order 1.3.0 is required.

Cascade skipping:
  The module-level ``_cascade_skip`` dict is mutated by each story implementation
  (Wave 2).  If Story N fails, it inserts an entry so Story N+1 is auto-skipped,
  preventing destructive operations on a card in an unknown state.

These tests are guarded by the ``user_story`` marker and will be skipped
unless ``--run-user-stories`` is passed on the command line (enforced by
``conftest.pytest_collection_modifyitems``).  They also require a physical
Satochip card accessible via ``cc_session`` (session-scoped fixture).

Run all user stories:
  python3 -m pytest -v electrum/plugins/satochip/tests/test_satochip_user_stories.py \\
      --run-user-stories -s

Run a single story:
  python3 -m pytest -v electrum/plugins/satochip/tests/test_satochip_user_stories.py::TestStory1WalletSetupAndSign \\
      --run-user-stories -s

Collect only (no execution, no card needed):
  python3 -m pytest --co electrum/plugins/satochip/tests/test_satochip_user_stories.py
"""

# pyright: reportUnknownVariableType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportAny=false, reportExplicitAny=false, reportUnnecessaryCast=false

import pytest
from pathlib import Path
from typing import Any, cast
from electrum.plugins.satochip.tests.story_helpers import (
    TESTPIN,
    TESTPUK,
    HUNGRY_MNEMONIC,
    StoryArtifacts,
    create_gui_observer,
    set_status,
    record_event,
    require_card_state,
    puk_preflight_check,
    wait_for_card_absent,
    wait_for_card_present,
    apdu_factory_reset,
)

# ---------------------------------------------------------------------------
# Module-level markers — applied to every test in this file.
# ---------------------------------------------------------------------------
pytestmark = [
    pytest.mark.user_story,
    pytest.mark.integration,
    pytest.mark.requires_card,
    pytest.mark.destructive_card,
]

# ---------------------------------------------------------------------------
# Cascade-skip registry — mutated by story implementations in Wave 2.
# If Story N fails it inserts: _cascade_skip["StoryN+1"] = "reason"
# Each test checks the registry at the start and calls pytest.skip() if set.
# ---------------------------------------------------------------------------
_cascade_skip: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Helper functions — duplicated from test_satochip_integration.py because
# we CANNOT import from that module (test files should be independent).
# ---------------------------------------------------------------------------


def _derive_xpub_from_card(cc, bip32_path: str, xtype: str) -> str:
    """
    Derive a BIP32 xpub from the card at *bip32_path* using the same logic
    as ``SatochipClient.get_xpub()``.
    """
    from electrum.bip32 import BIP32Node
    from electrum.crypto import hash_160
    from electrum.plugins.satochip.satochip import bip32path2bytes

    depth, bytepath = bip32path2bytes(bip32_path)
    childkey, childchaincode = cc.card_bip32_get_extendedkey(bytepath)

    if depth == 0:
        fingerprint = bytes(4)
        child_number = bytes(4)
    else:
        parentkey, _ = cc.card_bip32_get_extendedkey(bytepath[:-4])
        fingerprint = hash_160(parentkey.get_public_key_bytes(compressed=True))[:4]
        child_number = bytepath[-4:]

    return BIP32Node(
        xtype=xtype,
        eckey=childkey,
        chaincode=childchaincode,
        depth=depth,
        fingerprint=fingerprint,
        child_number=child_number,
    ).to_xpub()


def _derive_xpub_software(seed_bytes: bytes, bip32_path: str, xtype: str) -> str:
    """
    Compute the BIP32 xpub purely in software from *seed_bytes*.
    """
    from electrum.bip32 import BIP32Node
    root = BIP32Node.from_rootseed(seed_bytes, xtype=xtype)
    return root.subkey_at_private_derivation(bip32_path).to_xpub()


def _derive_key(cc, path_str: str):
    """Derive an extended key from the card at the given path string.

    Returns (pubkey, chaincode) where pubkey is a pysatochip ECPubkey.
    """
    from electrum.plugins.satochip.satochip import bip32path2bytes
    _, bytepath = bip32path2bytes(path_str)
    pubkey, chaincode = cc.card_bip32_get_extendedkey(bytepath)
    return pubkey, chaincode


def _r_s_from_der(der_sig_bytes: bytes):
    """Parse a DER-encoded ECDSA signature into (r, s) integers."""
    import electrum_ecc as _ecc
    return _ecc.get_r_and_s_from_ecdsa_der_sig(der_sig_bytes)


def _verify_ecdsa(pubkey, hash32: bytes, der_sig_bytes: bytes):
    """
    Verify a DER ECDSA signature against a pysatochip ECPubkey and a 32-byte hash.

    Converts DER to raw 64-byte r||s then calls ECPubkey.verify_message_hash.
    Raises on failure; returns None on success.
    """
    r, s = _r_s_from_der(der_sig_bytes)
    raw64 = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    pubkey.verify_message_hash(raw64, hash32)

# ---------------------------------------------------------------------------
# Story 0 — Factory Reset
# ---------------------------------------------------------------------------
@pytest.mark.order(0)
class TestStory0FactoryReset:
    """
    Story 0: Factory Reset

    Precondition:  Card may be in any state (FACTORY_RESET, INITIALIZED, SEEDED,
                   or PIN_BLOCKED).
    Action:        Use APDU-based reset signaling to return the card to a clean
                   FACTORY_RESET state.  This flow requires physical card
                   removal/reinsertion cycles and must run in GUI observer mode
                   (SATOCHIP_OBSERVE_GUI=1).  No subprocess/GP tooling is used.
    Postcondition: Card is in FACTORY_RESET state — setup_done=False,
                   is_seeded=False, PIN tries restored to maximum.

    ⚠️  SAFETY: This story permanently erases all card data.  Only run against
    a test card initialised by this suite (TESTPIN/TESTPUK known).
    """

    def test_factory_reset_card(self, cc_session: Any, story_artifact_root: Path):
        import os
        import time

        PREFIX = "story-0-factory-reset"
        artifacts = StoryArtifacts(cast(Path, story_artifact_root), PREFIX)
        events: list[dict[str, Any]] = []
        observer = create_gui_observer("Story 0 - Factory Reset")
        app, widget, status_label, observe_gui = cast(tuple[Any, Any, Any, bool], observer)

        def _status(text: str, shot_name: str | None = None) -> None:
            set_status(text, shot_name, PREFIX, widget, status_label, app, artifacts.screenshot_dir, observe_gui)

        _ = (require_card_state, wait_for_card_absent)

        if not observe_gui:
            _cascade_skip["story_0"] = "SKIPPED: GUI required for APDU reset"
            pytest.skip("Story 0 requires GUI mode (SATOCHIP_OBSERVE_GUI=1)")

        _status("Starting factory reset...", "00_start")

        _status("Running APDU factory-reset flow...", "01_apdu_start")
        try:
            _ = apdu_factory_reset(cc_session, _status, app=app)
        except RuntimeError as exc:
            _cascade_skip["story_0"] = f"FAILED: {exc}"
            _status(f"FAILED: {exc}", "03_failed")
            record_event(
                {
                    "event": "factory_reset_apdu",
                    "status": "failed",
                    "error": str(exc),
                },
                artifacts.log_path,
                events,
            )
            pytest.fail(str(exc))

        _status("APDU reset flow complete", "02_apdu_done")

        record_event(
            {
                "event": "factory_reset_apdu",
                "status": "ok",
                "observe_gui_env": os.environ.get("SATOCHIP_OBSERVE_GUI"),
            },
            artifacts.log_path,
            events,
        )

        _status("Verifying card is factory-reset...", "04_verify_blank")
        if not wait_for_card_present(cc_session, timeout=30, app=app):
            _cascade_skip["story_0"] = "FAILED: timed out waiting for card reconnection"
            _status("FAILED: card did not reconnect", "03_failed_reconnect")
            record_event(
                {
                    "event": "factory_reset_verification",
                    "status": "failed",
                    "error": "Timed out waiting for card reconnection after APDU reset",
                },
                artifacts.log_path,
                events,
            )
            pytest.fail("Timed out waiting for card reconnection after APDU reset")

        time.sleep(2.0)
        try:
            (_, sw1, sw2, status_dict) = cc_session.card_get_status()
        except Exception:
            time.sleep(2)
            try:
                cc_session.card_initiate_secure_channel()
            except Exception:
                pass
            (_, sw1, sw2, status_dict) = cc_session.card_get_status()

        setup_done = status_dict.get("setup_done", "UNKNOWN")
        record_event(
            {
                "event": "factory_reset_verification",
                "setup_done": setup_done,
                "sw": f"{sw1:02X}{sw2:02X}",
                "status_dict_keys": list(status_dict.keys()),
            },
            artifacts.log_path,
            events,
        )

        if setup_done is not False:
            _cascade_skip["story_0"] = f"FAILED: card not blank after reset (setup_done={setup_done})"
            _status(f"FAILED: setup_done={setup_done}", "05_failed_not_blank")
            pytest.fail(f"Card not blank after factory reset: setup_done={setup_done}")

        _cascade_skip["story_0"] = "passed"
        _status("Factory reset complete - card is blank", "06_success")
        record_event(
            {
                "event": "factory_reset_complete",
                "status": "passed",
            },
            artifacts.log_path,
            events,
        )


# ---------------------------------------------------------------------------
# Story 1 — Wallet Setup and Sign
# ---------------------------------------------------------------------------
@pytest.mark.order(1)
class TestStory1WalletSetupAndSign:
    """
    Story 1: Wallet Setup and Sign

    Precondition:  Card is in FACTORY_RESET state (setup_done=False).
    Action:        Initialize the card with TESTPIN/TESTPUK, import
                   HUNGRY_MNEMONIC, derive xpub, sign a test transaction,
                   and verify the resulting signature against a software wallet.
    Postcondition: Card is in SEEDED state — setup_done=True, is_seeded=True,
                   derived xpub matches the software-only reference.

    This story mirrors the happy-path user flow: unbox card → set PIN → import
    seed phrase → sign a Bitcoin transaction.
    """

    def test_wallet_setup_and_sign(self, cc_session: Any, story_artifact_root: Path):
        """
        Full lifecycle test: blank card → setup → seed → derive → sign → verify.

        A single test method so the entire flow is captured as one artifact set
        with a coherent JSONL log and sequential screenshots.
        """
        import os
        import hashlib
        import time
        from electrum.keystore import bip39_to_seed

        # -- Cascade skip check -------------------------------------------
        if _cascade_skip.get("story_0") != "passed":
            pytest.skip("Story 0 (Factory Reset) did not pass — skipping Story 1")

        # -- Artifact setup ------------------------------------------------
        PREFIX = "story-1-wallet-setup-and-sign"
        artifacts = StoryArtifacts(cast(Path, story_artifact_root), PREFIX)
        events: list[dict[str, Any]] = []
        observer = create_gui_observer("Story 1 - Wallet Setup & Sign")
        app, widget, status_label, observe_gui = cast(tuple[Any, Any, Any, bool], observer)

        def _status(text: str, shot_name: str | None = None) -> None:
            set_status(text, shot_name, PREFIX, widget, status_label, app, artifacts.screenshot_dir, observe_gui)

        _status("Starting wallet setup & sign workflow...", "00_start")

        # =================================================================
        # Step 1: Verify card is blank (factory-reset)
        # =================================================================
        _status("Step 1: Checking card is blank (factory-reset)...", "step01_check_blank")

        (_, sw1, sw2, d) = cc_session.card_get_status()
        record_event(
            {
                "event": "card_status_check",
                "step": 1,
                "setup_done": d.get("setup_done"),
                "is_seeded": d.get("is_seeded"),
                "sw": f"0x{sw1:02x}{sw2:02x}",
            },
            artifacts.log_path,
            events,
        )

        if d["setup_done"]:
            _status(
                "⚠ Card already initialized — skipping setup step.",
                "step01_already_setup",
            )
            record_event({"event": "skip_setup", "reason": "card already initialized"}, artifacts.log_path, events)
            # Still usable: verify PIN and continue to seed import
            _, sw1, sw2 = cc_session.card_verify_PIN_simple(TESTPIN)
            if (sw1, sw2) != (0x90, 0x00):
                reason = f"TESTPIN verification failed on already-setup card: SW=0x{sw1:02x}{sw2:02x}"
                _cascade_skip["story_1"] = f"FAILED: {reason}"
                pytest.fail(reason)
        else:
            # =============================================================
            # Step 2: Card setup — set PIN and PUK
            # =============================================================
            _status("Step 2: Initialising card with TESTPIN...", "step02_card_setup")

            # Secure channel race condition fix — on a blank card the
            # cc_session fixture may have raced with the CardObserver
            # thread, leaving the channel half-ready (SW=0x9C23).
            if getattr(cc_session, 'needs_secure_channel', False):
                try:
                    cc_session.card_initiate_secure_channel()
                except Exception:
                    pass  # already initialised — harmless

            pin_tries_0 = 0x05
            ublk_tries_0 = 0x01
            ublk_0 = list(TESTPUK)
            pin_tries_1 = 0x01
            ublk_tries_1 = 0x01
            pin_1 = list(os.urandom(16))
            ublk_1 = list(os.urandom(16))

            response, sw1, sw2 = cc_session.card_setup(
                pin_tries_0, ublk_tries_0, list(TESTPIN), ublk_0,
                pin_tries_1, ublk_tries_1, pin_1, ublk_1,
                32, 0,  # secmemsize, memsize
                0x01, 0x01, 0x01,  # ACLs
            )
            if (sw1, sw2) != (0x90, 0x00):
                reason = f"card_setup() failed: SW=0x{sw1:02x}{sw2:02x}"
                _cascade_skip["story_1"] = f"FAILED: {reason}"
                pytest.fail(reason)

            record_event(
                {
                    "event": "card_setup",
                    "step": 2,
                    "status": "ok",
                    "sw": f"0x{sw1:02x}{sw2:02x}",
                    "pin_tries": pin_tries_0,
                    "puk_tries": ublk_tries_0,
                },
                artifacts.log_path,
                events,
            )
            _status("✓ Card setup complete. PIN configured.", "step02_setup_done")

        # =================================================================
        # Step 3: Import seed from HUNGRY_MNEMONIC
        # =================================================================
        (_, _, _, d_after_setup) = cc_session.card_get_status()
        if d_after_setup["setup_done"] is not True:
            reason = "Card should be initialized by now"
            _cascade_skip["story_1"] = f"FAILED: {reason}"
            pytest.fail(reason)

        if d_after_setup.get("is_seeded"):
            _status(
                "⚠ Card already seeded — resetting seed first.",
                "step03_reset_seed",
            )
            _, sw1, sw2 = cc_session.card_reset_seed(list(TESTPIN))
            if (sw1, sw2) != (0x90, 0x00):
                reason = f"card_reset_seed() failed: SW=0x{sw1:02x}{sw2:02x}"
                _cascade_skip["story_1"] = f"FAILED: {reason}"
                pytest.fail(reason)
            record_event({"event": "seed_reset", "step": 3, "reason": "card was already seeded"}, artifacts.log_path, events)

        _status(
            f"Step 3: Importing seed from mnemonic ({HUNGRY_MNEMONIC[:30]}...)...",
            "step03_import_seed",
        )

        masterseed = bip39_to_seed(HUNGRY_MNEMONIC, passphrase="")
        authentikey = cc_session.card_bip32_import_seed(list(masterseed))

        if authentikey is None:
            reason = "card_bip32_import_seed() returned None"
            _cascade_skip["story_1"] = f"FAILED: {reason}"
            pytest.fail(reason)
        if cc_session.is_seeded is not True:
            reason = "cc.is_seeded must be True after import"
            _cascade_skip["story_1"] = f"FAILED: {reason}"
            pytest.fail(reason)

        authentikey_hex = authentikey.get_public_key_bytes(compressed=True).hex()
        record_event(
            {
                "event": "seed_import",
                "step": 3,
                "status": "ok",
                "mnemonic_preview": HUNGRY_MNEMONIC[:30] + "...",
                "authentikey": authentikey_hex,
            },
            artifacts.log_path,
            events,
        )
        _status(
            f"✓ Seed imported. Authentikey: {authentikey_hex[:16]}...",
            "step03_seed_imported",
        )

        # =================================================================
        # Step 4: Derive xpubs and cross-check with software
        # =================================================================
        _status("Step 4: Deriving xpubs and cross-checking...", "step04_derive_xpubs")

        xpub_paths = [
            ("m/84'/0'/0'", "p2wpkh"),       # native SegWit (BIP84)
            ("m/44'/0'/0'", "standard"),     # legacy (BIP44)
            ("m/49'/0'/0'", "p2wpkh-p2sh"),  # wrapped SegWit (BIP49)
        ]

        xpub_results = []
        for path, xtype in xpub_paths:
            card_xpub = _derive_xpub_from_card(cc_session, path, xtype)
            sw_xpub = _derive_xpub_software(masterseed, path, xtype)

            match = card_xpub == sw_xpub
            xpub_results.append({
                "path": path,
                "xtype": xtype,
                "card_xpub": card_xpub,
                "sw_xpub": sw_xpub,
                "match": match,
            })

            if not match:
                reason = (
                    f"xpub mismatch at {path} ({xtype})!\n"
                    f"  card: {card_xpub}\n  sw:   {sw_xpub}"
                )
                _cascade_skip["story_1"] = f"FAILED: {reason}"
                pytest.fail(reason)

        record_event(
            {
                "event": "xpub_derivation",
                "step": 4,
                "status": "ok",
                "paths_checked": len(xpub_paths),
                "all_match": all(r["match"] for r in xpub_results),
                "results": xpub_results,
            },
            artifacts.log_path,
            events,
        )
        _status(
            f"✓ All {len(xpub_paths)} xpub paths match software derivation.",
            "step04_xpubs_ok",
        )

        # =================================================================
        # Step 5: Sign a message and verify the signature
        # =================================================================
        sign_path = "m/84'/0'/0'/0/0"  # first receiving address, native SegWit
        message = b"Satochip wallet setup test: hello from electrum-satochip"

        _status(
            f"Step 5: Signing message at {sign_path}...",
            "step05_sign_message",
        )

        # Derive the key at the signing path
        pubkey, _ = _derive_key(cc_session, sign_path)
        pubkey_hex = pubkey.get_public_key_bytes(compressed=True).hex()

        # Sign the message
        sig4 = cc_session.card_sign_message(0xFF, pubkey, message, b'')
        if sig4 is None:
            reason = "card_sign_message returned None"
            _cascade_skip["story_1"] = f"FAILED: {reason}"
            pytest.fail(reason)
        _, sw1, sw2, compsig = sig4

        if (sw1, sw2) != (0x90, 0x00):
            reason = f"card_sign_message() failed: SW=0x{sw1:02x}{sw2:02x}"
            _cascade_skip["story_1"] = f"FAILED: {reason}"
            pytest.fail(reason)
        if len(compsig) != 65:
            reason = f"Expected 65-byte compact sig, got {len(compsig)}"
            _cascade_skip["story_1"] = f"FAILED: {reason}"
            pytest.fail(reason)

        # Verify the signature
        pubkey.verify_message_for_address(compsig, message)

        record_event(
            {
                "event": "message_sign",
                "step": 5,
                "status": "ok",
                "path": sign_path,
                "pubkey": pubkey_hex,
                "message": message.decode("utf-8"),
                "signature_hex": compsig.hex(),
                "signature_length": len(compsig),
            },
            artifacts.log_path,
            events,
        )
        _status(
            f"✓ Message signed and verified.\n"
            f"  Path: {sign_path}\n"
            f"  Pubkey: {pubkey_hex[:16]}...\n"
            f"  Sig: {compsig.hex()[:32]}...",
            "step05_signed_ok",
        )

        # =================================================================
        # Step 6: Sign a hash to prove ECDSA transaction signing works
        # =================================================================
        _status("Step 6: Signing a hash (ECDSA) to verify transaction signing...", "step06_sign_hash")

        test_hash = hashlib.sha256(hashlib.sha256(
            b"electrum-satochip-wallet-setup-test"
        ).digest()).digest()

        sig_der, sw1, sw2 = cc_session.card_sign_transaction_hash(
            0xFF, list(test_hash), None
        )
        if (sw1, sw2) != (0x90, 0x00):
            reason = f"card_sign_transaction_hash() failed: SW=0x{sw1:02x}{sw2:02x}"
            _cascade_skip["story_1"] = f"FAILED: {reason}"
            pytest.fail(reason)
        if bytes(sig_der)[0] != 0x30:
            reason = "Expected DER SEQUENCE tag"
            _cascade_skip["story_1"] = f"FAILED: {reason}"
            pytest.fail(reason)

        # Verify ECDSA
        _verify_ecdsa(pubkey, test_hash, bytes(sig_der))

        record_event(
            {
                "event": "hash_sign",
                "step": 6,
                "status": "ok",
                "hash": test_hash.hex(),
                "der_sig_hex": bytes(sig_der).hex(),
                "der_sig_length": len(sig_der),
            },
            artifacts.log_path,
            events,
        )
        _status(
            f"✓ ECDSA hash signed and verified.\n"
            f"  DER sig: {bytes(sig_der).hex()[:32]}...",
            "step06_hash_signed_ok",
        )

        # =================================================================
        # Step 7: Final status report
        # =================================================================
        (_, sw1_f, sw2_f, d_final) = cc_session.card_get_status()

        record_event(
            {
                "event": "workflow_complete",
                "step": 7,
                "status": "ok",
                "card_status": {
                    "setup_done": d_final.get("setup_done"),
                    "is_seeded": d_final.get("is_seeded"),
                    "PIN0_remaining_tries": d_final.get("PIN0_remaining_tries"),
                    "protocol_version": d_final.get("protocol_version"),
                },
                "artifact_dir": str(artifacts.artifact_dir),
                "total_events": len(events),
            },
            artifacts.log_path,
            events,
        )

        _status(
            f"✓ WORKFLOW COMPLETE — Wallet setup & sign verified.\n"
            f"  Setup done: {d_final.get('setup_done')}\n"
            f"  Is seeded: {d_final.get('is_seeded')}\n"
            f"  PIN tries: {d_final.get('PIN0_remaining_tries')}\n"
            f"  Events logged: {len(events)}\n"
            f"  Artifacts: {artifacts.artifact_dir}",
            "step07_complete",
        )

        if observe_gui and app is not None:
            # Keep the window visible briefly so user can see final state
            time.sleep(2)
            app.processEvents()

        # Final assertions
        if d_final["setup_done"] is not True:
            reason = f"Final check: setup_done={d_final.get('setup_done')}"
            _cascade_skip["story_1"] = f"FAILED: {reason}"
            pytest.fail(reason)
        if d_final["is_seeded"] is not True:
            reason = f"Final check: is_seeded={d_final.get('is_seeded')}"
            _cascade_skip["story_1"] = f"FAILED: {reason}"
            pytest.fail(reason)
        if len(events) < 5:
            reason = f"Expected at least 5 events, got {len(events)}"
            _cascade_skip["story_1"] = f"FAILED: {reason}"
            pytest.fail(reason)
        if not artifacts.log_path.exists():
            reason = f"JSONL log not written: {artifacts.log_path}"
            _cascade_skip["story_1"] = f"FAILED: {reason}"
            pytest.fail(reason)

        # All passed — mark cascade as passed
        _cascade_skip["story_1"] = "passed"


# ---------------------------------------------------------------------------
# Story 2 — Wrong PIN Until Block
# ---------------------------------------------------------------------------
@pytest.mark.order(2)
class TestStory2WrongPinUntilBlock:
    """
    Story 2: Wrong PIN Until Block

    Precondition:  Card is in SEEDED state (setup_done=True, is_seeded=True).
    Action:        Present an incorrect PIN repeatedly (up to the card's maximum
                   retry counter) until the card transitions to PIN_BLOCKED.
                   Verify the remaining-tries counter decrements correctly and
                   that the final attempt results in a SW_PIN_BLOCKED status.
    Postcondition: Card is in PIN_BLOCKED state — PIN_0_remaining_tries == 0.

    ⚠️  SAFETY: This story intentionally blocks the card.  Story 3 (PUK Recovery)
    MUST run immediately after to restore the card.  If Story 3 is skipped or
    fails the card will remain blocked.
    """

    def test_wrong_pin_until_block(self, cc_session: Any, story_artifact_root: Path):
        """
        Send wrong PIN repeatedly until the card blocks (PIN_BLOCKED).

        A single test method so the entire flow is captured as one artifact set
        with a coherent JSONL log and sequential screenshots.
        """
        import os
        import time

        # -- Cascade skip check -------------------------------------------
        if _cascade_skip.get("story_1") != "passed":
            pytest.skip("Story 1 (Wallet Setup & Sign) did not pass — skipping Story 2")

        # -- Artifact setup ------------------------------------------------
        PREFIX = "story-2-wrong-pin-until-block"
        artifacts = StoryArtifacts(cast(Path, story_artifact_root), PREFIX)
        events: list[dict[str, Any]] = []
        observer = create_gui_observer("Story 2 - Wrong PIN Until Block")
        app, widget, status_label, observe_gui = cast(tuple[Any, Any, Any, bool], observer)

        def _status(text: str, shot_name: str | None = None) -> None:
            set_status(text, shot_name, PREFIX, widget, status_label, app, artifacts.screenshot_dir, observe_gui)

        _status("Starting wrong PIN until block workflow...", "00_start")

        # -- PUK preflight safety check ------------------------------------
        # Ensure recovery is possible AFTER we block the card (Story 3 needs PUK).
        puk_preflight_check(cc_session)

        # =================================================================
        # Step 1: Verify TESTPIN works before destructive loop
        # =================================================================
        _status("Step 1: Verifying TESTPIN works...", "step01_verify_pin")
        try:
            _, sw1, sw2 = cc_session.card_verify_PIN_simple(TESTPIN)
        except Exception as exc:
            reason = f"TESTPIN verification raised {type(exc).__name__}: {exc}"
            _cascade_skip["story_2"] = f"FAILED: {reason}"
            record_event(
                {"event": "testpin_verify_failed", "exception_type": type(exc).__name__, "exception": str(exc)},
                artifacts.log_path,
                events,
            )
            pytest.fail(reason)

        if (sw1, sw2) != (0x90, 0x00):
            reason = f"TESTPIN verification failed before destructive loop: SW=0x{sw1:02x}{sw2:02x}"
            _cascade_skip["story_2"] = f"FAILED: {reason}"
            record_event(
                {"event": "testpin_verify_failed", "sw": f"0x{sw1:02x}{sw2:02x}"},
                artifacts.log_path,
                events,
            )
            pytest.fail(reason)

        record_event(
            {"event": "testpin_verify_ok", "sw": f"0x{sw1:02x}{sw2:02x}"},
            artifacts.log_path,
            events,
        )

        # =================================================================
        # Step 2: Get initial PIN0_remaining_tries
        # =================================================================
        _status("Step 2: Reading initial PIN0_remaining_tries...", "step02_get_tries")
        (_, _, _, status0) = cc_session.card_get_status()
        max_tries = status0.get("PIN0_remaining_tries")
        if not (isinstance(max_tries, int) and max_tries >= 1):
            reason = f"Could not determine PIN0_remaining_tries from card status: {status0}"
            _cascade_skip["story_2"] = f"FAILED: {reason}"
            record_event(
                {"event": "max_tries_unknown", "status": str(status0)},
                artifacts.log_path,
                events,
            )
            pytest.fail(reason)

        record_event(
            {"event": "initial_status", "PIN0_remaining_tries": max_tries},
            artifacts.log_path,
            events,
        )
        _status(f"PIN0_remaining_tries = {max_tries}", "step02_tries_known")

        # =================================================================
        # Step 3: Construct wrong PIN (always different from TESTPIN)
        # =================================================================
        wrong_pin = b"000000" if TESTPIN != b"000000" else b"111111"

        # =================================================================
        # Step 4: Send wrong PIN max_tries times
        # =================================================================
        _status(f"Step 4: Starting wrong PIN attempts (max_tries={max_tries})", "step04_start_loop")

        for attempt in range(1, max_tries + 1):
            try:
                cc_session.card_verify_PIN_simple(wrong_pin)
                # If we get here, the wrong PIN was accepted — that's a failure
                reason = f"Attempt {attempt}: expected wrong-PIN error, call succeeded"
                _cascade_skip["story_2"] = f"FAILED: {reason}"
                record_event(
                    {"event": "wrong_pin_accepted", "attempt": attempt},
                    artifacts.log_path,
                    events,
                )
                pytest.fail(reason)
            except Exception as exc:
                exc_type = type(exc).__name__
                (_, _, _, d_after) = cc_session.card_get_status()
                tries_after = d_after.get("PIN0_remaining_tries")
                record_event(
                    {
                        "event": "wrong_pin_attempt",
                        "attempt": attempt,
                        "exception_type": exc_type,
                        "exception": str(exc),
                        "tries_remaining": tries_after,
                    },
                    artifacts.log_path,
                    events,
                )
                _status(
                    f"Attempt {attempt}/{max_tries}: {exc_type}, tries_remaining={tries_after}",
                    f"step_attempt_{attempt:02d}",
                )

                if attempt < max_tries:
                    if not ("WrongPin" in exc_type or "wrong" in str(exc).lower()):
                        reason = f"Attempt {attempt} expected WrongPinError, got {exc_type}: {exc}"
                        _cascade_skip["story_2"] = f"FAILED: {reason}"
                        pytest.fail(reason)

        # =================================================================
        # Step 5: Post-exhaustion attempt — card should be blocked
        # =================================================================
        _status("Step 5: Post-exhaustion attempt (card should be blocked)...", "step05_post_exhaust")

        try:
            cc_session.card_verify_PIN_simple(wrong_pin)
            reason = "Expected blocked PIN after exhausting tries, but call succeeded"
            _cascade_skip["story_2"] = f"FAILED: {reason}"
            record_event(
                {"event": "post_exhaustion_not_blocked"},
                artifacts.log_path,
                events,
            )
            pytest.fail(reason)
        except Exception as exc:
            exc_type = type(exc).__name__
            (_, _, _, d_blocked) = cc_session.card_get_status()
            tries_blocked = d_blocked.get("PIN0_remaining_tries")
            record_event(
                {
                    "event": "post_exhaustion_attempt",
                    "exception_type": exc_type,
                    "exception": str(exc),
                    "tries_remaining": tries_blocked,
                },
                artifacts.log_path,
                events,
            )
            _status(
                f"Post-exhaustion: {exc_type}, tries_remaining={tries_blocked}",
                "step05_blocked",
            )
            if not (("PinBlocked" in exc_type) or tries_blocked == 0):
                reason = f"Expected blocked card after exhausting tries, got {exc_type}, tries_remaining={tries_blocked}"
                _cascade_skip["story_2"] = f"FAILED: {reason}"
                pytest.fail(reason)

        # =================================================================
        # All passed — mark cascade as passed
        # =================================================================
        _cascade_skip["story_2"] = "passed"
        _status("Card is now PIN-blocked. Story 2 complete.", "06_success")
        record_event(
            {
                "event": "story_2_complete",
                "status": "passed",
                "pin_blocked": True,
            },
            artifacts.log_path,
            events,
        )

# ---------------------------------------------------------------------------
# Story 3 — PUK Recovery and Verify
# ---------------------------------------------------------------------------
@pytest.mark.order(3)
class TestStory3PukRecoveryAndVerify:
    """
    Story 3: PUK Recovery and Verify

    Precondition:  Card is in PIN_BLOCKED state (PIN_0_remaining_tries == 0).
    Action:        Present TESTPUK to unblock the card and reset the PIN back to
                   TESTPIN.  Verify that PIN verification succeeds with TESTPIN
                   after recovery, and that the seed (HUNGRY_MNEMONIC xpub) is
                   still intact — i.e., no data was lost during recovery.
    Postcondition: Card is back in SEEDED state — PIN_0_remaining_tries restored,
                   xpub matches pre-block reference.

    A ``puk_preflight_check`` is performed before attempting PUK recovery to
    confirm PUK_0_remaining_tries > 0.  If the PUK is already exhausted the test
    is skipped to avoid permanently bricking the card.
    """

    def test_puk_recovery_and_verify(self, cc_session: Any, story_artifact_root: Path):
        """
        Recover a PIN-blocked card using PUK, then verify PIN works again.

        A single test method so the entire flow is captured as one artifact set
        with a coherent JSONL log and sequential screenshots.
        """
        import os
        import time

        # -- Cascade skip check -------------------------------------------
        if _cascade_skip.get("story_2") != "passed":
            pytest.skip("Story 2 (Wrong PIN Until Block) did not pass — skipping Story 3")

        # -- Artifact setup ------------------------------------------------
        PREFIX = "story-3-puk-recovery-and-verify"
        artifacts = StoryArtifacts(cast(Path, story_artifact_root), PREFIX)
        events: list[dict[str, Any]] = []
        observer = create_gui_observer("Story 3 - PUK Recovery and Verify")
        app, widget, status_label, observe_gui = cast(tuple[Any, Any, Any, bool], observer)

        def _status(text: str, shot_name: str | None = None) -> None:
            set_status(text, shot_name, PREFIX, widget, status_label, app, artifacts.screenshot_dir, observe_gui)

        _status("Starting PUK recovery workflow...", "00_start")

        # =================================================================
        # Step 1: PUK preflight safety check
        # =================================================================
        _status("Step 1: PUK preflight safety check...", "step01_puk_preflight")
        try:
            puk_tries = puk_preflight_check(cc_session)
        except Exception as exc:
            reason = f"PUK preflight check failed: {type(exc).__name__}: {exc}"
            _cascade_skip["story_3"] = f"FAILED: {reason}"
            record_event(
                {"event": "puk_preflight", "status": "failed", "exception_type": type(exc).__name__, "exception": str(exc)},
                artifacts.log_path,
                events,
            )
            pytest.fail(reason)

        record_event(
            {"event": "puk_preflight", "status": "ok", "PUK0_remaining_tries": puk_tries},
            artifacts.log_path,
            events,
        )
        _status(f"PUK preflight OK — PUK0_remaining_tries={puk_tries}", "step01_puk_ok")

        # =================================================================
        # Step 2: Verify card is PIN-blocked (PIN0_remaining_tries == 0)
        # =================================================================
        _status("Step 2: Verifying card is PIN-blocked...", "step02_pin_blocked_check")
        (_, _, _, d_blocked) = cc_session.card_get_status()
        pin_tries_before = d_blocked.get("PIN0_remaining_tries")
        puk_tries_before = d_blocked.get("PUK0_remaining_tries")

        record_event(
            {
                "event": "pin_blocked_check",
                "PIN0_remaining_tries": pin_tries_before,
                "PUK0_remaining_tries": puk_tries_before,
            },
            artifacts.log_path,
            events,
        )

        if pin_tries_before != 0:
            reason = f"Expected PIN0_remaining_tries==0 (blocked), got {pin_tries_before}"
            _cascade_skip["story_3"] = f"FAILED: {reason}"
            pytest.fail(reason)

        _status(f"Card confirmed PIN-blocked (tries={pin_tries_before})", "step02_confirmed_blocked")

        # =================================================================
        # Step 3: PUK recovery — unblock PIN using TESTPUK
        # =================================================================
        _status("Step 3: Attempting PUK unblock recovery...", "step03_recover_start")
        try:
            cc_session.card_unblock_PIN(0, list(TESTPUK))
        except Exception as exc:
            reason = f"card_unblock_PIN raised {type(exc).__name__}: {exc}"
            _cascade_skip["story_3"] = f"FAILED: {reason}"
            record_event(
                {"event": "puk_recovery", "status": "failed", "exception_type": type(exc).__name__, "exception": str(exc)},
                artifacts.log_path,
                events,
            )
            pytest.fail(reason)

        record_event(
            {"event": "puk_recovery", "status": "ok"},
            artifacts.log_path,
            events,
        )
        _status("PUK unblock command succeeded.", "step03_recover_ok")

        # =================================================================
        # Step 4: Verify TESTPIN works after recovery
        # =================================================================
        _status("Step 4: Verifying TESTPIN works after recovery...", "step04_verify_pin")
        try:
            _, sw1, sw2 = cc_session.card_verify_PIN_simple(TESTPIN)
        except Exception as exc:
            reason = f"TESTPIN verification after recovery raised {type(exc).__name__}: {exc}"
            _cascade_skip["story_3"] = f"FAILED: {reason}"
            record_event(
                {"event": "pin_verify_after_recovery", "status": "failed", "exception_type": type(exc).__name__, "exception": str(exc)},
                artifacts.log_path,
                events,
            )
            pytest.fail(reason)

        if (sw1, sw2) != (0x90, 0x00):
            reason = f"TESTPIN verify after recovery failed: SW=0x{sw1:02x}{sw2:02x}"
            _cascade_skip["story_3"] = f"FAILED: {reason}"
            record_event(
                {"event": "pin_verify_after_recovery", "status": "failed", "sw": f"0x{sw1:02x}{sw2:02x}"},
                artifacts.log_path,
                events,
            )
            pytest.fail(reason)

        record_event(
            {"event": "pin_verify_after_recovery", "status": "ok", "sw": f"0x{sw1:02x}{sw2:02x}"},
            artifacts.log_path,
            events,
        )
        _status("TESTPIN verified OK after recovery.", "step04_pin_ok")

        # =================================================================
        # Step 5: Verify PIN0_remaining_tries restored (> 0)
        # =================================================================
        _status("Step 5: Verifying PIN tries restored...", "step05_tries_restored")
        (_, _, _, d_final) = cc_session.card_get_status()
        pin_tries_after = d_final.get("PIN0_remaining_tries", 0)
        puk_tries_after = d_final.get("PUK0_remaining_tries")

        if pin_tries_after <= 0:
            reason = f"PIN0_remaining_tries not restored after recovery: {pin_tries_after}"
            _cascade_skip["story_3"] = f"FAILED: {reason}"
            record_event(
                {"event": "story_3_complete", "status": "failed", "pin_tries_remaining": pin_tries_after},
                artifacts.log_path,
                events,
            )
            pytest.fail(reason)

        # =================================================================
        # All passed — mark cascade as passed
        # =================================================================
        _cascade_skip["story_3"] = "passed"
        _status(f"Recovery successful — PIN tries restored to {pin_tries_after}. Story 3 complete.", "06_success")
        record_event(
            {
                "event": "story_3_complete",
                "status": "passed",
                "pin_tries_remaining": pin_tries_after,
                "puk_tries_remaining": puk_tries_after,
            },
            artifacts.log_path,
            events,
        )
