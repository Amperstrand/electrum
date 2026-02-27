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

import pytest
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
# Story 0 — Factory Reset
# ---------------------------------------------------------------------------
@pytest.mark.order(0)
class TestStory0FactoryReset:
    """
    Story 0: Factory Reset

    Precondition:  Card may be in any state (FACTORY_RESET, INITIALIZED, SEEDED,
                   or PIN_BLOCKED).
    Action:        Issue a factory-reset command to return the card to a clean
                   FACTORY_RESET state.  No PIN is required for this operation
                   when the card is already in PIN_BLOCKED state; otherwise the
                   current PIN (TESTPIN) is used.
    Postcondition: Card is in FACTORY_RESET state — setup_done=False,
                   is_seeded=False, PIN tries restored to maximum.

    ⚠️  SAFETY: This story permanently erases all card data.  Only run against
    a test card initialised by this suite (TESTPIN/TESTPUK known).
    """

    def test_placeholder(self):
        pass


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

    def test_placeholder(self):
        pass


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

    def test_placeholder(self):
        pass


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

    def test_placeholder(self):
        pass
