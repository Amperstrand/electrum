# Satochip Testing Guide

This directory contains the Satochip plugin test suite for Electrum, covering
three tiers: **unit tests** (mocked), **integration tests** (physical card),
and **destructive tests** (card-state-altering operations).

---

## Quick Start

```bash
# Tier 1: Unit tests (no hardware needed)
python3 -m pytest -v electrum/plugins/satochip/tests/test_satochip_plugin.py

# Tier 2: Integration tests (requires card via pcscd)
PCSCLITE_CSOCK_NAME=/tmp/pcscd-remote.comm \
DYLD_LIBRARY_PATH=/tmp:$DYLD_LIBRARY_PATH \
python3 -m pytest -v electrum/plugins/satochip/tests/test_satochip_integration.py -s

# Tier 3: Destructive tests (card setup, PIN exhaustion, etc.)
PCSCLITE_CSOCK_NAME=/tmp/pcscd-remote.comm \
DYLD_LIBRARY_PATH=/tmp:$DYLD_LIBRARY_PATH \
SATOCHIP_OBSERVE_GUI=1 \
python3 -m pytest -v electrum/plugins/satochip/tests/test_satochip_integration.py \
  --allow-destructive-card-tests -s

# Tier 4: User story lifecycle suite (ordered, requires card + runner script)
./scripts/run_user_stories.sh
```

---

## Test Tiers

### Tier 1: Unit Tests (`test_satochip_plugin.py`)

86 mock-based tests covering Electrum-side logic with no hardware:

- **Client logic** — PIN flows, error mapping, label derivation, timeout handling
- **Keystore** — message signing, transaction signing (ECDSA + Schnorr), 2FA paths
- **Plugin** — device detection, wizard entry points, xpub retrieval, factory reset
- **Edge cases** — card-not-present, PIN blocked, preimage mismatch, coinbase rejection

```bash
python3 -m pytest -v electrum/plugins/satochip/tests/test_satochip_plugin.py -s
```

### Tier 2: Integration Tests (`test_satochip_integration.py`)

Hardware-in-the-loop tests against a physical Satochip card. Auto-skipped if no
pcscd socket is detected. Read-only operations that don't alter card state.

Markers:
- `@pytest.mark.integration` — requires pcscd socket
- `@pytest.mark.requires_card` — requires card present in reader

```bash
PCSCLITE_CSOCK_NAME=/tmp/pcscd-remote.comm \
DYLD_LIBRARY_PATH=/tmp:$DYLD_LIBRARY_PATH \
python3 -m pytest -v electrum/plugins/satochip/tests/test_satochip_integration.py -s
```

### Tier 3: Destructive Tests (opt-in)

Tests that modify card state (PIN exhaustion, card setup, seed import). Require
the `--allow-destructive-card-tests` CLI flag. **These operations cannot be
undone without a factory reset.**

Marker: `@pytest.mark.destructive_card`

Current destructive test classes:
- **`TestPinBlockWorkflow`** — Enters wrong PIN 5 times, observes `WrongPinError` →
  `PinBlockedError` progression, attempts PUK recovery.
  ⚠ Requires card set up with known `TESTPUK = b'12345678'`.
- **`TestWalletSetupAndSign`** — Full lifecycle: blank card → setup → seed import →
  xpub derivation → message signing → hash signing.
  Uses mnemonic: `hungry type amount worth cloth breeze capable absent more wear manual audit`

```bash
PCSCLITE_CSOCK_NAME=/tmp/pcscd-remote.comm \
DYLD_LIBRARY_PATH=/tmp:$DYLD_LIBRARY_PATH \
SATOCHIP_OBSERVE_GUI=1 \
python3 -m pytest -v electrum/plugins/satochip/tests/test_satochip_integration.py::TestWalletSetupAndSign \
  --allow-destructive-card-tests -s
```

---

### Tier 4: User Story Lifecycle Suite (`test_satochip_user_stories.py`)

Ordered, hardware-in-the-loop user story tests that exercise the card's full
lifecycle in dependency order. Requires `--run-user-stories` and
`--allow-destructive-card-tests` flags plus a physical card.

See [User Story Test Suite](#user-story-test-suite) below for full details.

---

## Remote Card Reader Setup (SSH Tunnel)

The Satochip card reader is connected to a remote machine (e.g., Raspberry Pi)
and accessed via an SSH tunnel to the pcscd Unix socket.

### 1. Set up the SSH tunnel

```bash
# One-shot tunnel to the remote pcscd daemon
ssh -f -N -L /tmp/pcscd-remote.comm:/run/pcscd/pcscd.comm root@192.168.13.202
```

Or use the provided script:

```bash
./scripts/setup_remote_pcscd.sh
```

### 2. Verify connectivity

```bash
PCSCLITE_CSOCK_NAME=/tmp/pcscd-remote.comm \
DYLD_LIBRARY_PATH=/tmp:$DYLD_LIBRARY_PATH \
python3 -c "
from smartcard.System import readers
r = readers()
print(f'Readers: {len(r)}')
for reader in r:
    print(f'  {reader}')
    conn = reader.createConnection()
    conn.connect()
    print(f'    Card present: YES')
    conn.disconnect()
"
```

### 3. Socket auto-detection

`conftest.py` automatically detects pcscd sockets in this order:
1. `PCSCLITE_CSOCK_NAME` environment variable
2. `/tmp/pcscd-smoke.comm`
3. `/run/pcscd/pcscd.comm`

Integration tests are skipped if no socket is found.

---

## Safety Gates

| Gate | Mechanism | Purpose |
|---|---|---|
| No pcscd socket | `has_remote_pcscd()` → `pytest.skip()` | Skip integration tests without hardware |
| No card in reader | `can_detect_card()` → `pytest.skip()` | Skip if reader present but card absent |
| Destructive ops | `--allow-destructive-card-tests` flag | Prevent accidental card state changes |
| PUK preflight | `TestPinBlockWorkflow` checks `PUK0_remaining_tries` | Skip if PUK already exhausted |

---

## GUI Observer Mode

Set `SATOCHIP_OBSERVE_GUI=1` to enable a live Qt status window during tests.
This allows you to:

- Watch test progress in real time as a user would
- Capture screenshots at each test step
- Spot visual glitches not caught in headless mode

Screenshots are saved to the test's artifact directory under `screenshots/`.

```bash
SATOCHIP_OBSERVE_GUI=1 python3 -m pytest -v ... -s
```

---

## Artifacts

Each destructive test class produces artifacts in `tmp_path`:

```
<tmp_path>/
  <test_name>/
    <test_name>.jsonl          # Timestamped event log
    screenshots/
      step01_check_blank.png   # Screenshot per step
      step02_card_setup.png
      step03_import_seed.png
      ...
```

### JSONL Event Log

Each line is a JSON object with:
- `event` — event type (e.g., `card_setup`, `seed_import`, `message_sign`)
- `step` — sequential step number
- `timestamp` — Unix timestamp
- `status` — `"ok"` or error details
- Additional fields per event type (xpubs, signatures, SW codes, etc.)

---

## User Stories

### User Story 1: Wrong PIN Until Card Block

**Class:** `TestPinBlockWorkflow`

Tests the scenario where a user enters the wrong PIN repeatedly until the card
blocks, then recovers with the PUK code.

**Artifacts:** JSONL log showing PIN attempt → WrongPinError → PinBlockedError
progression, plus GUI screenshots.

### User Story 2: New Wallet Setup & Message Signing

**Class:** `TestWalletSetupAndSign`

Tests the full happy path: factory-reset card → card setup (PIN/PUK) → seed
import from BIP-39 mnemonic → xpub derivation at 3 BIP paths → message signing
→ ECDSA hash signing.

**Artifacts:** JSONL log with xpubs, signatures, and cross-check results, plus
GUI screenshots at each step.

---

## User Story Test Suite

The user story suite in `test_satochip_user_stories.py` tests the card's full
lifecycle as an ordered sequence. Each story runs in a fixed order and depends
on the previous story leaving the card in a known, well-defined state. This
mirrors how a real user interacts with the card: setup, normal use, PIN
exhaustion, and PUK recovery.

### Card State Machine

```
FACTORY_RESET ──(card_setup)──▶ INITIALIZED ──(import_seed)──▶ SEEDED
     ▲                                                            │
     │                                                    (5 wrong PINs)
     │                                                            ▼
     └──────────(GP factory reset)──────── SEEDED ◀──(PUK recovery)── PIN_BLOCKED
```

### Story Order

| Order | Story | Class | Precondition | Postcondition |
|-------|-------|-------|-------------|---------------|
| 0 | Factory Reset | `TestStory0FactoryReset` | Any state | FACTORY_RESET |
| 1 | Wallet Setup & Sign | `TestStory1WalletSetupAndSign` | FACTORY_RESET | SEEDED |
| 2 | Wrong PIN Until Block | `TestStory2WrongPinUntilBlock` | SEEDED | PIN_BLOCKED |
| 3 | PUK Recovery & Verify | `TestStory3PukRecoveryAndVerify` | PIN_BLOCKED | SEEDED |

### How to Run

```bash
# Full suite with GUI observer
./scripts/run_user_stories.sh

# Headless (no GUI window)
./scripts/run_user_stories.sh --headless

# Single story only
./scripts/run_user_stories.sh --story 2

# Skip factory reset (if card already in known state)
./scripts/run_user_stories.sh --no-reset

# Or run directly with pytest:
PCSCLITE_CSOCK_NAME=/tmp/pcscd-remote.comm \
DYLD_LIBRARY_PATH=/tmp:$DYLD_LIBRARY_PATH \
SATOCHIP_OBSERVE_GUI=1 \
python3 -m pytest -v electrum/plugins/satochip/tests/test_satochip_user_stories.py \
  --run-user-stories --allow-destructive-card-tests -s
```

### Cascade Skip Pattern

If a story fails, all subsequent stories are automatically skipped. This
prevents destructive operations on a card in an unknown state. The mechanism
is a module-level `_cascade_skip` dict: each story sets
`_cascade_skip["story_N"] = "passed"` on success or
`_cascade_skip["story_N"] = "FAILED: reason"` on failure. The next story
checks the dict at its start and calls `pytest.skip()` if the prerequisite
didn't pass.

⚠ **Never run Story 2 or Story 3 in isolation** without first confirming the
card is in the expected precondition state.

### Artifacts

Each story produces a dedicated artifact directory under pytest's `tmp_path`:

```
<tmp_path>/
  story-1-wallet-setup-and-sign/
    story-1-wallet-setup-and-sign.jsonl   # Timestamped event log
    screenshots/
      step01_check_blank.png
      step02_card_setup.png
      step03_import_seed.png
      ...
  story-2-wrong-pin-until-block/
    story-2-wrong-pin-until-block.jsonl
    screenshots/
      ...
```

JSONL event fields match the format described in the [Artifacts](#artifacts) section above.

### How to Add a New Story

1. Create a new test class in `test_satochip_user_stories.py` following the
   existing class structure.
2. Add `@pytest.mark.order(N)` (next number in sequence) to the class.
3. At the start of the test method, check `_cascade_skip` for the prerequisite
   story and call `pytest.skip()` if it didn't pass.
4. Set up artifacts with `StoryArtifacts` and the observer with
   `create_gui_observer()` from `story_helpers.py`.
5. Use `set_status()` and `record_event()` throughout for logging and
   screenshots.
6. Call `require_card_state()` to assert (and skip) based on card state.
7. On success, set `_cascade_skip["story_N"] = "passed"`. On any failure
   path, set `_cascade_skip["story_N"] = "FAILED: reason"` before calling
   `pytest.fail()`.
8. Update the Story Order table above and the [Adding New User Stories](#adding-new-user-stories)
   section.

---

## Test Constants

| Constant | Value | Usage |
|---|---|---|
| `TESTPIN` | `b'123456'` | Default PIN for test card |
| `TESTPUK` | `b'12345678'` | Default PUK for test card |
| `HUNGRY_MNEMONIC` | `hungry type amount worth cloth breeze capable absent more wear manual audit` | BIP-39 seed for wallet setup test |
| `pin_tries_0` | `0x05` | 5 wrong PIN attempts before block |
| `ublk_tries_0` | `0x01` | 1 wrong PUK attempt before permanent brick |

---

## Adding New User Stories

1. Create a new test class in `test_satochip_user_stories.py` (for ordered lifecycle stories)
   or `test_satochip_integration.py` (for standalone destructive tests)
2. Mark with `@pytest.mark.destructive_card` if it changes card state
3. Use the `_set_status()` / `_record()` pattern for logging and screenshots
4. Document the user story in this README
5. Run with `--allow-destructive-card-tests` and `SATOCHIP_OBSERVE_GUI=1`

---

## Mapping to Upstream `pysatochip` Hardware Tests

Upstream references:
- `Toporin/pysatochip/test_satochip.py`
- `Toporin/pysatochip/test_seedkeeper.py`

| Behavior | Upstream | Here |
|---|---|---|
| PIN verification & failures | PIN checks and failure status | `verify_PIN()` branches + `TestPinBlockWorkflow` |
| BIP32 / xpub derivation | BIP32 vector derivations | Plugin path conversion + `TestWalletSetupAndSign` xpub cross-check |
| Message signing | `card_sign_message()` ± 2FA | Keystore sign path + `TestWalletSetupAndSign` live signing |
| Transaction signing | Card signing + status-word handling | ECDSA/Schnorr paths in unit tests + `TestWalletSetupAndSign` hash signing |
| Card setup | `card_setup()` with PIN/PUK | `TestWalletSetupAndSign` step 2 |
| 2FA challenge-response | 2FA key setup/reset | `do_challenge_response` + Qt 2FA flows (mock) |
| Card label management | Card label APIs | Client label priority + Qt label-change (mock) |

---

## Factory Reset Approaches

Returning a Satochip to factory state (blank card, `setup_done=False`) is the
precondition for Story 0 and any fresh wallet test. Two approaches exist, each
suited to a different context.

| Approach | Mechanism | Card type | Physical interaction | Used by |
|----------|-----------|-----------|---------------------|---------|
| APDU-based | `card_reset_factory_signal()` via pysatochip | Any card (production or dev) | Required (~4 remove/reinsert cycles) | Story 0 (`TestStory0FactoryReset`) |
| GP-based | GlobalPlatformPro via Podman/SSH | Dev/unlocked cards only | None (fully automated) | `scripts/remote_card_audit_reset.py` (standalone utility) |

---

### APDU-Based Reset (Story 0)

Story 0 resets the card using a direct APDU sequence sent through pysatochip.
No GP access or special key material is needed, so it works on production cards
as well as development cards.

**How it works:**

1. `card_reset_factory_signal()` sends APDU `[0xB0, 0xFF, 0x00, 0x00, 0x00]` to
   the card. This increments the card's internal reset counter.
2. The card reports how many signals are still needed before the reset fires
   (typically 4 total, dynamic per card).
3. Between each APDU signal, the card **must be physically removed and
   reinserted** into the reader. Software power cycling (`SCARD_UNPOWER_CARD`)
   was tested and does **not** work — both approaches returned `0xFFFF`.
   Physical removal is required.
4. After reinsertion, a 2-second delay lets the pysatochip `CardMonitor` observer
   complete initialization before the next signal is sent.
5. Once all signals are received, the card resets to `setup_done=False`.

A `mode_factory_reset` flag is set during the process to prevent the observer
from interfering with the signal loop.

**Run Story 0:**

```bash
# With GUI observer (required — user sees the step counter)
SATOCHIP_OBSERVE_GUI=1 ./scripts/run_user_stories.sh --story 0
```

**Physical interaction:**

The GUI window shows a live step counter:
```
Step N/M: Remove card and reinsert to continue...
```

No button clicks are needed. Card presence is auto-detected by pysatochip's
`CardMonitor`. Remove the card, wait for the prompt to update, then reinsert.
Repeat until all steps complete (~4 cycles).

⚠ **`SATOCHIP_OBSERVE_GUI=1` is mandatory for Story 0.** Without the GUI,
there is no way to see the step counter or confirm the card is ready for the
next removal.

⚠ **`--headless` automatically skips Story 0.** Passing `--headless` to
`run_user_stories.sh` implies `--no-reset`, so the factory reset story is
skipped entirely. Use headless mode only when the card is already in a known
blank state.

---

### GP-Based Reset (Dev Utility)

`scripts/remote_card_audit_reset.py` is a standalone development utility that
resets a card using GlobalPlatformPro (GP). It connects to the remote card
reader via a Podman VM and SSH tunnel, downloads `gp.jar` if needed, and
issues a GP factory reset command directly.

**Requirements:**

- Podman VM running and accessible (`podman machine ssh regtest`)
- SSH tunnel to the pcscd socket on the remote host (`192.168.13.202`)
- Card must be **unlocked** (dev card with known GP keys). Production cards
  with locked GP keys cannot be reset this way.
- `gp.jar` from GlobalPlatformPro (downloaded automatically on first run)

**Run the GP reset utility:**

```bash
python3 scripts/remote_card_audit_reset.py
```

No physical card interaction is needed. The script handles everything over the
SSH/Podman tunnel. Useful for bulk resets during development when you need to
cycle a card through many test runs without touching the reader.

⚠ **This utility is NOT part of the user story test suite.** It's a separate
development tool. The test suite always uses the APDU-based approach (Story 0)
for factory resets, which works on any card type.

---

### Choosing an Approach

| Situation | Use |
|-----------|-----|
| Running the full user story suite | APDU-based (Story 0) — automatic |
| Card is production/locked | APDU-based only |
| Bulk dev resets, no physical access needed | GP-based (`remote_card_audit_reset.py`) |
| Card already blank, skip reset | `--no-reset` or `--headless` |
