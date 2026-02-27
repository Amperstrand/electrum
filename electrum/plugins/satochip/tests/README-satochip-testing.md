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

1. Create a new test class in `test_satochip_integration.py`
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
