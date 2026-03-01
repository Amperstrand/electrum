# Satochip UI Workflow Tests

End-to-end tests for the Satochip plugin that launch real Electrum Qt wizards and interact with actual or mock Satochip cards.

## Quick Start

### Mock Mode (No Card Required)

```bash
cd /Users/macbook/src/electrum-satochip
python3 -m pytest electrum/plugins/satochip/tests/ui_workflows/ \
    --run-ui-workflows -v
```

### Real Card Mode with GUI Observation

```bash
# 1. Setup SSH tunnel to remote card reader
ssh -f -N -o ExitOnForwardFailure=yes -o StreamLocalBindUnlink=yes \
    -L "/tmp/pcscd-remote.comm:/run/pcscd/pcscd.comm" root@192.168.13.202

# 2. Run test with real card and visible GUI
export PCSCLITE_CSOCK_NAME=/tmp/pcscd-remote.comm
export SATOCHIP_OBSERVE_GUI=1
python3 -m pytest electrum/plugins/satochip/tests/ui_workflows/ \
    --run-ui-workflows --use-real-card -v
```

---

## Requirements

### Python Version

**CRITICAL**: Use `python3` (Python 3.14+), NOT `python3.11`.

- Python 3.14's pyscard is linked to Homebrew's pcsc-lite (`/usr/local/opt/pcsc-lite/lib/libpcsclite.1.dylib`) which respects `PCSCLITE_CSOCK_NAME` for remote sockets.
- Python 3.11's pyscard is linked only to macOS native PCSC.framework which **ignores** `PCSCLITE_CSOCK_NAME`.

### Dependencies

```bash
# Install Homebrew pcsc-lite
brew install pcsc-lite

# Install pyscard linked to Homebrew's pcsc-lite
python3 -m pip install pyscard

# Qt dependencies for GUI tests
python3 -m pip install pytest-qt PyQt6
```

---

## Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `PCSCLITE_CSOCK_NAME` | Path to pcscd socket (remote or local) | `/tmp/pcscd-remote.comm` |
| `SATOCHIP_OBSERVE_GUI` | Show GUI windows during tests | `1` |
| `SATOCHIP_OBSERVE_LINGER` | Seconds to keep GUI visible after test | `2` |

---

## Remote Card Reader Setup

### SSH Tunnel (One-time per session)

```bash
ssh -f -N \
    -o ExitOnForwardFailure=yes \
    -o StreamLocalBindUnlink=yes \
    -L "/tmp/pcscd-remote.comm:/run/pcscd/pcscd.comm" \
    root@192.168.13.202
```

This forwards the remote pcscd socket to `/tmp/pcscd-remote.comm` locally.

### Socket Auto-Detection

The test framework auto-detects the pcscd socket in this order:

1. `PCSCLITE_CSOCK_NAME` environment variable
2. `/tmp/pcscd-remote.comm` (SSH tunnel default)
3. `/tmp/pcscd-smoke.comm` (smoke test socket)
4. `/run/pcscd/pcscd.comm` (standard Linux location)

---

## pcsc_remote_patch.py

### Purpose

macOS's native PCSC.framework ignores `PCSCLITE_CSOCK_NAME`. The `pcsc_remote_patch.py` module monkey-patches pyscard to use Homebrew's pcsc-lite via ctypes, enabling remote socket communication.

### Location

```
Satochip-Utils/pcsc_remote_patch.py
```

### How It Works

1. Checks if `PCSCLITE_CSOCK_NAME` is set and socket exists
2. Loads `/usr/local/opt/pcsc-lite/lib/libpcsclite.1.dylib` via ctypes
3. Replaces `smartcard.System.readers()` with ctypes-based implementation
4. Provides `_RemoteReader` and `_RemoteConnection` classes that communicate via the remote socket

### Auto-Loading

The patch is automatically loaded in `conftest.py:pytest_configure()` when:
- `--use-real-card` flag is passed
- A remote socket is configured

### Manual Loading

```python
import sys
sys.path.insert(0, "/path/to/Satochip-Utils")
import pcsc_remote_patch  # Must be imported BEFORE pyscard/smartcard
```

---

## Test Files

### UI Workflow Tests (`ui_workflows/`)

| File | Description |
|------|-------------|
| `test_wallet_setup_wizard.py` | New wallet creation wizard with Satochip |
| `conftest.py` | Fixtures: `use_real_card`, `real_card_connector`, `wallet_tmp_path` |
| `mock_card.py` | `MockCardConnector` for testing without physical card |
| `ui_helpers.py` | Qt widget interaction helpers |

### User Story Tests (`../test_satochip_user_stories.py`)

End-to-end card lifecycle tests requiring physical Satochip:

| Story | Name | Card State Transition | Destructive |
|-------|------|----------------------|-------------|
| 0 | Factory Reset | Any → Blank | YES |
| 1 | Wallet Setup & Sign | Blank → Seeded | YES |
| 2 | Wrong PIN Until Block | Seeded → Blocked | YES |
| 3 | PUK Recovery | Blocked → Seeded | NO |

Run with:
```bash
python3 -m pytest electrum/plugins/satochip/tests/test_satochip_user_stories.py \
    --run-user-stories -v
```

---

## CLI Flags

| Flag | Scope | Description |
|------|-------|-------------|
| `--run-ui-workflows` | `ui_workflows/` | Enable UI workflow tests |
| `--use-real-card` | `ui_workflows/` | Use real Satochip instead of mock |
| `--run-user-stories` | `test_satochip_user_stories.py` | Enable user story tests |

---

## Screenshots and Artifacts

When `SATOCHIP_OBSERVE_GUI=1` is set:

- Screenshots are saved to `tmp_path/satochip_ui_{timestamp}/screenshots/`
- Named sequentially: `00_launch.png`, `01_step1.png`, etc.
- JSONL event log saved alongside screenshots

---

## Troubleshooting

### "No readers found" with real card

1. Verify SSH tunnel is running: `ls -la /tmp/pcscd-remote.comm`
2. Check `PCSCLITE_CSOCK_NAME` is set: `echo $PCSCLITE_CSOCK_NAME`
3. Ensure you're using `python3` (3.14+), not `python3.11`

### "SCardTransmit failed: 0x80100013"

This indicates protocol mismatch. Fixed in `pcsc_remote_patch.py` by using proper `SCARD_IO_REQUEST` structure instead of raw protocol integer.

### pcsc_remote_patch not loading

Check the path resolution in `conftest.py`:
```python
_utils_path = Path(__file__).parent.parent.parent.parent.parent.parent / "Satochip-Utils"
```

### GUI not visible

Ensure `SATOCHIP_OBSERVE_GUI=1` is exported before running pytest.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Test Process (Python 3.14)              │
├─────────────────────────────────────────────────────────────┤
│  pytest → conftest.py → pcsc_remote_patch.py (ctypes)      │
│                              ↓                              │
│                    PCSCLITE_CSOCK_NAME                      │
│                    /tmp/pcscd-remote.comm                   │
└──────────────────────────────┬──────────────────────────────┘
                               │ SSH Tunnel
                               ↓
┌─────────────────────────────────────────────────────────────┐
│              Remote Host (192.168.13.202)                    │
│  pcscd → /run/pcscd/pcscd.comm → Card Reader → Satochip    │
└─────────────────────────────────────────────────────────────┘
```

---

## Related Files

- Parent conftest: `electrum/plugins/satochip/tests/conftest.py`
- Story helpers: `electrum/plugins/satochip/tests/story_helpers.py`
- Satochip client: `electrum/plugins/satochip/satochip.py`
- Remote patch: `Satochip-Utils/pcsc_remote_patch.py`
