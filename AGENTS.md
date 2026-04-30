# AGENTS.md

## Project Overview

Electrum-Satochip: A plugin for the Electrum Bitcoin wallet that adds support for the Satochip hardware wallet (JavaCard-based smartcard). The plugin is located at `electrum/plugins/satochip/`.

## Satochip Plugin Dependency Strategy

### Current State

- **Branch `satochip-minimal`**: Inlined protocol layer (2,014 lines) using Electrum-native crypto (`electrum_ecc`, `electrum.crypto`). Only external dep: `pyscard`. 56 unit tests passing.
- **Branch `satochip-pr`**: 9 commits with inlined protocol, Qt UI, wizard integration, visual lifecycle tests.
- **Toporin's PR #9972** (active, June 2025): Uses `pysatochip==0.12.3` as external dep. 3 files. Adds 5 transitive deps (`ecdsa`, `pyaes`, `cryptography`, `pyopenssl`, `certifi`).

### Research Findings

**Electrum HW plugin patterns (6 existing plugins):**
- 4 use external deps with their own crypto (Trezor/ecdsa, ColdCard/pycoin, BitBox02/noiseprotocol, Ledger)
- 1 inlines a stripped library (Jade — removed BLE/HTTP deps)
- 1 uses only Electrum crypto (Digital Bitbox)
- No plugin monkey-patches or swaps an external library's crypto for Electrum's.
- ColdCard subclasses one method (`mitm_verify`) to replace pycoin — cleanest precedent for crypto substitution.

**Sparrow Wallet (Java) pattern:**
- `CardApi` abstract base with `SatoCardApi` (Toporin protocol) and `CkCardApi` (Coinkite/Tapsigner protocol)
- Each card type is a separate `WalletModel` enum
- Tapsigner = separate product/protocol (Coinkite), not in pysatochip
- SeedKeeper = same pysatochip protocol, different APDU set (seed management vs wallet signing)

**pysatochip crypto dependency analysis:**
- `ecdsa` — Used in `ecc.py`, `SecureChannel.py`, `CardDataParser.py`. All replaceable by `electrum_ecc`.
- `pyaes` — Used in `SecureChannel.py` only. Replaceable by `electrum.crypto.aes_encrypt_with_iv`.
- `cryptography`/`pyopenssl` — Used in `certificate_validator.py` only for X.509 chain verification. Replaceable with effort using `cryptography.x509` directly (already a transitive dep of Electrum).
- `certifi` — Used in `Satochip2FA.py` only (1 line). Trivially replaceable.

**5 bugs in pysatochip 0.12.3 fixed in our inlined code:**
1. `card_transmit` infinite loop: `while(card_present)` with no retry limit
2. `card_transmit` 0x9C21 recursion guard
3. `UID`/`UID_SHA1` not initialized in `__init__`
4. No `reader_index` parameter for multi-reader systems
5. No `_detect_protocol()` for T=0/T=1/RAW auto-detection

### Strategy Decision

**Recommended: Submit our inlined approach, offer collaboration to Toporin.**

Rationale:
1. Jade precedent: Jade inlined `jadepy/` (1,899 lines) to strip unwanted deps. Our protocol layer (2,014 lines) does the same.
2. Zero new transitive deps: Only `pyscard` needed. Toporin's approach adds 5 packages.
3. No duplicate ECC: `ecdsa` (pure Python) and `electrum_ecc` (libsecp256k1) doing the same math. pysatochip's `ecc.py` is literally a copy of Electrum's own module.
4. Bug fixes included: 5 critical bugs fixed that would need upstream pysatochip releases otherwise.
5. 65% smaller: 2,014 lines vs pysatochip's 5,478.

### Future: SeedKeeper and Tapsigner Support

- **SeedKeeper**: Same pysatochip `CardConnector`, same AID probing. Would be an extension of the satochip plugin (auxiliary seed management UI, not a signing keystore).
- **Tapsigner**: Completely different product (Coinkite), different protocol, different auth (CVC vs PIN). Would be a separate Electrum plugin (`electrum/plugins/tapsigner/`), following the same `HW_PluginBase` pattern. Not in pysatochip scope.
- **Sparrow pattern**: `CardApi` base class with `SatoCardApi` / `CkCardApi` implementations. In Electrum, the natural split is one plugin per vendor (same as Trezor vs ColdCard).

### Next Steps

1. Run full hardware test with `SATOCHIP_SKIP_RESET=0`
2. Squash commits on `satochip-pr` into clean commits for PR
3. Prepare clean PR based on `satochip-pr` branch
4. Submit to spesmilo/electrum

## IMPORTANT: No External Interaction

**NEVER submit a PR, comment on issues/PRs, or interact with any external
repository or person on behalf of the user.** This includes:
- No pushing to remote repositories
- No creating PRs on GitHub (spesmilo/electrum or any other)
- No commenting on Toporin's PR #9972 or any other issue/PR
- No contacting upstream maintainers
- The user will handle all external communication themselves

## Development Conventions

- Branch `satochip-minimal` has all development; `satochip-pr` has squashed commits for PR
- Test files ARE git-tracked
- No Java-style parens, no unused imports, no excessive logging/comments
- 2FA and SeedKeeper are OUT OF SCOPE for initial PR
- `SATOCHIP_SKIP_RESET=1` is the default for testing
- Plugin targets upstream PR-ready quality

## Lint and Typecheck

Run `flake8` with Electrum's linter settings before committing:
```
flake8 electrum/plugins/satochip/ --count --select=E,F,W,C90,B --ignore=W503 --show-source --statistics
```

## Key Files

- `electrum/plugins/satochip/client.py` — SatochipClient, run_flow(), @runs_in_hwd_thread
- `electrum/plugins/satochip/satochip.py` — Satochip_KeyStore, SatochipPlugin, _classify_reader
- `electrum/plugins/satochip/qt.py` — Satochip_Handler, Qt UI, _fetch_card_info (worker thread), show_values (GUI thread)
- `electrum/plugins/satochip/card_connector.py` — Inlined protocol, retry-limited card_transmit, _detect_protocol
- `electrum/plugins/satochip/card_data_parser.py` — Inlined parser with electrum_ecc
- `electrum/plugins/satochip/secure_channel.py` — Uses electrum.crypto.aes_encrypt_with_iv
- `electrum/plugins/satochip/tx_parser.py` — Transaction parser
- `electrum/plugins/satochip/exceptions.py` — 12 exception classes
- `electrum/plugins/satochip/tests/unit/test_unit.py` — 57 unit tests

## JavaCard Applet APDU Reference

### `card_setup` APDU (INS 0x2A) — memsize and deprecated fields

The `card_setup` APDU sends two 16-bit memory size values after the PIN data:

| Parameter | Wire name | Current value | Applet behavior |
|-----------|-----------|---------------|-----------------|
| `memsize` | `secmemsize` | 32 | Number of BIP32 cache **elements** (not bytes). Each element is `BIP32_OBJECT_SIZE` = 69 bytes. Total EEPROM = `memsize × 69`. |
| `memsize2` | `memsize` | 0x0000 | **Deprecated** — applet reads into `RFU` and discards. |

The JavaCard applet creates `Bip32ObjectManager(secmem_size, BIP32_OBJECT_SIZE, BIP32_ANTICOLLISION_LENGTH)`:
- `secmem_size` = first memsize param — max number of cached BIP32 derived keys
- `BIP32_OBJECT_SIZE` = `2 × 32 + 4 + 1` = 69 bytes per cached key
- `BIP32_ANTICOLLISION_LENGTH` = 4 bytes used as lookup hash
- Total EEPROM allocated: `secmem_size × 69` bytes (32 × 69 = 2,208 bytes with default)

The 3 ACL bytes (`create_object_ACL`, `create_key_ACL`, `create_pin_ACL`) are also **deprecated** — read into `RFU` and discarded by the applet. They remain in the APDU for backward compatibility.

**secmemsize=32 matches pysatochip's Satochip-Utils** (`Satochip-Utils/controller.py:254`). Our test card needed 256 slots due to limited EEPROM, but production Satochip cards work fine with 32.

## Upstream Electrum Import Compatibility

These imports changed in the current Electrum codebase and required fixes:

1. **`ScriptTypeNotSupported`**: Moved from `electrum.keystore` to `electrum.base_wizard`. All other HW plugins import from `base_wizard`.
2. **`convert_bip32_strpath_to_intpath`**: Renamed to `convert_bip32_path_to_list_of_uint32` in `electrum.bip32`. We alias it: `from electrum.bip32 import convert_bip32_path_to_list_of_uint32 as convert_bip32_strpath_to_intpath`.
3. **`usermessage_magic`**: Removed from `electrum.bitcoin` during ecc separation. We define `_usermessage_magic()` locally in `card_connector.py`.
4. **`var_int()` returns `str`, not `bytes`**: `electrum.bitcoin.var_int(64)` returns `'40'` (hex string). Our `_usermessage_magic` handles this with `bytes.fromhex(length)` conversion.
5. **`electrum/hw_wallet/`**: Moved from `electrum/plugins/hw_wallet/` to `electrum/hw_wallet/` in commit `6e087950c`. If the directory is empty, restore with `git checkout 6e087950c -- electrum/hw_wallet/`.
6. **`HW_PluginBase` identity**: `electrum.hw_wallet.plugin.HW_PluginBase` and `electrum.plugins.hw_wallet.plugin.HW_PluginBase` are **different classes**. `base_wizard.py` imports from `electrum.plugins.hw_wallet`. All Satochip imports must use relative imports (`from ..hw_wallet`) to match. Using absolute `from electrum.hw_wallet` causes `isinstance` assertion failures in the wizard.
7. **`__init__.py` registration**: Plugin `__init__.py` must export `registers_keystore = ('hardware', 'satochip', ...)` and `available_for = ['qt', 'cmdline']`. Without these, Electrum never discovers Satochip as a hardware wallet plugin.
8. **`ChoiceWidget`**: Imported directly from `electrum.gui.qt.util`. No fallback needed (present in upstream).
9. **`WalletWizardComponent`**: Imported directly from `electrum.gui.qt.wizard.wallet`. No fallback needed (present in upstream).

## Hardware Testing

- Card reader: OMNIKEY AG Smart Card Reader USB
- Card ISD keys: `KEY_ENC=5A9E63D03BADBC2A240FE8F534709EDF`, `KEY_MAC=7CCC1E79D64FC5FA263B8F2955282998`, `KEY_DEK=B040703EC3DE23EE8AE4CFB6D632AA80`
- Satochip AID: `5361746F43686970` (package), `5361746F4368697000` (applet instance)
- `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python` env var required for any script importing electrum
- `gp.jar` at `SatochipApplet/gp.jar` (GlobalPlatformPro v20.01.23)
- Applet v0.14-0.2: `SatochipApplet/SatoChip-v0.14-0.2.cap`
- Applet v0.12-05: `SatochipApplet/SatoChip-0.12-05.cap`
- For hardware tests requiring `memsize=0x0100`, modify the test or use the direct card_setup call

### Hardware test commands

```bash
# Reinstall applet (factory reset)
export KEY_ENC="5A9E63D03BADBC2A240FE8F534709EDF" KEY_MAC="7CCC1E79D64FC5FA263B8F2955282998" KEY_DEK="B040703EC3DE23EE8AE4CFB6D632AA80"
java -jar SatochipApplet/gp.jar --delete 5361746F43686970 --key-enc $KEY_ENC --key-mac $KEY_MAC --key-dek $KEY_DEK
sleep 1
java -jar SatochipApplet/gp.jar --install SatochipApplet/SatoChip-v0.14-0.2.cap --key-enc $KEY_ENC --key-mac $KEY_MAC --key-dek $KEY_DEK

# Run hardware tests
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python3 -m pytest electrum/plugins/satochip/tests/hardware/ -v

# Run unit tests
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python3 -m pytest electrum/plugins/satochip/tests/unit/test_unit.py -v
```

### Upstream visual lifecycle tests

Visual tests run against **upstream Electrum** at `/tmp/electrum-upstream` with PyQt6 and native macOS display. The plugin is symlinked into the upstream checkout.

```bash
# One-time setup (from repo root)
python3 -m venv /tmp/electrum-upstream/.venv
/tmp/electrum-upstream/.venv/bin/pip install -e "/tmp/electrum-upstream[gui]" pyscard pytest pytest-qt pytest-order cryptography pyobjc-framework-Quartz
ln -sf $(pwd)/electrum/plugins/satochip /tmp/electrum-upstream/electrum/plugins/satochip

# Factory reset card, then run visual lifecycle
export KEY_ENC="5A9E63D03BADBC2A240FE8F534709EDF" KEY_MAC="7CCC1E79D64FC5FA263B8F2955282998" KEY_DEK="B040703EC3DE23EE8AE4CFB6D632AA80"
java -jar SatochipApplet/gp.jar --delete 5361746F43686970 --key-enc $KEY_ENC --key-mac $KEY_MAC --key-dek $KEY_DEK
sleep 1
java -jar SatochipApplet/gp.jar --install SatochipApplet/SatoChip-v0.14-0.2.cap --key-enc $KEY_ENC --key-mac $KEY_MAC --key-dek $KEY_DEK

# Run from upstream checkout (uses native macOS display, real PyQt6, real card)
cd /tmp/electrum-upstream
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python .venv/bin/python3 -m pytest electrum/plugins/satochip/tests/visual/test_visual_lifecycle.py -v

# Output:
#   - screenshots: electrum/plugins/satochip/tests/screenshots/visual-lifecycle-YYYYMMDD-HHMMSS/
#   - storyboard (interactive HTML with mermaid diagrams): .../storyboard.html
#   - report (gallery): .../report.html + ../visual-lifecycle-report.html
```

**Architecture:**
- `RealElectrumContext` (harness.py): Boots real Electrum stack (config, daemon, plugins) with offline network
- `WizardDriver` (harness.py): Creates real `QENewWalletWizard` instances and pushes views directly via `load_next_component()`
- `capture_window_native()` (native_capture.py): Uses PyObjC Quartz to capture windows by CGWindowID; falls back to `QWidget.grab()`
- `storyboard_mermaid.py`: Generates mermaid state diagrams for storyboard HTML
- Device manager is mocked during wizard screenshots and **never restored** (prevents stale-event crashes during pytest-qt teardown)
- `@pytest.mark.qt_no_exception_capture` suppresses Qt event loop errors from wizard background threads
- `_reconnect_after_wizard()` (test_visual_lifecycle.py): Quiet secure-channel resync → full disconnect/reconnect → PIN re-verify → `cc.pin` restore
- `_snap_wizard(cc=cc_session)`: Auto-reconnects after wizard screenshots when `cc=` is provided

**Critical patterns:**
- **Qt `strt()` cannot be monkey-patched**: `QMetaObject.invokeMethod` uses Qt meta-object system, not Python MRO. Let auto-start happen, then push target view on top via `load_next_component()`.
- **PIN-blocked cards**: Do NOT pass `cc=` to `_snap_wizard()` for blocked-state screenshots (Stories 2 and 3). Reconnect is impossible and would corrupt the secure channel.
- **`card_disconnect()` clears `cc.pin`**: Must restore `cc.pin = list(TESTPIN)` after reconnect for auto-PIN-verify in `card_transmit`.
- **Mock DM not restored**: `ctx.plugins.device_manager` is shadowed with a MagicMock during wizard screenshots and intentionally never restored. This prevents daemon threads from triggering card access during pytest-qt's `pytest_runtest_teardown` event processing.
- **`time.sleep()` + `processEvents()` loops**: Used instead of `qtbot.wait()` (which causes hangs with background wizard threads).

**Key differences from local 4.3.3 tests:**
- Uses upstream's real `WalletWizardComponent` base class (wizard screenshots render with full chrome)
- Uses PyQt6 (not PyQt5)
- Uses native macOS display (`QT_QPA_PLATFORM` not set to `offscreen`)
- Wizard screenshots captured as real `QENewWalletWizard` QDialog windows with logo, title, scroll area, Back/Next buttons
- Settings dialog screenshots captured via native macOS Quartz window capture (Retina resolution)
- Screenshots are 56-80KB vs 1-42KB previously

**Mermaid diagrams in storyboard:**
- Full-width state banner at top with global state machine (FACTORY_RESET → INITIALIZED → SEEDED → PIN_BLOCKED)
- Per-story path diagrams at top of each story section
- Per-frame transition diagrams below screenshots at full content width
- Sidebar TOC with state machine overview

**Current status (all passing):**
- Story 0: Factory reset (settings → wipe → post-reset settings → setup prompt)
- Story 1: Wallet setup (init card → import seed → xpub derivation → sign message → settings)
- Story 2: Wrong PIN until block (exhaust retries → PIN blocked dialog → settings)
- Story 3: PUK recovery (blocked settings → recover dialog → PUK unblock → verify PIN)
- Runtime: ~62s for all 4 stories with `SATOCHIP_SKIP_RESET=0`
- Output: 18 screenshots + `report.html` + `storyboard.html`

**Known issues:**
- `SATOCHIP_SKIP_RESET=1` (default) means the card retains state between runs. For full lifecycle, set `SATOCHIP_SKIP_RESET=0`.
- Wizard auto-start renders `wallet_name` view briefly before target view is pushed on top. The 2s event-processing wait handles this reliably.
