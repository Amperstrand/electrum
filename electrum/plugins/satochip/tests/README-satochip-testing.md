# Satochip Testing Guide (No Hardware)

This directory now has mock-based tests that mirror key behaviors from `pysatochip` hardware tests, so we can validate Electrum integration before real-card testing.

## Test Modules

- `tests/test_satochip_plugin.py`
  - Client logic, keystore logic, plugin logic
  - PIN flows and error handling
  - Taproot/Schnorr gating logic
  - Label derivation/fallback logic

- `tests/test_satochip_qt_settings.py`
  - Qt settings action flows:
    - set/reset 2FA
    - reset seed
    - card label changes

## Mapping to Upstream `pysatochip` Hardware Tests

Upstream references:
- `Toporin/pysatochip/test_satochip.py`
- `Toporin/pysatochip/test_seedkeeper.py`

### Behavior Mapping

- **PIN verification and failures**
  - Upstream: PIN checks and failure status handling
  - Here: `verify_PIN()` branches tested with mocked `WrongPinError`, `PinBlockedError`, `CardNotPresentError`, `PinRequiredError`

- **BIP32 and xpub flow**
  - Upstream: BIP32 vector derivations from known seeds
  - Here: plugin path conversion and xpub assembly behavior tested with mocked card responses

- **Message signing**
  - Upstream: `card_sign_message()` with/without 2FA
  - Here: keystore message-sign path and success/failure handling tested via mocks

- **Transaction signing**
  - Upstream: card signing operations and status-word handling
  - Here:
    - ECDSA path tests for non-Taproot
    - Taproot path tests for Schnorr selection and guardrails

- **2FA challenge-response**
  - Upstream: 2FA key setup/reset and challenge workflows
  - Here: `do_challenge_response`, Qt `set_2FA`, `reset_2FA`, and `reset_seed` 2FA flows tested with mocked challenge server

- **Card label management**
  - Upstream: card label APIs
  - Here: client label priority and Qt label-change status handling tested

## What These Tests Cover Well

- Electrum-side control flow
- Error mapping/user-facing exceptions
- Version/feature gates (e.g., Taproot v0.14+ rule, 2FA incompatibility for Taproot)
- Handler/UI callback behavior

## What Still Requires Physical Card Testing

- Real APDU transport behavior and timing
- Smartcard reader/device edge cases
- Firmware-specific cryptographic outputs
- Authenticity cert chain/challenge exchange against real card keys

## Run Commands

- Only Satochip mock suite:
  - `python3 -m pytest -q tests/test_satochip_plugin.py tests/test_satochip_qt_settings.py`

- Syntax check:
  - `python3 -m py_compile tests/test_satochip_plugin.py tests/test_satochip_qt_settings.py electrum/plugins/satochip/satochip.py electrum/plugins/satochip/qt.py`

## Hardware Follow-up Checklist (When Card Arrives)

1. Verify PIN and wrong-PIN retries on real card
2. Sign message with and without 2FA
3. Sign legacy/segwit transaction
4. Sign Taproot transaction on v0.14+ card
5. Confirm Taproot + 2FA rejection on-device flow
6. Validate settings actions: enable/disable 2FA, reset seed, set label
