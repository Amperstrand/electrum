# Satochip Manual Test Report — Happy Path with Clean Card

**Date**: 2026-02-27
**Network**: Signet
**Git commit (pre-fix)**: `40e97396ea1c5daa6ff7432883e6db971f05fcd0`
**Log source**: `~/.electrum/signet/logs/electrum_log_20260227T095415Z_78283.log`
**Wallet name**: `happypathwithcleancard`

---

## Tested User Flows

### 1. Card Setup ✅

A clean (uninitialized) Satochip card was set up through the Electrum new-wallet wizard.

| Step | Log evidence | Timestamp |
|------|-------------|-----------|
| `_setup_device()` called | line 1046 | 09:55:17 |
| Card state verified: `setup_done=False, is_seeded=False` | line 1087 | 09:55:18 |
| `card_setup` APDU sent | line 1088 | 09:55:18 |
| Setup completed successfully | line 1096 (`setup applet successfully!`) | 09:55:18 |

**Wizard flow**: `wallet_name` → `wallet_type` (standard) → `keystore_type` (hardware) → `choose_hardware_device` (Satochip) → `satochip_not_setup` → card setup executed.

### 2. Wallet Setup ✅

A new hardware wallet was created using the Satochip card with BIP39 seed on signet.

| Detail | Value |
|--------|-------|
| Wallet name | `happypathwithcleancard` |
| Wallet type | Standard |
| Keystore type | Hardware (Satochip) |
| Seed variant | BIP39 (12-word, checksum valid) |
| Derivation path | `m/84h/1h/0h` |
| Script type | `p2wpkh` (native segwit) |
| Root fingerprint | `9b10a447` |
| Card label | `Satochip 568c8d2e [PIN0_remaining_tries=5, is_seeded=True, fw=0.12-0.5]` |

**Log evidence**: Wizard completed full flow from `wallet_name` through `keystore_type` → hardware device selection → card setup → seed import → derivation path → wallet creation (lines 538–1740). Wallet file created at `~/.electrum/signet/wallets/happypathwithcleancard`.

### 3. Transaction Signing ✅

Two transactions were signed during the session:

#### Transaction A — Software-signed (line 3085)
- `Abstract_Wallet.sign_transaction` called at 09:57:25
- `Software_KeyStore.sign_transaction` executed (line 3106)
- `tx.sign() finished. is_complete=True` (line 3117)
- Completed in 0.10s
- Broadcasting status transitioned 8→9 (broadcast attempted)

#### Transaction B — Hardware-signed via Satochip card (line 3311)
- `Abstract_Wallet.sign_transaction` called at 09:58:01
- Full PSBT passed to Satochip plugin (line 3561)
- Transaction pre-hash computed: `752a53d7bc761b408a2733879cd77e4465faa845ebd30d2940bfcea93832f82c` (line 3771)
- `card_sign_transaction` APDU sent (line 3804)
- Returned successfully: `PartialTransaction` (line 3816)
- Completed in 5.76s (includes card round-trip)
- Broadcasting status set to 8 (line 3817)

### 4. Message Signing ✅

A message was signed using the Satochip card's hardware key.

| Step | Log evidence | Timestamp |
|------|-------------|-----------|
| `sign_message` called | line 3913 | 09:58:34 |
| Address: `tb1qp39pj2ezfs2sx3zukkk7nakzm0s6fhrr7cghwm` | line 3913 | 09:58:34 |
| Message: `test` | line 3913 | 09:58:34 |
| Derivation path: `m/84h/1h/0h/0/0` | line 4100 | 09:58:36 |
| `card_sign_message` APDU sent | line 4130 | 09:58:36 |
| Signature returned (65 bytes) | line 4155 | 09:58:37 |
| Completed in 3.05s | line 4155 | 09:58:37 |

---

## Bug Found During Testing

**`has_usable_connection_with_device()` NoneType crash**

When the Satochip card is removed during operation, `self.cc.cardservice` becomes `None`, causing `card_get_ATR()` to throw `'NoneType' object has no attribute 'connection'`.

- **Root cause**: No null check on `cardservice` before calling `card_get_ATR()`
- **Fix**: Added guard `if self.cc.cardservice is None: return False` in `satochip.py` (line ~334)
- **Test added**: `test_has_usable_connection_with_device_no_cardservice` in `test_satochip_plugin.py`

This bug was found in the earlier debug log (`.cursor/debug-2344d5.log`, 2 occurrences) during real-card testing.

---

## Hardware Follow-up Checklist Status

From `tests/README-satochip-testing.md`:

| # | Item | Status |
|---|------|--------|
| 1 | Verify PIN and wrong-PIN retries on real card | ⏳ Not tested (PIN was set during setup, not explicitly stress-tested) |
| 2 | Sign message with and without 2FA | ✅ Signed without 2FA; 2FA not configured |
| 3 | Sign legacy/segwit transaction | ✅ Segwit (p2wpkh) transaction signed |
| 4 | Sign Taproot transaction on v0.14+ card | ⏳ Not tested (card fw 0.12-0.5, below v0.14 threshold) |
| 5 | Confirm Taproot + 2FA rejection on-device flow | ⏳ Not tested |
| 6 | Validate settings actions: enable/disable 2FA, reset seed, set label | ⏳ Not tested |

---

## Environment

- **Electrum**: Development build from source (signet mode)
- **Card firmware**: 0.12-0.5
- **Card ID**: 568c8d2e
- **Transport**: CCID (smartcard reader)
- **OS**: macOS (darwin)
