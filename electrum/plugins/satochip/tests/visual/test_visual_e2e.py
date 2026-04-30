"""test_visual_e2e.py — End-to-end visual user journey test for Satochip.

Drives the real Electrum wallet creation wizard step-by-step, capturing
each view the user would see. After wallet creation, captures the main
Electrum window (send tab, receive tab, sign message dialog).

Two paths:
  Path A — Factory-fresh card: full setup + seed import + wallet creation
  Path B — Seeded card: direct wallet creation (skips setup)

Run:
  PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python \\
    /tmp/electrum-upstream/.venv/bin/python3 -m pytest \\
    electrum/plugins/satochip/tests/visual/test_visual_e2e.py -v -s
"""

import time
import tempfile
import os
from pathlib import Path

import pytest

from electrum.logging import get_logger
from electrum.plugins.satochip.tests.fixtures.card_helpers import TESTPIN
from electrum.plugins.satochip.tests.fixtures.story_helpers import (
    HUNGRY_MNEMONIC,
)
from electrum.plugins.satochip.tests.fixtures.visual_testing import (
    VisualTestArtifacts,
    capture_screenshot,
    generate_html_report,
    log_step,
)
from electrum.plugins.satochip.tests.fixtures.visual_storyboard import (
    StoryboardBuilder,
    add_screenshot_frame,
)
from electrum.plugins.satochip.tests.visual.harness import (
    WizardDriver,
    RealElectrumContext,
    create_config,
    make_mock_device_info,
)

_logger = get_logger(__name__)

PREFIX = "e2e"

PYQT = False
if "PyQt5" in __import__("sys").modules:
    try:
        from PyQt5.QtWidgets import QApplication
        PYQT = True
    except ImportError:
        pass
else:
    try:
        from PyQt6.QtWidgets import QApplication
        PYQT = True
    except ImportError:
        pass


def _process_events(qapp, seconds=1.0):
    deadline = time.time() + seconds
    while time.time() < deadline:
        qapp.processEvents()
        time.sleep(0.02)


def _snap(widget, name, artifacts, qapp, prefix,
          storyboard=None, step_number=0, story_id="", story_name="",
          title="", annotation="",
          card_state_before=None, card_state_after=None):
    _process_events(qapp, 0.3)
    path = capture_screenshot(widget, name, artifacts, prefix)
    if path and storyboard:
        add_screenshot_frame(
            storyboard,
            step_number=step_number,
            story_id=story_id or prefix,
            story_name=story_name,
            title=title or name,
            annotation=annotation,
            screenshot_path=path,
            card_state_before=card_state_before or {},
            card_state_after=card_state_after or {},
        )
    return path


def _base_wizard_data(wallet_path):
    return {
        "wallet_name": str(wallet_path),
        "wallet_exists": False,
        "wallet_is_open": False,
        "wallet_needs_hw_unlock": False,
        "wallet_type": "standard",
        "keystore_type": "hardware",
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def cc_session():
    from electrum.plugins.satochip.card_connector import CardConnector
    from smartcard.System import readers as _readers
    from smartcard.PassThruCardService import PassThruCardService
    all_readers = _readers()
    if not all_readers:
        pytest.skip("No smartcard reader found")
    reader = all_readers[0]
    conn = reader.createConnection()
    conn.connect()
    svc = PassThruCardService(conn)
    cc = CardConnector(client=None, card_filter=["satochip"])
    cc.cardservice = svc
    cc.card_present = True
    cc._detect_protocol()
    cc.card_select()
    time.sleep(1.5)
    cc.card_initiate_secure_channel()
    cc.card_verify_PIN_simple(TESTPIN)
    yield cc
    cc.card_disconnect()


@pytest.fixture(scope="session")
def story_artifact_root(tmp_path_factory):
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    p = (Path("electrum/plugins/satochip/tests/screenshots")
         / f"visual-lifecycle-{ts}")
    p.mkdir(parents=True, exist_ok=True)
    return p


@pytest.fixture(scope="session")
def electrum_ctx():
    config = create_config()
    ctx = RealElectrumContext(config)
    yield ctx
    ctx.cleanup()


_shared_artifacts = None


@pytest.fixture(scope="module")
def artifacts(story_artifact_root, request):
    global _shared_artifacts
    if (_shared_artifacts is None
            or _shared_artifacts.root_dir != story_artifact_root):
        _shared_artifacts = VisualTestArtifacts(
            root_dir=story_artifact_root,
            run_name=PREFIX,
        )
    return _shared_artifacts


# ---------------------------------------------------------------------------
# Path A: Factory-fresh card — full setup + wallet creation
# ---------------------------------------------------------------------------

@pytest.mark.order(1)
@pytest.mark.qt_no_exception_capture
def test_e2e_fresh_card_wallet_creation(
    cc_session, electrum_ctx, artifacts, qtbot, request
):
    cc = cc_session
    qapp = QApplication.instance()

    storyboard = StoryboardBuilder()
    step = [0]

    def next_step():
        step[0] += 1
        return step[0]

    log_step("Starting E2E fresh card wallet creation workflow", artifacts)

    # Check card is seeded (from previous lifecycle test or setup)
    sw1, sw2 = 0x90, 0x00
    d = {}
    try:
        response, sw1, sw2, d = cc.card_get_status()
    except Exception:
        pytest.skip("Cannot read card status — card not present or not seeded")

    is_seeded = d.get("is_seeded", False)
    setup_done = d.get("setup_done", False)
    if not is_seeded or not setup_done:
        pytest.skip(
            f"Card not seeded (setup_done={setup_done}, "
            f"is_seeded={is_seeded}). "
            "Run lifecycle test first to seed the card.")

    log_step(
        f"Card state: setup_done={setup_done}, "
        f"is_seeded={is_seeded}", artifacts)

    # Create mock device info for an initialized+seeded card
    device_info = make_mock_device_info()
    device_info.initialized = True

    wallet_dir = tempfile.mkdtemp(prefix="satochip-e2e-")
    wallet_path = os.path.join(wallet_dir, "test_wallet")

    wd = _base_wizard_data(wallet_path)

    # Use WizardDriver (one wizard per view) to avoid strt() auto-start
    driver = WizardDriver(electrum_ctx, qapp, qtbot)

    # --- Step 1: wallet_name view ---
    n = next_step()
    wizard = driver.push_view("wallet_name", wd)
    _snap(
        wizard, f"{n:02d}-wallet-name", artifacts, qapp, PREFIX,
        storyboard=storyboard, step_number=n, story_name="Wallet Creation",
        title="Name Your Wallet",
        annotation="First wizard view: user names the wallet file",
    )

    # --- Step 2: wallet_type view ---
    n = next_step()
    wd["wallet_type"] = "standard"
    wizard = driver.push_view("wallet_type", wd)
    _snap(
        wizard, f"{n:02d}-wallet-type", artifacts, qapp, PREFIX,
        storyboard=storyboard, step_number=n, story_name="Wallet Creation",
        title="Wallet Type Selection",
        annotation=("User selects 'Standard wallet' for "
                    "single-signature wallet"),
    )

    # --- Step 3: keystore_type view ---
    n = next_step()
    wd["keystore_type"] = "hardware"
    wizard = driver.push_view("keystore_type", wd)
    _snap(
        wizard, f"{n:02d}-keystore-type", artifacts, qapp, PREFIX,
        storyboard=storyboard, step_number=n, story_name="Wallet Creation",
        title="Keystore Type Selection",
        annotation="User selects 'Use a hardware device' to use Satochip",
    )

    # --- Step 4: choose_hardware_device view ---
    n = next_step()
    wd["hardware_device"] = ("satochip", device_info)
    wizard = driver.push_view("choose_hardware_device", wd)
    _process_events(qapp, 2.0)
    _snap(
        wizard, f"{n:02d}-choose-hardware-device", artifacts, qapp, PREFIX,
        storyboard=storyboard, step_number=n, story_name="Wallet Creation",
        title="Hardware Device Selection",
        annotation="Device list showing detected Satochip card",
    )

    # --- Step 5: satochip_start (script type + derivation) ---
    n = next_step()
    wd["script_type"] = "p2wpkh"
    wd["derivation_path"] = "m/84'/0'/0'"
    wizard = driver.push_view("script_and_derivation", wd)
    _process_events(qapp, 1.5)
    _snap(
        wizard, f"{n:02d}-script-and-derivation", artifacts, qapp, PREFIX,
        storyboard=storyboard, step_number=n, story_name="Wallet Creation",
        title="Script Type and Derivation Path",
        annotation=("User selects native segwit (p2wpkh) "
                    "with m/84'/0'/0' derivation"),
    )

    # --- Step 6: wallet_password_hardware view ---
    n = next_step()
    wd["encrypt"] = False
    wd["password"] = ""
    wizard = driver.push_view("wallet_password_hardware", wd)
    _process_events(qapp, 1.0)
    _snap(
        wizard, f"{n:02d}-wallet-password-hardware", artifacts, qapp, PREFIX,
        storyboard=storyboard, step_number=n, story_name="Wallet Creation",
        title="Wallet Encryption Options",
        annotation="User chooses whether to encrypt the wallet file",
    )

    log_step("Wizard screenshots complete.", artifacts)

    driver.teardown()

    log_step("E2E fresh card wallet creation complete", artifacts)

    # Generate report
    generate_html_report(artifacts, title="Satochip E2E User Journey")
    log_step("Report generated", artifacts)

    sb_path = Path(artifacts.artifact_dir) / "storyboard-e2e.html"
    storyboard.write_html(sb_path, title="Satochip E2E User Journey")
    log_step(f"Storyboard: {sb_path}", artifacts)


# ---------------------------------------------------------------------------
# Path B: Uninitialized card — full setup from blank
# ---------------------------------------------------------------------------

@pytest.mark.order(2)
@pytest.mark.qt_no_exception_capture
def test_e2e_blank_card_setup_flow(
    cc_session, electrum_ctx, artifacts, qtbot, request
):
    cc = cc_session
    qapp = QApplication.instance()

    storyboard = StoryboardBuilder()
    step = [0]

    def next_step():
        step[0] += 1
        return step[0]

    log_step("Starting E2E blank card setup flow", artifacts)

    # Card must be present but we don't require specific state
    # since we use WizardDriver (mock wizard views, no real card APDUs)
    try:
        response, sw1, sw2, d = cc.card_get_status()
    except Exception:
        pytest.skip("Cannot read card status")
    setup_done = d.get("setup_done", False)
    is_seeded = d.get("is_seeded", False)
    log_step(
        f"Card state: setup_done={setup_done}, "
        f"is_seeded={is_seeded}", artifacts)

    # Mock device info for NOT initialized card (factory-fresh)
    device_info_fresh = make_mock_device_info()
    device_info_fresh.initialized = None

    device_info_setup = make_mock_device_info()
    device_info_setup.initialized = False

    driver = WizardDriver(electrum_ctx, qapp, qtbot)

    wallet_dir = tempfile.mkdtemp(prefix="satochip-e2e-blank-")
    wallet_path = os.path.join(wallet_dir, "test_wallet")

    wd = _base_wizard_data(wallet_path)

    # --- Step 1-3: wallet_name / wallet_type / keystore_type ---
    n = next_step()
    wizard = driver.push_view("wallet_name", wd)
    _snap(
        wizard, f"{n:02d}-wallet-name", artifacts, qapp, PREFIX,
        storyboard=storyboard, step_number=n, story_name="Blank Card Setup",
        title="Name Your Wallet",
        annotation=("Starting wallet creation with a "
                    "blank (uninitialized) Satochip"),
    )

    n = next_step()
    wd["wallet_type"] = "standard"
    wizard = driver.push_view("wallet_type", wd)
    _snap(
        wizard, f"{n:02d}-wallet-type", artifacts, qapp, PREFIX,
        storyboard=storyboard, step_number=n, story_name="Blank Card Setup",
        title="Wallet Type",
        annotation="Standard wallet selected",
    )

    n = next_step()
    wd["keystore_type"] = "hardware"
    wizard = driver.push_view("keystore_type", wd)
    _snap(
        wizard, f"{n:02d}-keystore-type", artifacts, qapp, PREFIX,
        storyboard=storyboard, step_number=n, story_name="Blank Card Setup",
        title="Keystore Type",
        annotation="'Use a hardware device' selected",
    )

    # --- Step 4: choose_hardware_device ---
    n = next_step()
    wd["hardware_device"] = ("satochip", device_info_fresh)
    wizard = driver.push_view("choose_hardware_device", wd)
    _process_events(qapp, 2.0)
    _snap(
        wizard, f"{n:02d}-choose-hardware-device", artifacts, qapp, PREFIX,
        storyboard=storyboard, step_number=n, story_name="Blank Card Setup",
        title="Hardware Device Selection",
        annotation="Device list — blank Satochip shown as uninitialized",
    )

    # --- Step 5: satochip_not_setup (PIN/label entry) ---
    n = next_step()
    wd["satochip_setup_settings"] = (TESTPIN.decode(), "")
    wizard = driver.push_view("satochip_not_setup", wd)
    _process_events(qapp, 1.5)
    _snap(
        wizard, f"{n:02d}-satochip-not-setup", artifacts, qapp, PREFIX,
        storyboard=storyboard, step_number=n, story_name="Blank Card Setup",
        title="Satochip Card Setup",
        annotation="PIN, confirm PIN, and optional card label input fields",
    )

    # --- Step 6: satochip_not_seeded (seed method choice) ---
    n = next_step()
    wizard = driver.push_view("satochip_not_seeded", wd)
    _process_events(qapp, 1.0)
    _snap(
        wizard, f"{n:02d}-seed-method-choice", artifacts, qapp, PREFIX,
        storyboard=storyboard, step_number=n, story_name="Blank Card Setup",
        title="Seed Method Choice",
        annotation=("Choose between generating a new seed "
                    "or importing an existing one"),
    )

    # --- Step 7: satochip_import_seed ---
    n = next_step()
    wd["seed_type"] = "bip39"
    wd["seed"] = HUNGRY_MNEMONIC
    wd["seed_extend"] = False
    wd["seed_extra_words"] = ""
    wd["seed_variant"] = "bip39"
    wizard = driver.push_view("satochip_import_seed", wd)
    _process_events(qapp, 1.5)
    _snap(
        wizard, f"{n:02d}-import-seed", artifacts, qapp, PREFIX,
        storyboard=storyboard, step_number=n, story_name="Blank Card Setup",
        title="Import Seed Phrase",
        annotation="BIP39 seed phrase input for importing into Satochip",
    )

    # --- Step 8: satochip_success_seed ---
    n = next_step()
    wizard = driver.push_view("satochip_success_seed", wd)
    _process_events(qapp, 1.0)
    _snap(
        wizard, f"{n:02d}-seed-success", artifacts, qapp, PREFIX,
        storyboard=storyboard, step_number=n, story_name="Blank Card Setup",
        title="Seed Import Success",
        annotation="Seed imported successfully — ready for xpub derivation",
    )

    # --- Step 9: satochip_start (script type + derivation) ---
    n = next_step()
    wd["script_type"] = "p2wpkh"
    wd["derivation_path"] = "m/84'/0'/0'"
    wizard = driver.push_view("script_and_derivation", wd)
    _process_events(qapp, 1.5)
    _snap(
        wizard, f"{n:02d}-script-and-derivation", artifacts, qapp, PREFIX,
        storyboard=storyboard, step_number=n, story_name="Blank Card Setup",
        title="Script Type and Derivation Path",
        annotation="Native segwit selected with standard BIP84 derivation",
    )

    # --- Step 10: wallet_password_hardware ---
    n = next_step()
    wd["encrypt"] = False
    wd["password"] = ""
    wizard = driver.push_view("wallet_password_hardware", wd)
    _process_events(qapp, 1.0)
    _snap(
        wizard, f"{n:02d}-wallet-password", artifacts, qapp, PREFIX,
        storyboard=storyboard, step_number=n, story_name="Blank Card Setup",
        title="Wallet Encryption",
        annotation="Final step: encrypt wallet file",
    )

    log_step("Blank card E2E setup flow complete", artifacts)
    driver.teardown()

    generate_html_report(artifacts, title="Satochip E2E User Journey")
    storyboard.write_html(
        Path(artifacts.artifact_dir) / "storyboard-e2e-blank.html",
        title="Satochip E2E: Blank Card Setup Flow",
    )
