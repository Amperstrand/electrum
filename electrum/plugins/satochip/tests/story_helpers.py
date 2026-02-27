"""
story_helpers.py — Shared helpers for Satochip user-story integration tests.

Extracted from the duplicated patterns in TestPinBlockWorkflow and
TestWalletSetupAndSign in test_satochip_integration.py.

This module is standalone: it does NOT import from test_satochip_integration.py
and does NOT import optional dependencies (PyQt6, pysatochip) at module level.
"""

import json
import os
import time
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# PIN used to initialize the test card via card_setup().
# A short, memorable value so tests can be re-run easily.
# WARNING: NEVER use on a card holding real funds.
TESTPIN = b'123456'

# A random PUK (unblock code) stored during card_setup but not actually used
# in these tests — pysatochip requires a non-empty value at setup time.
TESTPUK = b'12345678'

# Well-known BIP39 test mnemonic (12 words, all from BIP39 word list).
# WARNING: NEVER use with real funds.
HUNGRY_MNEMONIC = (
    "hungry type amount worth cloth breeze "
    "capable absent more wear manual audit"
)


# ---------------------------------------------------------------------------
# StoryArtifacts
# ---------------------------------------------------------------------------

class StoryArtifacts:
    """
    Manages artifact directory layout for a single user-story test run.

    Creates:
        {root_dir}/{story_name}/
        {root_dir}/{story_name}/screenshots/
        {root_dir}/{story_name}/{story_name}.jsonl  (log path)
    """

    def __init__(self, root_dir: Path, story_name: str) -> None:
        self._story_name = story_name
        self._artifact_dir = root_dir / story_name
        self._artifact_dir.mkdir(parents=True, exist_ok=True)
        self._screenshot_dir = self._artifact_dir / "screenshots"
        self._screenshot_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self._artifact_dir / f"{story_name}.jsonl"

    @property
    def artifact_dir(self) -> Path:
        return self._artifact_dir

    @property
    def log_path(self) -> Path:
        return self._log_path

    @property
    def screenshot_dir(self) -> Path:
        return self._screenshot_dir


# ---------------------------------------------------------------------------
# GUI observer
# ---------------------------------------------------------------------------

def create_gui_observer(title: str) -> tuple:
    """
    Create an optional Qt GUI window to observe test progress.

    Checks SATOCHIP_OBSERVE_GUI environment variable. If "1", attempts to
    create a PyQt6 QApplication and a status widget. Falls back gracefully
    if PyQt6 is unavailable or any error occurs.

    Parameters
    ----------
    title:
        Window title for the observer widget.

    Returns
    -------
    tuple
        (app, widget, status_label, observe_gui)
        - app:          QApplication instance or None
        - widget:       QWidget instance or None
        - status_label: QLabel instance or None
        - observe_gui:  bool — True if GUI is active
    """
    observe_gui = os.environ.get("SATOCHIP_OBSERVE_GUI", "0") == "1"

    if not observe_gui:
        return (None, None, None, False)

    try:
        from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel  # noqa: PLC0415

        app = QApplication.instance() or QApplication([])
        widget = QWidget()
        widget.setWindowTitle(title)
        widget.setStyleSheet("background-color: #1a1a2e; color: #e0e0e0;")
        layout = QVBoxLayout(widget)
        status_label = QLabel("Starting…")
        status_label.setWordWrap(True)
        status_label.setStyleSheet("font-size: 16px; padding: 16px;")
        layout.addWidget(status_label)
        widget.resize(800, 200)
        widget.show()
        app.processEvents()
        return (app, widget, status_label, True)

    except Exception as exc:
        print(f"[{title}] GUI observe disabled (PyQt6 unavailable): {exc}")
        return (None, None, None, False)


# ---------------------------------------------------------------------------
# set_status
# ---------------------------------------------------------------------------

def set_status(
    text,
    shot_name,
    prefix,
    widget,
    status_label,
    app,
    screenshot_dir,
    observe_gui,
):
    """
    Print a status message and optionally update the GUI label / save screenshot.

    Parameters
    ----------
    text:           Status text to print and display.
    shot_name:      Filename stem for the screenshot (without .png), or None/falsy to skip.
    prefix:         Log prefix shown in brackets, e.g. "pin-block".
    widget:         QWidget instance or None.
    status_label:   QLabel instance or None.
    app:            QApplication instance or None.
    screenshot_dir: Path to the screenshots directory.
    observe_gui:    bool — whether GUI observation is active.
    """
    print(f"[{prefix}] {text}")

    if observe_gui and status_label is not None:
        status_label.setText(text)
        app.processEvents()

    if shot_name:
        shot_path = Path(screenshot_dir) / f"{shot_name}.png"
        if observe_gui and widget is not None:
            widget.grab().save(str(shot_path))


# ---------------------------------------------------------------------------
# record_event
# ---------------------------------------------------------------------------

def record_event(event: dict, log_path: Path, events_list: list) -> None:
    """
    Stamp an event with the current timestamp, append it to a list, and
    write a JSON line to the JSONL log file.

    Parameters
    ----------
    event:       Dict describing the event. A "timestamp" key is added automatically.
    log_path:    Path to the .jsonl file (opened in append mode).
    events_list: In-memory list that accumulates events for the current test.
    """
    event["timestamp"] = time.time()
    events_list.append(event)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# require_card_state
# ---------------------------------------------------------------------------

def require_card_state(cc, requires_setup=None, requires_seeded=None):
    """
    Refresh card status and skip the current test if the card is not in the
    expected state.

    Parameters
    ----------
    cc:
        Card controller object with a ``card_get_status()`` method.
    requires_setup:
        If True,  skip when ``setup_done`` is not True (card is blank).
        If False, skip when ``setup_done`` is True (card is already set up).
        If None,  no setup check is performed.
    requires_seeded:
        If True,  skip when ``is_seeded`` is not True (seed not loaded).
        If False, skip when ``is_seeded`` is True (seed already present).
        If None,  no seeded check is performed.

    Returns
    -------
    dict
        The status dict returned by ``card_get_status()``.
    """
    (_, _, _, status) = cc.card_get_status()

    if requires_setup is True and status.get("setup_done") is not True:
        pytest.skip("Card not set up")

    if requires_setup is False and status.get("setup_done") is True:
        pytest.skip("Card already set up")

    if requires_seeded is True and status.get("is_seeded") is not True:
        pytest.skip("Card not seeded")

    if requires_seeded is False and status.get("is_seeded") is True:
        pytest.skip("Card already seeded")

    return status


# ---------------------------------------------------------------------------
# puk_preflight_check
# ---------------------------------------------------------------------------

def puk_preflight_check(cc):
    """
    Safety check: skip if PUK0_remaining_tries is 0 (card permanently locked).

    Parameters
    ----------
    cc:
        Card controller object with a ``card_get_status()`` method.

    Returns
    -------
    int or None
        The value of ``PUK0_remaining_tries`` from the card status, or None if
        the field is absent.
    """
    (_, _, _, status_dict) = cc.card_get_status()
    puk_tries = status_dict.get("PUK0_remaining_tries")

    if puk_tries is not None and puk_tries == 0:
        pytest.skip(
            "PUK0_remaining_tries=0 — card PUK is already exhausted. "
            "The card is permanently locked. Factory-reset required."
        )

    return puk_tries


from typing import Any


def wait_for_card_absent(cc: "Any", timeout: float = 30.0, app=None) -> bool:
    start = time.time()
    while (time.time() - start) < timeout:
        if app is not None:
            app.processEvents()
        if not cc.card_present:
            return True
        time.sleep(0.3)
    return not cc.card_present


def wait_for_card_present(cc: "Any", timeout: float = 60.0, app=None) -> bool:
    start = time.time()
    while (time.time() - start) < timeout:
        if app is not None:
            app.processEvents()
        if not cc.card_present:
            time.sleep(0.3)
            continue
        if getattr(cc, "cardservice", None) and hasattr(
            getattr(cc.cardservice, "connection", None), "transmit"
        ):
            return True
        time.sleep(0.3)
    return False


def apdu_factory_reset(
    cc: "Any",
    status_fn,
    app=None,
    timeout_per_step: int = 60,
) -> bool:
    cc.set_mode_factory_reset(True)
    try:
        status_fn("Remove card for fresh session...", "reset_00_remove")
        if not wait_for_card_absent(cc, timeout=timeout_per_step, app=app):
            raise RuntimeError("Factory reset timed out waiting for card removal.")

        status_fn("Reinsert card to begin reset...", "reset_01_reinsert")
        if not wait_for_card_present(cc, timeout=timeout_per_step, app=app):
            raise RuntimeError("Factory reset timed out waiting for card reinsertion.")

        time.sleep(2.0)

        step_count = 0
        cla_retries = 0

        while True:
            (_, sw1, sw2) = cc.card_reset_factory_signal()

            if sw1 == 0xFF and sw2 == 0x00:
                cc.card_disconnect()
                return True

            if sw1 == 0xFF and sw2 == 0xFF:
                status_fn("Card not removed. Remove card...", "reset_retry_remove")
                if not wait_for_card_absent(cc, timeout=timeout_per_step, app=app):
                    raise RuntimeError("Factory reset timed out waiting for card removal.")

                status_fn("Reinsert card...", "reset_retry_reinsert")
                if not wait_for_card_present(cc, timeout=timeout_per_step, app=app):
                    raise RuntimeError("Factory reset timed out waiting for card reinsertion.")

                time.sleep(2.0)
                continue

            if sw1 == 0xFF and sw2 > 0x00:
                step_count += 1
                status_fn(
                    f"Step {step_count} ({sw2} remaining): Remove card...",
                    f"reset_{step_count:02d}_remove",
                )
                if not wait_for_card_absent(cc, timeout=timeout_per_step, app=app):
                    raise RuntimeError("Factory reset timed out waiting for card removal.")

                status_fn("Reinsert card...", f"reset_{step_count:02d}_reinsert")
                if not wait_for_card_present(cc, timeout=timeout_per_step, app=app):
                    raise RuntimeError("Factory reset timed out waiting for card reinsertion.")

                time.sleep(2.0)
                continue

            if sw1 == 0x9C and sw2 == 0x04:
                return True

            if sw1 == 0x6D and sw2 == 0x00:
                raise RuntimeError("Factory reset failed: instruction not supported (error 0x6D00).")

            if sw1 == 0x6E and sw2 == 0x00:
                cla_retries += 1
                if cla_retries > 3:
                    raise RuntimeError("Factory reset failed: class not supported (error 0x6E00).")
                print(
                    f"[factory-reset] Warning: got 0x6E00 (CLA not supported), "
                    f"retrying ({cla_retries}/3) after observer settle delay."
                )
                time.sleep(3.0)
                continue

            raise RuntimeError(
                f"Factory reset failed with unexpected error: {hex(256 * sw1 + sw2)}"
            )
    finally:
        cc.set_mode_factory_reset(False)
