"""
BDD User Story Tests for Satochip Integration.

This module contains pytest-bdd step definitions that implement the user stories
defined in the .feature files. The step definitions wrap the existing story_helpers
functions - they do NOT reimplement the logic.

How to run:
    # Collect tests (verify they are found)
    python3 -m pytest --co -q electrum/plugins/satochip/tests/test_bdd_user_stories.py --run-user-stories

    # Run with real card (requires SSH tunnel + SATOCHIP_OBSERVE_GUI=1)
    SATOCHIP_OBSERVE_GUI=1 python3 -m pytest electrum/plugins/satochip/tests/test_bdd_user_stories.py \\
        --run-user-stories --alluredir=/tmp/allure-results -v -s

    # View Allure report
    allure serve /tmp/allure-results

Relationship to existing tests:
    This file provides BDD-style tests that wrap the same logic as test_satochip_user_stories.py.
    Both test files use the same fixtures (cc_session, story_artifact_root) and helpers (story_helpers.py).
    They CANNOT run concurrently because they share the same physical card.
"""
import os
import time
from pathlib import Path
from typing import Any

import pytest
from pytest_bdd import scenario, given, when, then

from electrum.plugins.satochip.tests.story_helpers import (
    StoryArtifacts,
    create_gui_observer,
    set_status,
    record_event,
    apdu_factory_reset,
    wait_for_card_absent,
    wait_for_card_present,
)


# Scenario binding
@scenario(
    "features/story_0_factory_reset.feature",
    "Factory reset returns card to blank state",
)
@pytest.mark.user_story
def test_factory_reset_card():
    """BDD test for Story 0: Factory Reset."""
    pass


# Context fixture to share state between steps
@pytest.fixture
def bdd_context():
    """Shared context for BDD step data."""
    return {
        "artifacts": None,
        "observer": None,
        "status_fn": None,
        "events": [],
        "status_before": None,
        "reset_completed": False,
    }


# Background steps
@given("a real Satochip card is connected via remote reader")
def card_connected(cc_session: Any, bdd_context: dict, story_artifact_root: Path):
    """Verify card is connected and initialize artifacts."""
    # Create artifacts directory
    bdd_context["artifacts"] = StoryArtifacts(story_artifact_root, "bdd-story-0-factory-reset")
    
    # Verify card is accessible
    (_, sw1, sw2, status) = cc_session.card_get_status()
    assert sw1 == 0x90, f"Card not accessible: SW={sw1:02X}{sw2:02X}"
    
    return bdd_context


@given("the GUI observer is active")
def gui_observer_active(bdd_context: dict, request: Any):
    """Create GUI observer for test visualization."""
    observe_gui = os.environ.get("SATOCHIP_OBSERVE_GUI", "0") == "1"
    
    if not observe_gui:
        pytest.skip("Story 0 requires GUI mode (SATOCHIP_OBSERVE_GUI=1)")
    
    app, widget, status_label, observe_active = create_gui_observer("BDD: Story 0 - Factory Reset")
    bdd_context["observer"] = (app, widget, status_label, observe_active)
    
    def cleanup():
        if widget is not None:
            widget.close()
    
    request.addfinalizer(cleanup)
    
    return bdd_context


# Scenario steps
@given("the card status is recorded before reset")
def record_status_before(cc_session: Any, bdd_context: dict):
    """Record the card status before factory reset."""
    (_, sw1, sw2, status) = cc_session.card_get_status()
    bdd_context["status_before"] = status
    
    # Log the event
    record_event(
        {"event": "bdd_pre_reset_status", "status": status},
        bdd_context["artifacts"].log_path,
        bdd_context["events"],
    )


@when("the APDU factory reset flow is initiated")
def initiate_apdu_reset(cc_session: Any, bdd_context: dict):
    """Initiate the APDU factory reset flow."""
    app, widget, status_label, observe_gui = bdd_context["observer"]
    artifacts = bdd_context["artifacts"]
    
    def _status(text: str, shot_name: str | None = None) -> None:
        set_status(
            text, shot_name, "bdd-reset",
            widget, status_label, app,
            artifacts.screenshot_dir, observe_gui
        )
    
    _status("Starting APDU factory reset...", "00_apdu_start")
    
    try:
        apdu_factory_reset(cc_session, _status, app=app)
        bdd_context["reset_completed"] = True
    except RuntimeError as exc:
        _status(f"FAILED: {exc}", "99_failed")
        record_event(
            {"event": "bdd_factory_reset", "status": "failed", "error": str(exc)},
            artifacts.log_path,
            bdd_context["events"],
        )
        pytest.fail(f"APDU factory reset failed: {exc}")
    
    _status("APDU reset flow complete", "01_apdu_done")
    record_event(
        {"event": "bdd_factory_reset", "status": "ok"},
        artifacts.log_path,
        bdd_context["events"],
    )


@when("the user removes and reinserts the card as prompted")
def user_removes_reinserts_card():
    """This step is handled internally by apdu_factory_reset()."""
    # The apdu_factory_reset function already handles card removal/reinsertion cycles
    # This step exists for documentation purposes in the Gherkin file
    pass


@then("the APDU reset flow completes successfully")
def verify_reset_completed(bdd_context: dict):
    """Verify the APDU reset flow completed."""
    assert bdd_context["reset_completed"], "APDU factory reset did not complete"
    
    app, widget, status_label, observe_gui = bdd_context["observer"]
    if observe_gui and status_label is not None:
        status_label.setText("APDU reset verified complete")
        app.processEvents()


@when("the card is removed for final verification")
def remove_for_verification(cc_session: Any, bdd_context: dict):
    """Wait for user to remove card for final verification."""
    app, widget, status_label, observe_gui = bdd_context["observer"]
    artifacts = bdd_context["artifacts"]
    
    def _status(text: str, shot_name: str | None = None) -> None:
        set_status(
            text, shot_name, "bdd-reset",
            widget, status_label, app,
            artifacts.screenshot_dir, observe_gui
        )
    
    _status("Remove card for final verification...", "02_verify_remove")
    
    if not wait_for_card_absent(cc_session, timeout=60, app=app):
        _status("FAILED: card not removed", "99_failed_remove")
        pytest.fail("Timed out waiting for card removal for verification")


@when("the card is reinserted for status check")
def reinsert_for_status_check(cc_session: Any, bdd_context: dict):
    """Wait for user to reinsert card for status check."""
    app, widget, status_label, observe_gui = bdd_context["observer"]
    artifacts = bdd_context["artifacts"]
    
    def _status(text: str, shot_name: str | None = None) -> None:
        set_status(
            text, shot_name, "bdd-reset",
            widget, status_label, app,
            artifacts.screenshot_dir, observe_gui
        )
    
    _status("Reinsert card for status check...", "03_verify_reinsert")
    
    if not wait_for_card_present(cc_session, timeout=60, app=app):
        _status("FAILED: card not reinserted", "99_failed_reinsert")
        pytest.fail("Timed out waiting for card reinsertion for status check")
    
    # Small delay for card to stabilize
    time.sleep(2.0)


@then("the card status shows setup_done is False")
def verify_setup_done_false(cc_session: Any, bdd_context: dict):
    """Verify card status shows setup_done is False (factory reset state)."""
    app, widget, status_label, observe_gui = bdd_context["observer"]
    artifacts = bdd_context["artifacts"]
    
    def _status(text: str, shot_name: str | None = None) -> None:
        set_status(
            text, shot_name, "bdd-reset",
            widget, status_label, app,
            artifacts.screenshot_dir, observe_gui
        )
    
    _status("Verifying card is factory-reset...", "04_verify_blank")
    
    # Get card status
    try:
        (_, sw1, sw2, status) = cc_session.card_get_status()
    except Exception:
        # Retry with secure channel initiation
        time.sleep(2)
        try:
            cc_session.card_initiate_secure_channel()
        except Exception:
            pass
        (_, sw1, sw2, status) = cc_session.card_get_status()
    
    setup_done = status.get("setup_done", "UNKNOWN")
    
    record_event(
        {"event": "bdd_verification", "setup_done": setup_done, "sw": f"{sw1:02X}{sw2:02X}"},
        artifacts.log_path,
        bdd_context["events"],
    )
    
    if setup_done is not False:
        _status(f"FAILED: setup_done={setup_done}", "99_failed_not_blank")
        pytest.fail(f"Card not blank after factory reset: setup_done={setup_done}")


@then("the card is in factory-reset state")
def verify_factory_reset_state(bdd_context: dict):
    """Verify card is in factory-reset state."""
    # This is a documentation step - the actual verification is in verify_setup_done_false
    app, widget, status_label, observe_gui = bdd_context["observer"]
    if observe_gui and status_label is not None:
        status_label.setText("Card is in factory-reset state")
        app.processEvents()


@then("the factory reset event log is complete")
def verify_event_log_complete(bdd_context: dict):
    """Verify the event log is complete and save final status."""
    app, widget, status_label, observe_gui = bdd_context["observer"]
    artifacts = bdd_context["artifacts"]
    
    def _status(text: str, shot_name: str | None = None) -> None:
        set_status(
            text, shot_name, "bdd-reset",
            widget, status_label, app,
            artifacts.screenshot_dir, observe_gui
        )
    
    # Record completion
    record_event(
        {"event": "bdd_factory_reset_complete", "status": "passed"},
        artifacts.log_path,
        bdd_context["events"],
    )
    
    _status("Factory reset complete - card is blank", "05_success")
