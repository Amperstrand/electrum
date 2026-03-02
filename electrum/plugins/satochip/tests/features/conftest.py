"""
BDD-specific fixtures and Allure hooks for Satochip user story tests.

This conftest extends the parent conftest with BDD-specific fixtures.
It does NOT redefine cc_session or story_artifact_root - those are reused
from the parent conftest.py.
"""
import allure
import pytest
from pathlib import Path
from typing import Any, Callable

from electrum.plugins.satochip.tests.story_helpers import (
    StoryArtifacts,
    create_gui_observer,
    set_status,
    record_event,
)


@pytest.fixture
def bdd_artifacts(story_artifact_root: Path, request: Any) -> StoryArtifacts:
    """Create a StoryArtifacts instance for BDD tests."""
    story_name = request.node.name.replace(" ", "-").lower()
    return StoryArtifacts(story_artifact_root, f"bdd-{story_name}")


@pytest.fixture
def bdd_observer(request: Any) -> tuple[Any, Any, Any, bool]:
    """Create a GUI observer for BDD test steps."""
    title = f"BDD: {request.node.name}"
    app, widget, status_label, observe_gui = create_gui_observer(title)
    yield (app, widget, status_label, observe_gui)
    # Cleanup: close widget if it exists
    if widget is not None:
        widget.close()


@pytest.fixture
def bdd_status_fn(
    bdd_artifacts: StoryArtifacts,
    bdd_observer: tuple[Any, Any, Any, bool]
) -> Callable[[str, str | None], None]:
    """Return a status function that updates GUI and attaches to Allure."""
    app, widget, status_label, observe_gui = bdd_observer
    prefix = "bdd-test"

    def _status(text: str, shot_name: str | None = None) -> None:
        # Print to console
        print(f"[{prefix}] {text}")

        # Update GUI if active
        if observe_gui and status_label is not None:
            status_label.setText(text)
            app.processEvents()

        # Save screenshot and attach to Allure
        if shot_name:
            shot_path = bdd_artifacts.screenshot_dir / f"{shot_name}.png"
            if observe_gui and widget is not None:
                widget.grab().save(str(shot_path))
            # Attach to Allure report
            if shot_path.exists():
                allure.attach.file(
                    str(shot_path),
                    name=f"{shot_name}: {text}",
                    attachment_type=allure.attachment_type.PNG,
                )

    return _status
