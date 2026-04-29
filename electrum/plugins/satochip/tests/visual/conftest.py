"""Pytest fixtures for Satochip visual lifecycle tests.

Provides:
  - ``cc_session``: module-scoped smart card connection (requires hardware)
  - ``story_artifact_root``: temp directory for screenshots + logs + report
  - ``_generate_final_report``: session-scoped autouse fixture that writes
    the HTML report after all stories finish (even if some fail).
"""

import os
import sys
import shutil
import time
from datetime import datetime
from pathlib import Path

if not os.environ.get("QT_QPA_PLATFORM"):
    pass

try:
    from PyQt5.QtCore import Qt  # noqa: F401
    os.environ.setdefault("PYTEST_QT_API", "pyqt5")
except ImportError:
    os.environ.setdefault("PYTEST_QT_API", "pyqt6")

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _find_reader():
    try:
        from smartcard.System import readers
        rs = readers()
        return rs[0] if rs else None
    except Exception:
        return None


def _report_root() -> Path:
    root = Path(REPO_ROOT) / "plugins" / "satochip" / "tests" / "screenshots"
    root.mkdir(parents=True, exist_ok=True)
    return root


@pytest.fixture(scope="module")
def cc_session():
    """Module-scoped card connector session for visual lifecycle tests."""
    reader = _find_reader()
    if reader is None:
        pytest.skip("No smart card reader found — connect reader and insert Satochip")

    from smartcard.PassThruCardService import PassThruCardService
    from electrum.plugins.satochip.card_connector import CardConnector

    conn = reader.createConnection()
    try:
        conn.connect()
    except Exception as e:
        pytest.skip(f"Cannot connect to card: {e}")

    connector = CardConnector(client=None, card_filter=["satochip"])
    connector.cardservice = PassThruCardService(conn)
    connector.card_present = True
    connector._detect_protocol()
    connector.card_select()
    time.sleep(1.5)

    yield connector

    try:
        connector.card_disconnect()
    except Exception:
        pass


@pytest.fixture(scope="session")
def story_artifact_root():
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    root = _report_root() / f"visual-lifecycle-{ts}"
    root.mkdir(parents=True, exist_ok=True)
    return root


@pytest.fixture(scope="session")
def electrum_ctx():
    from electrum.plugins.satochip.tests.visual.harness import (
        RealElectrumContext,
        create_config,
    )
    import tempfile
    config = create_config(tempfile.mkdtemp(prefix="satochip-electrum-ctx-"))
    ctx = RealElectrumContext(config)
    yield ctx
    ctx.cleanup()


@pytest.fixture(scope="session", autouse=True)
def _generate_final_report(request):
    """After all visual lifecycle tests, generate the HTML report.

    Imports the shared artifacts object from test_visual_lifecycle and
    writes report.html regardless of pass/fail/skip status.
    """
    yield

    try:
        from electrum.plugins.satochip.tests.visual.test_visual_lifecycle import (
            _shared_artifacts,
        )
        from electrum.plugins.satochip.tests.fixtures.visual_testing import (
            generate_html_report,
        )

        if _shared_artifacts is None:
            return

        screenshots = len(_shared_artifacts.get_all_screenshots())
        report = generate_html_report(_shared_artifacts, title="Satochip Visual Lifecycle Test")
        if report:
            stable_report = _report_root() / "visual-lifecycle-report.html"
            shutil.copyfile(report, stable_report)
            print(f"\n[visual-lifecycle] Report ({screenshots} screenshots): {stable_report}")
            print(f"[visual-lifecycle] Artifact bundle: {_shared_artifacts.artifact_dir}")
        else:
            print(f"\n[visual-lifecycle] Report generation failed ({screenshots} screenshots collected)")
    except Exception as e:
        print(f"\n[visual-lifecycle] Final report generation error: {e}")
