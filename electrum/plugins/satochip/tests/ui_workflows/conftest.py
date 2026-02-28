import pytest
from pathlib import Path


def pytest_addoption(parser):
    """Register CLI flags for UI workflow tests."""
    parser.addoption(
        "--run-ui-workflows",
        action="store_true",
        default=False,
        help="run UI workflow tests using real Electrum Qt wizard",
    )
    parser.addoption(
        "--use-real-card",
        action="store_true",
        default=False,
        help="use real Satochip card instead of MockCardConnector",
    )


def pytest_configure(config):
    """Register the ui_workflow marker."""
    config.addinivalue_line(
        "markers", "ui_workflow: end-to-end UI workflow test; only runs with --run-ui-workflows"
    )


def pytest_collection_modifyitems(config, items):
    """Skip ui_workflow tests when --run-ui-workflows is not passed."""
    if not config.getoption("--run-ui-workflows", default=False):
        skip_marker = pytest.mark.skip(reason="UI workflow test disabled (use --run-ui-workflows)")
        for item in items:
            if "ui_workflow" in item.keywords:
                item.add_marker(skip_marker)


@pytest.fixture
def wallet_tmp_path(tmp_path: Path) -> Path:
    """Create and return a temporary wallet directory path."""
    wallet_dir = tmp_path / "wallet_test_dir"
    wallet_dir.mkdir()
    return wallet_dir


@pytest.fixture
def ui_artifact_root(tmp_path: Path) -> Path:
    """Create and return a timestamped UI artifact directory path."""
    import time

    timestamp = int(time.time())
    artifact_dir = tmp_path / f"satochip_ui_{timestamp}"
    artifact_dir.mkdir()
    return artifact_dir


class _DummyCardClient:
    """Minimal pysatochip client stub for CardConnector."""
    def request(self, req_type, *args):
        return None


@pytest.fixture
def use_real_card(request) -> bool:
    """Return True when --use-real-card CLI flag is passed."""
    return request.config.getoption("--use-real-card", default=False)


@pytest.fixture
def real_card_connector(use_real_card):
    """Create a real CardConnector if --use-real-card, else yield None."""
    if not use_real_card:
        yield None
        return

    import logging
    import os
    import time

    from electrum.plugins.satochip.tests.conftest import has_remote_pcscd

    # Auto-detect pcscd socket
    if "PCSCLITE_CSOCK_NAME" not in os.environ:
        for candidate in ("/tmp/pcscd-remote.comm", "/tmp/pcscd-smoke.comm", "/run/pcscd/pcscd.comm"):
            if os.path.exists(candidate):
                os.environ["PCSCLITE_CSOCK_NAME"] = candidate
                break

    # Ensure DYLD_LIBRARY_PATH includes /tmp for macOS pcsc-lite
    dyld_path = os.environ.get("DYLD_LIBRARY_PATH", "")
    if "/tmp" not in dyld_path:
        os.environ["DYLD_LIBRARY_PATH"] = "/tmp:" + dyld_path

    if not has_remote_pcscd():
        yield None
        return

    try:
        from pysatochip.CardConnector import CardConnector
    except ImportError:
        yield None
        return

    cc = None
    try:
        cc = CardConnector(_DummyCardClient(), logging.WARNING)
        for _attempt in range(5):
            try:
                _, sw1, sw2, _ = cc.card_get_status()
                if (sw1, sw2) == (0x90, 0x00):
                    break
            except Exception:
                pass
            time.sleep(0.5)
        if getattr(cc, 'needs_secure_channel', False):
            try:
                cc.card_initiate_secure_channel()
            except Exception:
                pass
        yield cc
    except Exception:
        yield None
    finally:
        if cc is not None:
            try:
                cc.card_disconnect()
            except Exception:
                pass

