"""Story helpers for Satochip card lifecycle testing.

Provides card interaction primitives used by both hardware-only tests and
visual lifecycle tests.  The ``record_event`` and ``StoryArtifacts`` aliases
mirror the visual_testing module so that visual tests can use a single import
path for event logging + screenshot capture.
"""

import datetime
import json
import os
import subprocess
import time
import logging
from pathlib import Path
from typing import Any, Callable

_logger = logging.getLogger(__name__)

HUNGRY_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def record_event(
    event: dict[str, Any],
    log_path: Path,
    events: list | None = None,
) -> None:
    """Append a timestamped event dict to *log_path* (JSONL) and optionally to *events*."""
    event["_timestamp"] = time.time()
    event["_datetime"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if events is not None:
        events.append(event)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def puk_preflight_check(cc: Any) -> int:
    """Return PUK0_remaining_tries, or raise RuntimeError if PUK unavailable."""
    try:
        (_, _, _, status) = cc.card_get_status()
    except Exception as exc:
        raise RuntimeError(f"card_get_status failed during PUK preflight: {exc}") from exc

    puk_tries = status.get("PUK0_remaining_tries", status.get("PUK_remaining_tries", -1))
    if not isinstance(puk_tries, int) or puk_tries <= 0:
        raise RuntimeError(
            f"PUK not available for unblock (PUK0_remaining_tries={puk_tries}). "
            f"Full status: {status}"
        )
    return puk_tries


def reconnect_card(cc: Any, max_attempts: int = 3) -> None:
    """Reconnect to the card after a reset or swap.

    Tries to re-establish the reader connection, detect protocol, and
    select the Satochip applet.  Retries up to *max_attempts* times.
    """
    for attempt in range(1, max_attempts + 1):
        try:
            from smartcard.System import readers
            rs = readers()
            if not rs:
                raise RuntimeError("No readers found")
            from smartcard.PassThruCardService import PassThruCardService
            conn = rs[0].createConnection()
            conn.connect()
            cc.cardservice = PassThruCardService(conn)
            cc.card_present = True
            cc._detect_protocol()
            cc.card_select()
            return
        except Exception:
            if attempt == max_attempts:
                raise
            time.sleep(2)


def _is_card_present(cc: Any) -> bool:
    """Check if the card is currently inserted by probing the reader."""
    try:
        if not cc.card_present:
            return False
        conn = cc.cardservice.connection
        try:
            conn.transmit([0x00, 0xA4, 0x04, 0x00, 0x08,
                           0x53, 0x61, 0x74, 0x6F, 0x43, 0x68, 0x69, 0x70])
            return True
        except Exception:
            return False
    except Exception:
        return False


def wait_for_card_absent(cc: Any, timeout: float = 60.0) -> bool:
    """Block until the card is removed or *timeout* seconds elapse."""
    start = time.time()
    while time.time() - start < timeout:
        if not _is_card_present(cc):
            cc.card_present = False
            return True
        time.sleep(0.1)
    return False


def wait_for_card_present(cc: Any, timeout: float = 60.0) -> bool:
    """Block until the card is inserted or *timeout* seconds elapse."""
    start = time.time()
    while time.time() - start < timeout:
        if _is_card_present(cc):
            cc.card_present = True
            return True
        time.sleep(0.1)
    return False


def apdu_factory_reset(
    cc: Any,
    log_fn: Callable[[str], None] | None = None,
    on_need_card_swap: Callable[[int | None], bool] | None = None,
    max_attempts: int = 10,
) -> tuple:
    """Perform full legacy factory reset loop.

    The Satochip legacy factory reset requires sending the APDU ``B0 FF 00 00 00``
    multiple times (typically 4).  After each APDU the card returns a remaining
    counter in ``sw2``.  The operator must **remove and reinsert** the card
    between each iteration; if the card is not removed the APDU returns
    ``0xFF 0xFF`` and the attempt is wasted.

    Response codes from the card:
      ``0xFF 0x00`` — factory reset complete
      ``0xFF NN`` (NN>0, NN!=0xFF) — remaining counter, must remove/reinsert
      ``0xFF 0xFF`` — card not removed between attempts
      ``0x9C 0x04`` — already in factory state

    Args:
        cc: CardConnector session.
        log_fn: Optional logger ``callable(str)``.
        on_need_card_swap: Called when the card must be removed/reinserted.
            Receives ``remaining`` — the swap counter from the card (or ``None``
            if the card returned ``0xFF 0xFF`` and the counter is unknown).
            The callback should block until the card swap is complete and
            return ``True`` on success, ``False`` to abort.
            If *None*, a single APDU is sent (no loop).
        max_attempts: Safety limit on reset iterations.

    Returns:
        ``(response, sw1, sw2)`` from the final APDU.

    Raises:
        RuntimeError: If the reset fails or the card returns an unexpected
            status after exhausting *max_attempts*.
    """
    cc.mode_factory_reset = True
    try:
        for attempt in range(1, max_attempts + 1):
            if log_fn:
                log_fn(f"Factory reset APDU attempt {attempt}/{max_attempts}...")

            try:
                response, sw1, sw2 = cc.card_reset_factory_signal()
            except AttributeError:
                if log_fn:
                    log_fn("card_reset_factory_signal not found, trying card_factory_reset...")
                response, sw1, sw2 = cc.card_factory_reset()

            if log_fn:
                log_fn(f"  Response: sw1=0x{sw1:02X} sw2=0x{sw2:02X}")

            if sw1 == 0x9C and sw2 == 0x04:
                if log_fn:
                    log_fn("Card already in factory state")
                return response, sw1, sw2

            if sw1 == 0xFF and sw2 == 0x00:
                if log_fn:
                    log_fn("Factory reset complete!")
                return response, sw1, sw2

            if sw1 == 0xFF and sw2 == 0xFF:
                if log_fn:
                    log_fn("Card not removed between attempts — need card swap")
                if on_need_card_swap is not None:
                    if not on_need_card_swap(None):
                        raise RuntimeError("Factory reset aborted: card swap callback returned False")
                else:
                    raise RuntimeError(
                        "Factory reset requires card removal/reinsertion "
                        "but no on_need_card_swap callback was provided"
                    )
                continue

            if sw1 == 0xFF and sw2 > 0x00:
                if log_fn:
                    log_fn(f"Remaining counter: {sw2} — card swap required")
                if on_need_card_swap is not None:
                    if not on_need_card_swap(sw2):
                        raise RuntimeError("Factory reset aborted: card swap callback returned False")
                else:
                    raise RuntimeError(
                        f"Factory reset has remaining counter {sw2} — requires "
                        "card removal/reinsertion but no on_need_card_swap callback"
                    )
                continue

            raise RuntimeError(
                f"Factory reset failed with unexpected status: 0x{sw1:02X}{sw2:02X}"
            )

        raise RuntimeError(
            f"Factory reset did not complete after {max_attempts} attempts"
        )
    finally:
        cc.mode_factory_reset = False


ISD_KEYS = {
    "KEY_ENC": "5A9E63D03BADBC2A240FE8F534709EDF",
    "KEY_MAC": "7CCC1E79D64FC5FA263B8F2955282998",
    "KEY_DEK": "B040703EC3DE23EE8AE4CFB6D632AA80",
}

SATOCHIP_AID = "5361746F43686970"

_REPO_ROOT = Path(__file__).resolve().parents[5]
_GP_JAR = _REPO_ROOT / "SatochipApplet" / "gp.jar"
_CAP_FILE = _REPO_ROOT / "SatochipApplet" / "SatoChip-v0.14-0.2.cap"


def cap_reinstall(
    log_fn: Callable[[str], None] | None = None,
    cap_file: Path | None = None,
    gp_jar: Path | None = None,
) -> None:
    """Delete and reinstall the Satochip applet via GlobalPlatformPro.

    This is an alternative to the multi-swap APDU factory reset: it deletes
    the applet package and reinstalls from the .cap file, giving a clean card
    in one step with no card removal/reinsertion needed.

    Requires ``java`` on PATH and the ISD keys for the card.
    """
    jar = gp_jar or _GP_JAR
    cap = cap_file or _CAP_FILE

    if not jar.exists():
        raise FileNotFoundError(f"gp.jar not found: {jar}")
    if not cap.exists():
        raise FileNotFoundError(f".cap file not found: {cap}")

    env = os.environ.copy()
    env.update(ISD_KEYS)

    base_cmd = [
        "java", "-jar", str(jar),
        "--key-enc", ISD_KEYS["KEY_ENC"],
        "--key-mac", ISD_KEYS["KEY_MAC"],
        "--key-dek", ISD_KEYS["KEY_DEK"],
    ]

    if log_fn:
        log_fn("Deleting Satochip applet package...")

    result = subprocess.run(
        base_cmd + ["--delete", SATOCHIP_AID],
        capture_output=True, text=True, env=env, timeout=60,
    )
    if log_fn:
        log_fn(f"  delete stdout: {result.stdout.strip()}")
        if result.stderr:
            log_fn(f"  delete stderr: {result.stderr.strip()}")

    time.sleep(1.0)

    if log_fn:
        log_fn("Installing Satochip applet from .cap file...")

    result = subprocess.run(
        base_cmd + ["--install", str(cap)],
        capture_output=True, text=True, env=env, timeout=60,
    )
    if log_fn:
        log_fn(f"  install stdout: {result.stdout.strip()}")
        if result.stderr:
            log_fn(f"  install stderr: {result.stderr.strip()}")

    if result.returncode != 0:
        raise RuntimeError(
            f"Applet install failed (rc={result.returncode}): "
            f"{result.stdout} {result.stderr}"
        )

    if log_fn:
        log_fn("Applet reinstalled — card is now in factory state.")
