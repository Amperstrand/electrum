"""Native macOS window capture using Quartz/CoreGraphics via PyObjC.

Falls back to QWidget.grab() when PyObjC is unavailable or when the
window cannot be found in the CGWindowList.
"""

import os
import sys
from pathlib import Path
from typing import Optional

from electrum.logging import get_logger

_logger = get_logger(__name__)

QuartzAvailable = False
try:
    import Quartz
    QuartzAvailable = True
except ImportError:
    pass


def _find_cgwindow_id(widget) -> Optional[int]:
    if not QuartzAvailable:
        return None
    pid = os.getpid()
    title = ""
    try:
        title = widget.windowTitle() or ""
    except Exception:
        pass
    window_list = Quartz.CGWindowListCopyWindowInfo(
        Quartz.kCGWindowListOptionAll,
        Quartz.kCGNullWindowID,
    )
    candidates = []
    for w in window_list:
        if w.get("kCGWindowOwnerPID") != pid:
            continue
        if w.get("kCGWindowLayer", -1) != 0:
            continue
        wname = w.get("kCGWindowName", "") or ""
        wnum = w.get("kCGWindowNumber", 0)
        if title and title in wname:
            return wnum
        candidates.append((wnum, wname))
    if len(candidates) == 1:
        return candidates[0][0]
    if candidates:
        return candidates[-1][0]
    return None


def _capture_with_quartz(cg_window_id: int, out_path: str) -> bool:
    rect = Quartz.CGRectInfinite
    image = Quartz.CGWindowListCreateImage(
        rect,
        Quartz.kCGWindowListOptionIncludingWindow,
        cg_window_id,
        Quartz.kCGWindowImageNominalResolution
        | Quartz.kCGWindowImageBoundsIgnoreFraming,
    )
    if image is None:
        return False
    url = Quartz.CFURLCreateFromFileSystemRepresentation(
        None, out_path.encode("utf-8"), len(out_path.encode("utf-8")), False
    )
    dest = Quartz.CGImageDestinationCreateWithURL(url, "public.png", 1, None)
    if dest is None:
        return False
    Quartz.CGImageDestinationAddImage(dest, image, None)
    Quartz.CGImageDestinationFinalize(dest)
    return True


def capture_window_native(widget, out_path: Path) -> bool:
    if not QuartzAvailable:
        return False
    cg_wid = _find_cgwindow_id(widget)
    if cg_wid is None:
        _logger.debug("native_capture: CGWindowID not found, falling back to grab()")
        return False
    try:
        return _capture_with_quartz(cg_wid, str(out_path))
    except Exception as e:
        _logger.debug(f"native_capture: Quartz capture failed: {e}")
        return False


def capture_widget(widget, out_path: Path, *, use_native: bool = True) -> bool:
    if use_native:
        try:
            if capture_window_native(widget, out_path):
                return True
        except Exception:
            pass
    pixmap = widget.grab()
    if pixmap.isNull():
        return False
    if 'PyQt6' in sys.modules:
        from PyQt6.QtCore import QBuffer, QIODevice
        buf = QBuffer()
        buf.open(QIODevice.OpenModeFlag.WriteOnly)
        pixmap.save(buf, "PNG")
        buf.close()
        out_path.write_bytes(buf.data().data())
    else:
        from PyQt5.QtCore import QBuffer, QIODevice
        buf = QBuffer()
        buf.open(QIODevice.WriteOnly)
        pixmap.save(buf, "PNG")
        buf.close()
        out_path.write_bytes(buf.data())
    return True
