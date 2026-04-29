"""
visual_testing.py — Screenshot capture and HTML report generation for Satochip visual tests.

Captures Qt widget screenshots via QWidget.grab(), stores them as base64 PNG data,
and generates a self-contained HTML report with all screenshots organized by category.
"""

import base64
import json
import re
import sys as _sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_QtWidgets: tuple[type, ...] = ()
_QtGui: tuple[type, ...] = ()
_QtCore: tuple[type, ...] = ()


def _ensure_qt():
    global _QtCore
    if _QtWidgets:
        return _QtWidgets
    if 'PyQt5' in _sys.modules:
        from PyQt5.QtWidgets import QApplication, QWidget
        from PyQt5.QtCore import QBuffer, QIODevice
        _QtCore = (QBuffer, QIODevice)
        return (QApplication, QWidget)
    else:
        from PyQt6.QtWidgets import QApplication, QWidget
        from PyQt6.QtCore import QBuffer, QIODevice
        _QtCore = (QBuffer, QIODevice)
        return (QApplication, QWidget)


@dataclass
class ScreenshotEntry:
    name: str
    display_name: str
    category: str
    status: str
    detail: str
    b64_png: str
    timestamp: str
    width: int
    height: int
    step_number: int = 0
    step_description: str = ""


class VisualTestArtifacts:
    def __init__(self, root_dir: Path, run_name: str):
        self._test_name = run_name
        self._artifact_dir = root_dir / run_name
        self._artifact_dir.mkdir(parents=True, exist_ok=True)
        self._screenshot_dir = self._artifact_dir / "screenshots"
        self._screenshot_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self._artifact_dir / "test_log.txt"
        self._screenshots: list[ScreenshotEntry] = []

    @property
    def artifact_dir(self) -> Path:
        return self._artifact_dir

    @property
    def log_path(self) -> Path:
        return self._log_path

    @property
    def screenshot_dir(self) -> Path:
        return self._screenshot_dir

    def add_screenshot(self, entry: ScreenshotEntry) -> None:
        self._screenshots.append(entry)

    def get_screenshots_by_category(self) -> dict[str, list[ScreenshotEntry]]:
        categories: dict[str, list[ScreenshotEntry]] = {}
        for entry in self._screenshots:
            categories.setdefault(entry.category, []).append(entry)
        return categories

    def get_all_screenshots(self) -> list[ScreenshotEntry]:
        return list(self._screenshots)

    def record_event(self, event: dict[str, Any]) -> None:
        event["_timestamp"] = time.time()
        event["_datetime"] = datetime.now(timezone.utc).isoformat()
        with open(self._log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")


# Module-level alias used by story_helpers
StoryArtifacts = VisualTestArtifacts


def _infer_display_name(name: str, prefix: str | None) -> str:
    raw = name
    if prefix:
        raw = name
    parts = raw.replace("-", " ").replace("_", " ").split()
    # Strip leading numbers like "01", "02"
    cleaned = []
    for p in parts:
        if p.isdigit():
            continue
        cleaned.append(p.capitalize())
    return " ".join(cleaned) if cleaned else name


def _extract_step_number(name: str) -> int:
    """Extract leading step number from a screenshot name.

    Handles patterns like "01-pre-reset-settings" -> 1, "02a" -> 2.
    Returns 0 if no leading number is found.
    """
    match = re.match(r"^(\d+)", name)
    if match:
        return int(match.group(1))
    return 0


def _infer_category(name: str, prefix: str | None) -> str:
    prefix_map = {
        "s0": "Factory Reset",
        "s1": "Wallet Setup",
        "s2": "PIN Block",
        "s3": "PUK Recovery",
    }
    if prefix and prefix in prefix_map:
        return prefix_map[prefix]
    lower = name.lower()
    if "wizard" in lower or "setup" in lower:
        return "Wizard Views"
    if "settings" in lower:
        return "Settings Dialog"
    if "device" in lower or "chooser" in lower:
        return "Device Chooser"
    return "General"


def log_step(message: str, artifacts: VisualTestArtifacts) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {message}"
    print(line)
    artifacts.record_event({"type": "step", "message": message})


def capture_screenshot(
    widget: Any,
    name: str,
    artifacts: VisualTestArtifacts,
    prefix: str | None = None,
) -> Optional[Path]:
    """QWidget.grab() → PNG → base64. Returns Path or None."""
    if widget is None:
        return None

    qt_types = _ensure_qt()
    QWidget = qt_types[1]

    if not isinstance(widget, QWidget):
        return None

    try:
        pixmap = widget.grab()
        if pixmap.isNull():
            return None

        filename = f"{prefix}-{name}.png" if prefix else f"{name}.png"
        save_path = artifacts.screenshot_dir / filename
        pixmap.save(str(save_path), "PNG")

        # Use QBuffer (QIODevice) instead of io.BytesIO —
        # QPixmap.save() does not accept Python file-like objects.
        QBuffer, QIODevice = _QtCore
        buf = QBuffer()
        buf.open(QIODevice.OpenModeFlag.WriteOnly)
        pixmap.save(buf, "PNG")
        b64_data = base64.b64encode(bytes(buf.data())).decode("ascii")
        buf.close()

        entry = ScreenshotEntry(
            name=filename,
            display_name=_infer_display_name(name, prefix),
            category=_infer_category(name, prefix),
            status="pass",
            detail=f"Captured {pixmap.width()}x{pixmap.height()}",
            b64_png=b64_data,
            timestamp=datetime.now(timezone.utc).isoformat(),
            width=pixmap.width(),
            height=pixmap.height(),
            step_number=_extract_step_number(name),
            step_description=_infer_display_name(name, prefix),
        )
        artifacts.add_screenshot(entry)
        return save_path

    except Exception:
        return None


def capture_all_windows(
    artifacts: VisualTestArtifacts,
    prefix: str = "window",
) -> list[Path]:
    qt_types = _ensure_qt()
    QApplication = qt_types[0]
    app = QApplication.instance()
    if app is None:
        return []

    paths = []
    for i, w in enumerate(app.topLevelWidgets()):
        if not w.isVisible():
            continue
        try:
            title = w.objectName() or w.windowTitle() or f"window_{i}"
            safe_title = "".join(c if c.isalnum() or c in "-_" else "_" for c in title)
            filename = f"{prefix}-{safe_title}.png"
            save_path = artifacts.screenshot_dir / filename
            pixmap = w.grab()
            if pixmap.isNull():
                continue
            pixmap.save(str(save_path), "PNG")

            QBuffer, QIODevice = _QtCore
            buf = QBuffer()
            buf.open(QIODevice.OpenModeFlag.WriteOnly)
            pixmap.save(buf, "PNG")
            b64_data = base64.b64encode(bytes(buf.data())).decode("ascii")
            buf.close()

            entry = ScreenshotEntry(
                name=filename,
                display_name=title,
                category="Open Windows",
                status="pass",
                detail=f"Captured {pixmap.width()}x{pixmap.height()}",
                b64_png=b64_data,
                timestamp=datetime.now(timezone.utc).isoformat(),
                width=pixmap.width(),
                height=pixmap.height(),
            )
            artifacts.add_screenshot(entry)
            paths.append(save_path)
        except Exception:
            continue

    return paths


def _build_html(artifacts: VisualTestArtifacts, title: str) -> str:
    screenshots = artifacts.get_all_screenshots()
    by_category = artifacts.get_screenshots_by_category()

    pass_count = sum(1 for s in screenshots if s.status == "pass")
    fail_count = sum(1 for s in screenshots if s.status == "fail")
    skip_count = sum(1 for s in screenshots if s.status == "skip")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    sidebar_links = ""
    for cat in by_category:
        anchor = cat.lower().replace(" ", "-")
        sidebar_links += f'<a href="#{anchor}" class="nav-link">{cat}</a>\n'

    category_sections = ""
    for cat, entries in by_category.items():
        anchor = cat.lower().replace(" ", "-")
        steps = ""
        for entry in entries:
            status_class = f"status-{entry.status}"
            step_cls = f"step-{entry.status}"
            status_icon = {"pass": "PASS", "fail": "FAIL", "skip": "SKIP"}.get(
                entry.status, "?"
            )
            step_num = entry.step_number or 0
            steps += f"""
            <div class="timeline-step {step_cls}" data-step="{step_num}">
                <div class="timeline-step-content">
                    <div class="step-header">
                        <span class="step-title">{entry.display_name}</span>
                        <span class="badge {status_class}">{status_icon}</span>
                    </div>
                    <div class="step-image-wrap">
                        <img
                            src="data:image/png;base64,{entry.b64_png}"
                            alt="{entry.display_name}"
                            class="screenshot-img"
                            onclick="openLightbox(this)"
                        />
                    </div>
                    <p class="step-meta">{entry.detail} &middot; {entry.width}&times;{entry.height} &middot; {entry.timestamp[:19]}</p>
                </div>
            </div>"""
        category_sections += f"""
        <section id="{anchor}" class="category-section">
            <h2 class="category-title">{cat}</h2>
            <div class="timeline">
                {steps}
            </div>
        </section>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: #f5f5f5;
    color: #333;
    display: flex;
    min-height: 100vh;
}}
.sidebar {{
    position: fixed;
    top: 0; left: 0;
    width: 250px;
    height: 100vh;
    background: #1a1a2e;
    color: #ccc;
    padding: 24px 16px;
    overflow-y: auto;
    z-index: 100;
}}
.sidebar h1 {{
    font-size: 16px;
    color: #fff;
    margin-bottom: 8px;
    line-height: 1.3;
}}
.sidebar .meta {{
    font-size: 12px;
    color: #888;
    margin-bottom: 20px;
    line-height: 1.6;
}}
.nav-link {{
    display: block;
    color: #aaa;
    text-decoration: none;
    padding: 8px 12px;
    border-radius: 4px;
    margin-bottom: 2px;
    font-size: 13px;
}}
.nav-link:hover {{ background: #16213e; color: #fff; }}
.main {{
    margin-left: 250px;
    flex: 1;
    padding: 32px;
}}
.header {{
    background: #fff;
    padding: 24px;
    border-radius: 8px;
    margin-bottom: 24px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}}
.header h2 {{ font-size: 22px; margin-bottom: 8px; }}
.header .summary {{
    display: flex;
    gap: 16px;
    font-size: 14px;
    margin-top: 12px;
}}
.header .summary span {{
    padding: 4px 12px;
    border-radius: 12px;
    font-weight: 600;
}}
.summary-pass {{ background: #e8f5e9; color: #2e7d32; }}
.summary-fail {{ background: #ffebee; color: #c62828; }}
.summary-skip {{ background: #f5f5f5; color: #757575; }}
.category-section {{ margin-bottom: 40px; }}
.category-title {{
    font-size: 18px;
    padding-bottom: 8px;
    margin-bottom: 20px;
    border-bottom: 2px solid #e0e0e0;
    color: #1a1a2e;
}}
.timeline {{
    position: relative;
    padding-left: 48px;
}}
.timeline::before {{
    content: '';
    position: absolute;
    left: 17px;
    top: 0;
    bottom: 0;
    width: 2px;
    background: linear-gradient(to bottom, #c5cae9, #e0e0e0);
}}
.timeline-step {{
    position: relative;
    margin-bottom: 28px;
    padding-left: 16px;
}}
.timeline-step::before {{
    content: attr(data-step);
    position: absolute;
    left: -39px;
    top: 8px;
    width: 36px;
    height: 36px;
    border-radius: 50%;
    background: #4caf50;
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
    font-size: 13px;
    z-index: 2;
    box-shadow: 0 2px 6px rgba(0,0,0,0.15);
}}
.timeline-step.step-pass::before {{ background: #4caf50; }}
.timeline-step.step-fail::before {{ background: #f44336; }}
.timeline-step.step-skip::before {{ background: #9e9e9e; }}
.timeline-step.step-0::before {{
    content: '';
    background: #7986cb;
}}
.timeline-step-content {{
    background: #fff;
    border-radius: 8px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.08);
    overflow: hidden;
    border: 1px solid #eee;
}}
.step-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 16px;
    border-bottom: 1px solid #f0f0f0;
    background: #fafafa;
}}
.step-title {{
    font-size: 14px;
    font-weight: 600;
    color: #333;
}}
.badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
}}
.badge.status-pass {{ background: #e8f5e9; color: #2e7d32; }}
.badge.status-fail {{ background: #ffebee; color: #c62828; }}
.badge.status-skip {{ background: #f5f5f5; color: #757575; }}
.step-image-wrap {{
    padding: 12px 16px;
    background: #fff;
}}
.screenshot-img {{
    max-width: 600px;
    width: 100%;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    cursor: pointer;
    display: block;
}}
.step-meta {{
    padding: 8px 16px 10px;
    font-size: 12px;
    color: #999;
    background: #fafafa;
    border-top: 1px solid #f0f0f0;
    margin: 0;
}}
@media (max-width: 900px) {{
    .sidebar {{ display: none; }}
    .main {{ margin-left: 0; }}
    .timeline {{ padding-left: 36px; }}
    .timeline::before {{ left: 12px; }}
    .timeline-step::before {{ left: -30px; width: 30px; height: 30px; font-size: 11px; }}
    .screenshot-img {{ max-width: 100%; }}
}}
.lightbox {{
    display: none;
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: rgba(0,0,0,0.85);
    z-index: 1000;
    justify-content: center;
    align-items: center;
    cursor: pointer;
}}
.lightbox.active {{ display: flex; }}
.lightbox img {{
    max-width: 90vw;
    max-height: 90vh;
    border-radius: 4px;
    box-shadow: 0 0 40px rgba(0,0,0,0.5);
}}
</style>
</head>
<body>
<aside class="sidebar">
    <h1>{title}</h1>
    <div class="meta">
        {now}<br/>
        {len(screenshots)} screenshots<br/>
        <span style="color:#4caf50">{pass_count} pass</span> ·
        <span style="color:#f44336">{fail_count} fail</span> ·
        <span style="color:#9e9e9e">{skip_count} skip</span>
    </div>
    {sidebar_links}
</aside>
<main class="main">
    <div class="header">
        <h2>{title}</h2>
        <div class="summary">
            <span class="summary-pass">✓ {pass_count} passed</span>
            <span class="summary-fail">✗ {fail_count} failed</span>
            <span class="summary-skip">— {skip_count} skipped</span>
        </div>
    </div>
    {category_sections}
</main>
<div class="lightbox" id="lightbox" onclick="closeLightbox()">
    <img id="lightbox-img" src="" alt="Enlarged screenshot"/>
</div>
<script>
function openLightbox(el) {{
    var lb = document.getElementById('lightbox');
    var img = document.getElementById('lightbox-img');
    img.src = el.src;
    lb.classList.add('active');
}}
function closeLightbox() {{
    document.getElementById('lightbox').classList.remove('active');
}}
document.addEventListener('keydown', function(e) {{
    if (e.key === 'Escape') closeLightbox();
}});
</script>
</body>
</html>"""


def generate_html_report(
    artifacts: VisualTestArtifacts,
    title: str = "Visual Test Report",
) -> Optional[Path]:
    try:
        html = _build_html(artifacts, title)
        report_path = artifacts.artifact_dir / "report.html"
        report_path.write_text(html, encoding="utf-8")
        return report_path
    except Exception:
        return None


def record_event(
    event: dict[str, Any], log_path: Path, events: list | None = None
) -> None:
    event["_timestamp"] = time.time()
    event["_datetime"] = datetime.now(timezone.utc).isoformat()
    if events is not None:
        events.append(event)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
