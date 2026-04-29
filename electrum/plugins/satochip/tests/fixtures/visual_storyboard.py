"""
visual_storyboard.py -- Figma-like interactive storyboard HTML generator.

Generates a self-contained HTML file that presents visual test results as an
interactive prototype/storyboard.  Frames are organised by story (s0-s3) and
rendered with navigation, presentation mode, and keyboard shortcuts.
"""

import base64
import json
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class StoryboardFrame:
    """Single frame in the storyboard -- either a screenshot or a state-only snapshot."""

    step_number: int
    story_id: str  # "s0", "s1", "s2", "s3"
    story_name: str  # "Factory Reset", "Wallet Setup", "PIN Block", "PUK Recovery"
    title: str  # "Pre-reset Settings"
    annotation: str  # "Settings dialog showing card state before factory reset"
    frame_type: str  # "screenshot" or "state_snapshot"
    card_state_before: dict  # {"setup_done": False, "is_seeded": False, ...}
    card_state_after: dict  # Same keys, values after this step
    b64_png: str  # base64-encoded PNG, empty string for state_snapshot frames
    timestamp: str  # ISO 8601
    width: int  # screenshot width, 0 for state_snapshot
    height: int  # screenshot height, 0 for state_snapshot


class StoryboardBuilder:
    """Collects storyboard frames and generates the interactive HTML presentation."""

    def __init__(self) -> None:
        self._frames: list[StoryboardFrame] = []

    def add_frame(self, frame: StoryboardFrame) -> None:
        self._frames.append(frame)

    def get_frames_by_story(self) -> dict[str, list[StoryboardFrame]]:
        result: dict[str, list[StoryboardFrame]] = {}
        for f in self._frames:
            result.setdefault(f.story_id, []).append(f)
        return result

    def get_all_frames(self) -> list[StoryboardFrame]:
        return list(self._frames)

    def generate_html(self, title: str = "Satochip Visual Storyboard") -> str:
        return _build_storyboard_html(self, title)

    def write_html(self, path: Path, title: str = "Satochip Visual Storyboard") -> Path:
        html = self.generate_html(title)
        path.write_text(html, encoding="utf-8")
        return path


def _read_png_dimensions(path: Path) -> tuple[int, int]:
    """Read width and height directly from the PNG IHDR header (bytes 16-24)."""
    raw = path.read_bytes()
    if len(raw) < 24 or raw[:8] != b"\x89PNG\r\n\x1a\n":
        return (0, 0)
    width = struct.unpack(">I", raw[16:20])[0]
    height = struct.unpack(">I", raw[20:24])[0]
    return (width, height)


def _infer_state_label(card_state: dict) -> str:
    """Map a card state dict to a human-readable label.

    Priority order:
      - PIN0_remaining_tries == 0  -> "Blocked"
      - setup_done == False       -> "FactoryFresh"
      - setup_done and not seeded -> "Seedless"
      - setup_done and seeded     -> "Ready"
    """
    pin_tries = card_state.get("PIN0_remaining_tries", card_state.get("PIN_remaining_tries", -1))
    if pin_tries == 0:
        return "Blocked"
    if not card_state.get("setup_done", False):
        return "FactoryFresh"
    if not card_state.get("is_seeded", False):
        return "Seedless"
    return "Ready"


def add_screenshot_frame(
    builder: StoryboardBuilder,
    step_number: int,
    story_id: str,
    story_name: str,
    title: str,
    annotation: str,
    card_state_before: dict,
    card_state_after: dict,
    screenshot_path: Path,
) -> None:
    """Read screenshot from *path*, encode to base64, add as screenshot frame."""
    b64 = base64.b64encode(screenshot_path.read_bytes()).decode("ascii")
    width, height = _read_png_dimensions(screenshot_path)
    builder.add_frame(
        StoryboardFrame(
            step_number=step_number,
            story_id=story_id,
            story_name=story_name,
            title=title,
            annotation=annotation,
            frame_type="screenshot",
            card_state_before=card_state_before,
            card_state_after=card_state_after,
            b64_png=b64,
            timestamp=datetime.now(timezone.utc).isoformat(),
            width=width,
            height=height,
        )
    )


def add_state_snapshot_frame(
    builder: StoryboardBuilder,
    step_number: int,
    story_id: str,
    story_name: str,
    title: str,
    annotation: str,
    card_state_before: dict,
    card_state_after: dict,
) -> None:
    """Add a state-only frame (no screenshot -- shows as an info card)."""
    builder.add_frame(
        StoryboardFrame(
            step_number=step_number,
            story_id=story_id,
            story_name=story_name,
            title=title,
            annotation=annotation,
            frame_type="state_snapshot",
            card_state_before=card_state_before,
            card_state_after=card_state_after,
            b64_png="",
            timestamp=datetime.now(timezone.utc).isoformat(),
            width=0,
            height=0,
        )
    )


def _build_storyboard_html(builder: StoryboardBuilder, title: str) -> str:
    """Build a complete self-contained HTML string from the collected frames."""
    by_story = builder.get_frames_by_story()

    story_data: dict[str, Any] = {}
    for story_id, frames in by_story.items():
        story_data[story_id] = {
            "name": frames[0].story_name if frames else story_id,
            "frames": [
                {
                    "step_number": f.step_number,
                    "title": f.title,
                    "annotation": f.annotation,
                    "frame_type": f.frame_type,
                    "card_state_before": f.card_state_before,
                    "card_state_after": f.card_state_after,
                    "b64_png": f.b64_png,
                    "timestamp": f.timestamp,
                    "width": f.width,
                    "height": f.height,
                    "state_before": _infer_state_label(f.card_state_before),
                    "state_after": _infer_state_label(f.card_state_after),
                }
                for f in frames
            ],
        }

    story_json = json.dumps(story_data, ensure_ascii=False)

    from electrum.plugins.satochip.tests.fixtures.storyboard_mermaid import (
        GLOBAL_STATE_MACHINE,
        STORY_DIAGRAMS,
        mermaid_div,
    )

    global_mermaid = mermaid_div(GLOBAL_STATE_MACHINE, "global-state-machine")
    story_mermaids: dict[str, str] = {}
    for sid, diagram in STORY_DIAGRAMS.items():
        story_mermaids[sid] = mermaid_div(diagram, f"story-diagram-{sid}")

    first = True
    story_buttons = ""
    for story_id in sorted(story_data):
        info = story_data[story_id]
        count = len(info["frames"])
        active_cls = " active" if first else ""
        story_buttons += (
            f'<button data-story="{story_id}" class="story-btn{active_cls}" '
            f'onclick="switchStory(\'{story_id}\')">'
            f"Story {story_id[1:]}: {info['name']} ({count} steps)</button>\n"
        )
        first = False

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    story_mermaid_json = json.dumps(story_mermaids)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
/* ===== Reset & base ===== */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
html, body {{ height: 100%; }}
body {{
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
    background: #fafafa;
    color: #1a1a2e;
    display: flex;
    overflow: hidden;
}}

/* ===== Sidebar ===== */
.sidebar {{
    position: fixed;
    top: 0; left: 0;
    width: 260px;
    height: 100vh;
    background: #1e1e2e;
    color: #ccc;
    display: flex;
    flex-direction: column;
    z-index: 100;
    overflow-y: auto;
    overflow-x: hidden;
}}
.sidebar h1 {{
    font-size: 14px;
    font-weight: 600;
    color: #fff;
    padding: 20px 16px 4px;
    line-height: 1.4;
}}
.sidebar .meta {{
    font-size: 11px;
    color: #666;
    padding: 0 16px 16px;
    border-bottom: 1px solid #2a2a3e;
}}

/* Story buttons */
.story-list {{
    padding: 12px 10px;
    display: flex;
    flex-direction: column;
    gap: 2px;
}}
.story-btn {{
    background: transparent;
    border: none;
    color: #9a9ab0;
    font-size: 12px;
    text-align: left;
    padding: 8px 10px;
    border-radius: 6px;
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}}
.story-btn:hover {{ background: #2a2a3e; color: #ccc; }}
.story-btn.active {{ background: #30304a; color: #fff; font-weight: 500; }}

/* Step list */
.step-list {{
    padding: 8px 10px 20px;
    display: flex;
    flex-direction: column;
    gap: 1px;
    flex: 1;
}}
.step-btn {{
    background: transparent;
    border: none;
    color: #8888a0;
    font-size: 12px;
    text-align: left;
    padding: 7px 10px;
    border-radius: 5px;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 8px;
    transition: background 0.12s, color 0.12s;
}}
.step-btn:hover {{ background: #2a2a3e; color: #bbb; }}
.step-btn.active {{ background: #3a3a5c; color: #fff; }}
.step-num {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    background: #2a2a3e;
    font-size: 10px;
    font-weight: 600;
    flex-shrink: 0;
}}
.step-btn.active .step-num {{ background: #5b5bf0; color: #fff; }}
.step-title {{
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}}

/* ===== Canvas area ===== */
.canvas-area {{
    margin-left: 260px;
    flex: 1;
    display: flex;
    flex-direction: column;
    height: 100vh;
    position: relative;
    overflow-y: auto;
}}

/* Minimap */
.minimap {{
    padding: 14px 32px 0;
    flex-shrink: 0;
}}
.minimap-track {{
    display: flex;
    align-items: center;
    gap: 0;
    position: relative;
    padding: 0 6px;
}}
.minimap-dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #d0d0d8;
    cursor: pointer;
    transition: background 0.2s, transform 0.2s, box-shadow 0.2s;
    position: relative;
    z-index: 2;
    flex-shrink: 0;
}}
.minimap-dot.active {{
    background: #5b5bf0;
    transform: scale(1.5);
    box-shadow: 0 0 0 3px rgba(91,91,240,0.25);
}}
.minimap-dot:hover {{ background: #8888b0; }}
.minimap-line {{
    flex: 1;
    height: 2px;
    background: #e0e0e8;
    min-width: 8px;
}}

/* Frame viewer */
.frame-viewer {{
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 20px 32px;
    overflow-y: auto;
}}
.frame {{
    max-width: 1000px;
    width: 100%;
    animation: frameIn 0.25s ease-out;
}}
.frame-main {{
    width: 100%;
}}
@keyframes frameIn {{
    from {{ opacity: 0; transform: translateY(8px); }}
    to   {{ opacity: 1; transform: translateY(0); }}
}}

/* Frame canvas (screenshot) */
.frame-canvas {{
    background: #fff;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08), 0 0 0 1px rgba(0,0,0,0.03);
    overflow: hidden;
    display: flex;
    justify-content: center;
    align-items: center;
}}
.frame-canvas img {{
    display: block;
    max-width: 100%;
    max-height: 55vh;
    width: auto;
    height: auto;
    object-fit: contain;
}}

.state-badge {{
    display: inline-block;
    padding: 4px 14px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 500;
}}
.state-badge.before {{
    background: #ececf0;
    color: #555;
}}
.state-badge.after {{
    background: #e8f5e9;
    color: #2e7d32;
}}
.state-badge.FactoryFresh {{ background: #ececf0; color: #757575; }}
.state-badge.Seedless     {{ background: #fff3e0; color: #f57c00; }}
.state-badge.Ready        {{ background: #e8f5e9; color: #2e7d32; }}
.state-badge.Blocked      {{ background: #ffebee; color: #c62828; }}

.state-bar {{
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    background: #f7f7fb;
    border-radius: 8px;
    margin-top: 12px;
    flex-wrap: wrap;
}}
.state-bar-arrow {{
    color: #aaa;
    font-size: 16px;
}}
.state-bar .detail-chip {{
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 3px 10px;
    background: #fff;
    border-radius: 6px;
    font-size: 11px;
    color: #555;
}}
.state-bar .detail-chip .key {{ color: #999; }}
.state-bar .detail-chip .changed {{ color: #c62828; font-weight: 600; }}

/* Frame info */
.frame-info {{
    margin-top: 16px;
    padding: 0 4px;
}}
.frame-info h3 {{
    font-size: 15px;
    font-weight: 600;
    color: #1a1a2e;
    margin-bottom: 4px;
}}
.frame-info .annotation {{
    font-size: 13px;
    color: #777;
    margin-bottom: 10px;
    line-height: 1.5;
}}
.frame-meta {{
    font-size: 11px;
    color: #aaa;
}}

/* ===== Frame controls ===== */
.frame-controls {{
    padding: 12px 32px 20px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 12px;
    flex-shrink: 0;
}}
.frame-controls button {{
    background: #fff;
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 8px 18px;
    font-size: 13px;
    color: #444;
    cursor: pointer;
    transition: background 0.15s, border-color 0.15s, box-shadow 0.15s;
}}
.frame-controls button:hover {{
    background: #f5f5fa;
    border-color: #c0c0d0;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
}}
.frame-controls button:active {{
    background: #eeeef4;
}}
.frame-controls button.btn-present {{
    background: #5b5bf0;
    color: #fff;
    border-color: #5b5bf0;
}}
.frame-controls button.btn-present:hover {{
    background: #4848e0;
    border-color: #4848e0;
}}
.step-counter {{
    font-size: 13px;
    color: #888;
    min-width: 56px;
    text-align: center;
    font-variant-numeric: tabular-nums;
}}

/* ===== Presentation mode ===== */
body.presentation-mode .sidebar {{ display: none; }}
body.presentation-mode .canvas-area {{ margin-left: 0; }}
body.presentation-mode .minimap {{ display: none; }}
body.presentation-mode .frame-controls {{
    position: fixed;
    bottom: 20px;
    left: 50%;
    transform: translateX(-50%);
    background: rgba(30,30,46,0.85);
    border-radius: 24px;
    padding: 8px 24px;
    z-index: 200;
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
}}
body.presentation-mode .frame-controls button {{
    background: rgba(255,255,255,0.12);
    border-color: rgba(255,255,255,0.2);
    color: #fff;
}}
body.presentation-mode .frame-controls button:hover {{
    background: rgba(255,255,255,0.2);
}}
body.presentation-mode .frame-controls button.btn-present {{
    background: rgba(255,255,255,0.25);
    border-color: rgba(255,255,255,0.3);
}}
body.presentation-mode .frame-controls .step-counter {{ color: #ccc; }}
body.presentation-mode .frame-info {{
    position: fixed;
    bottom: 80px;
    left: 50%;
    transform: translateX(-50%);
    background: rgba(30,30,46,0.85);
    color: #eee;
    border-radius: 10px;
    padding: 12px 24px;
    z-index: 200;
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    text-align: center;
    max-width: 90vw;
}}
body.presentation-mode .frame-info h3 {{ color: #fff; }}
body.presentation-mode .frame-info .annotation {{ color: #bbb; }}
body.presentation-mode .frame-info .frame-meta {{ color: #888; }}
body.presentation-mode .state-badges .badge {{
    background: rgba(255,255,255,0.12);
    color: #ddd;
}}
body.presentation-mode .frame-canvas img {{
    max-width: 90vw;
    max-height: 80vh;
    object-fit: contain;
}}
body.presentation-mode .frame-viewer {{
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    padding: 24px;
}}
body.presentation-mode .frame-canvas {{
    background: transparent;
    box-shadow: none;
}}
body.presentation-mode .state-bar {{
    background: rgba(255,255,255,0.1);
}}
body.presentation-mode .state-bar .detail-chip {{
    background: rgba(255,255,255,0.08);
    color: #ccc;
}}

@media (max-width: 960px) {{
    .frame {{ max-width: 100%; }}
}}

/* Empty state */
.empty-state {{
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 80px 20px;
    color: #bbb;
    text-align: center;
}}
.empty-state h2 {{
    font-size: 18px;
    font-weight: 500;
    color: #999;
    margin-bottom: 8px;
}}
.empty-state p {{ font-size: 13px; color: #bbb; }}
.mermaid {{ max-width: 100%; }}
.mermaid-container {{ overflow-y: auto; }}
.mermaid-container svg {{ max-width: 100% !important; }}
.state-banner {{ width: 100%; padding: 20px 32px; background: #1e1e2e; flex-shrink: 0; }}
.state-banner-inner {{ max-width: 1200px; margin: 0 auto; }}
.state-banner h2 {{ color: #ccc; font-size: 13px; font-weight: 500; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }}
.state-banner .mermaid-container {{ max-height: 180px; overflow: hidden; background: #2a2a3e; border-radius: 8px; padding: 16px; transition: max-height 0.3s ease; }}
.state-banner.expanded .mermaid-container {{ max-height: none; }}
.banner-toggle {{ background: none; border: 1px solid #444; color: #888; font-size: 11px; padding: 3px 10px; border-radius: 4px; cursor: pointer; margin-left: 12px; vertical-align: middle; }}
.banner-toggle:hover {{ color: #ccc; border-color: #666; }}
</style>
</head>
<body>

<aside class="sidebar">
    <h1>{title}</h1>
    <div class="meta">{now_str}</div>
    <nav class="story-list">
        {story_buttons}
    </nav>
    <div style="padding: 10px 14px; border-bottom: 1px solid #2a2a3e;">
        <div style="font-size: 10px; color: #666; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px;">State Machine</div>
        <div class="mermaid-container" style="background: #fff; border-radius: 6px; padding: 8px; overflow-x: auto; max-height: 480px;">
            {global_mermaid}
        </div>
    </div>
    <div class="step-list" id="stepList">
        <!-- populated by JS -->
    </div>
</aside>

<main class="canvas-area">
    <div class="state-banner" id="stateBanner">
        <div class="state-banner-inner">
            <h2>Card State Machine <button class="banner-toggle" onclick="toggleBanner()">Expand</button></h2>
            <div class="mermaid-container">
                {global_mermaid}
            </div>
        </div>
    </div>
    <div class="minimap">
        <div class="minimap-track" id="minimapTrack">
            <!-- populated by JS -->
        </div>
    </div>

    <div class="frame-viewer" id="frameViewer">
        <!-- populated by JS -->
    </div>

    <div class="frame-controls">
        <button class="btn-prev" onclick="prevStep()">&#8592; Previous</button>
        <span class="step-counter" id="stepCounter">- / -</span>
        <button class="btn-next" onclick="nextStep()">Next &#8594;</button>
        <button class="btn-present" onclick="togglePresentation()">Present</button>
    </div>
</main>

<script>
// ===== Data =====
const STORYBOARD_DATA = {story_json};
const STORY_MERMAIDS = {story_mermaid_json};

// ===== State =====
let currentStory = Object.keys(STORYBOARD_DATA).sort()[0] || "";
let currentStep = 0;
let isPresentation = false;

// ===== Render helpers =====

function badgeClass(label) {{
    const map = {{
        "FactoryFresh": "FactoryFresh",
        "Seedless":     "Seedless",
        "Ready":        "Ready",
        "Blocked":      "Blocked",
    }};
    return map[label] || "";
}}

function renderStepList() {{
    const el = document.getElementById("stepList");
    if (!currentStory || !STORYBOARD_DATA[currentStory]) {{
        el.innerHTML = "";
        return;
    }}
    const frames = STORYBOARD_DATA[currentStory].frames;
    let html = "";
    for (let i = 0; i < frames.length; i++) {{
        const active = i === currentStep ? " active" : "";
        html += '<button class="step-btn' + active + '" data-step="' + i + '" '
              + 'onclick="goToStep(' + i + ')">'
              + '<span class="step-num">' + (i + 1) + '</span>'
              + '<span class="step-title">' + escHtml(frames[i].title) + '</span>'
              + '</button>';
    }}
    el.innerHTML = html;
}}

function renderMinimap() {{
    const el = document.getElementById("minimapTrack");
    if (!currentStory || !STORYBOARD_DATA[currentStory]) {{
        el.innerHTML = "";
        return;
    }}
    const frames = STORYBOARD_DATA[currentStory].frames;
    let html = "";
    for (let i = 0; i < frames.length; i++) {{
        if (i > 0) html += '<span class="minimap-line"></span>';
        const active = i === currentStep ? " active" : "";
        html += '<span class="minimap-dot' + active + '" data-step="' + i + '" '
              + 'onclick="goToStep(' + i + ')"></span>';
    }}
    el.innerHTML = html;
}}

function renderFrame() {{
    const viewer = document.getElementById("frameViewer");
    if (!currentStory || !STORYBOARD_DATA[currentStory]) {{
        viewer.innerHTML = '<div class="empty-state"><h2>No frames</h2>'
                         + '<p>Add frames to see the storyboard.</p></div>';
        document.getElementById("stepCounter").textContent = "- / -";
        return;
    }}
    const frames = STORYBOARD_DATA[currentStory].frames;
    if (currentStep >= frames.length) currentStep = frames.length - 1;
    if (currentStep < 0) currentStep = 0;
    const f = frames[currentStep];

    document.getElementById("stepCounter").textContent =
        (currentStep + 1) + " / " + frames.length;

    let canvasHtml = "";
    if (f.frame_type === "screenshot" && f.b64_png) {{
        canvasHtml = '<img src="data:image/png;base64,' + f.b64_png + '" '
                   + 'alt="' + escHtml(f.title) + '" />';
    }}

    let stateBarHtml = renderStateBar(f);

    let meta = "";
    if (f.width && f.height) {{
        meta = f.width + " x " + f.height + " . ";
    }}
    meta += f.timestamp ? f.timestamp.substring(0, 19) : "";

    viewer.innerHTML = '<div class="frame" data-story="' + currentStory + '" data-step="' + currentStep + '">'
      +   '<div class="frame-main">'
      +     '<div class="frame-canvas">' + canvasHtml + '</div>'
      +     '<div class="frame-info">'
      +       '<h3>Step ' + (currentStep + 1) + ': ' + escHtml(f.title) + '</h3>'
      +       '<p class="annotation">' + escHtml(f.annotation) + '</p>'
      +       '<div class="frame-meta">' + meta + '</div>'
      +     '</div>'
      +     stateBarHtml
      +   '</div>'
      + '</div>';
}}

function renderStateBar(f) {{
    let beforeLabel = f.state_before || "unknown";
    let afterLabel = f.state_after || "unknown";
    let chips = "";
    const before = f.card_state_before || {{}};
    const after  = f.card_state_after  || {{}};
    const allKeys = Object.keys(Object.assign({{}}, before, after));
    allKeys.sort();
    for (const key of allKeys) {{
        const bv = formatVal(before[key]);
        const av = formatVal(after[key]);
        const changed = bv !== av ? " changed" : "";
        if (changed) {{
            chips += '<span class="detail-chip">'
                   + '<span class="key">' + escHtml(key) + ':</span> '
                   + '<span class="' + changed + '">' + escHtml(bv) + ' &rarr; ' + escHtml(av) + '</span>'
                   + '</span>';
        }}
    }}
    return '<div class="state-bar">'
         +   '<span class="state-badge ' + badgeClass(beforeLabel) + '">' + escHtml(beforeLabel) + '</span>'
         +   '<span class="state-bar-arrow">&rarr;</span>'
         +   '<span class="state-badge ' + badgeClass(afterLabel) + '">' + escHtml(afterLabel) + '</span>'
         +   chips
         + '</div>';
}}

function formatVal(v) {{
    if (v === undefined || v === null) return "-";
    return String(v);
}}

function escHtml(s) {{
    if (!s) return "";
    return String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}}

// ===== Navigation =====

function switchStory(storyId) {{
    currentStory = storyId;
    currentStep = 0;

    // Update active story button
    document.querySelectorAll(".story-btn").forEach(function(btn) {{
        btn.classList.toggle("active", btn.dataset.story === storyId);
    }});

    renderStepList();
    renderMinimap();
    renderFrame();
}}

function goToStep(idx) {{
    if (!currentStory || !STORYBOARD_DATA[currentStory]) return;
    const frames = STORYBOARD_DATA[currentStory].frames;
    if (idx < 0 || idx >= frames.length) return;
    currentStep = idx;
    renderStepList();
    renderMinimap();
    renderFrame();
}}

function nextStep() {{
    if (!currentStory || !STORYBOARD_DATA[currentStory]) return;
    const frames = STORYBOARD_DATA[currentStory].frames;
    if (currentStep < frames.length - 1) {{
        goToStep(currentStep + 1);
    }}
}}

function prevStep() {{
    if (currentStep > 0) {{
        goToStep(currentStep - 1);
    }}
}}

function togglePresentation() {{
    isPresentation = !isPresentation;
    document.body.classList.toggle("presentation-mode", isPresentation);
}}

function toggleBanner() {{
    const banner = document.getElementById("stateBanner");
    const btn = banner.querySelector(".banner-toggle");
    banner.classList.toggle("expanded");
    btn.textContent = banner.classList.contains("expanded") ? "Collapse" : "Expand";
}}

function exitPresentation() {{
    if (isPresentation) {{
        isPresentation = false;
        document.body.classList.remove("presentation-mode");
    }}
}}

// ===== Keyboard shortcuts =====
document.addEventListener("keydown", function(e) {{
    if (e.key === "ArrowRight") nextStep();
    else if (e.key === "ArrowLeft") prevStep();
    else if (e.key === "Escape") exitPresentation();
    else if (e.key === "f" || e.key === "F") togglePresentation();
}});

// ===== Initialise =====
window.addEventListener("DOMContentLoaded", function() {{
    const firstStory = Object.keys(STORYBOARD_DATA).sort()[0] || "";
    if (firstStory) {{
        switchStory(firstStory);
    }} else {{
        renderFrame();
    }}
}});
</script>
<script type="module">
import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/+esm';
mermaid.initialize({{ startOnLoad: true, theme: 'dark', themeVariables: {{ fontSize: '14px', fontFamily: 'system-ui' }}, flowchart: {{ useMaxWidth: true }} }});
</script>
</body>
</html>"""
