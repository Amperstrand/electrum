"""Mermaid.js state diagram generator for the Satochip card lifecycle storyboard."""

from typing import Optional


GLOBAL_STATE_MACHINE = r"""stateDiagram-v2
    direction TB
    [*] --> FACTORY_RESET: Card installed
    FACTORY_RESET --> INITIALIZED: card_setup\n(PIN, PUK, memsize)
    INITIALIZED --> SEEDED: seed_import\n(BIP39 mnemonic)
    SEEDED --> PIN_BLOCKED: 3x wrong PIN\n(PIN0_remaining = 0)
    PIN_BLOCKED --> SEEDED: PUK unblock\n(reset PIN)
    SEEDED --> FACTORY_RESET: Factory reset\n(5x card swap)
    PIN_BLOCKED --> FACTORY_RESET: Factory reset\n(5x card swap)
"""

STORY_DIAGRAMS = {
    "s0": r"""stateDiagram-v2
    direction TB
    [*] --> AnyState: Card may be in any state
    AnyState --> FACTORY_RESET: APDU factory reset\n(or card already blank)
""",
    "s1": r"""stateDiagram-v2
    direction TB
    FACTORY_RESET --> INITIALIZED: card_setup\n(PIN, PUK)
    INITIALIZED --> SEEDED: seed_import\n(HUNGRY_MNEMONIC)
""",
    "s2": r"""stateDiagram-v2
    direction TB
    SEEDED --> SEEDED: wrong PIN #1\n(tries: 5→4)
    SEEDED --> SEEDED: wrong PIN #2\n(tries: 4→3)
    SEEDED --> SEEDED: wrong PIN #3\n(tries: 3→0)
    SEEDED --> PIN_BLOCKED: PIN0_remaining = 0
""",
    "s3": r"""stateDiagram-v2
    direction TB
    PIN_BLOCKED --> SEEDED: PUK unblock\n+ reset PIN\n(tries: 0→5)
""",
}


def _fmt_state(d: dict) -> str:
    if not d:
        return "unknown"
    if d.get("error"):
        return "error"
    lines = []
    if "setup_done" in d:
        lines.append(f"setup_done={d['setup_done']}")
    if "is_seeded" in d:
        lines.append(f"is_seeded={d['is_seeded']}")
    if "PIN0_remaining_tries" in d:
        lines.append(f"PIN_tries={d['PIN0_remaining_tries']}")
    if "protocol_version" in d:
        pv = d["protocol_version"]
        if isinstance(pv, int):
            lines.append(f"proto=v{pv >> 8}.{pv & 0xFF}")
        else:
            lines.append(f"proto={pv}")
    return "<br/>".join(lines) if lines else "unknown"


def transition_diagram(before: dict, after: dict, trigger: str) -> str:
    b = _fmt_state(before)
    a = _fmt_state(after)
    trigger_escaped = trigger.replace("\n", "<br/>")
    return (
        "stateDiagram-v2\n"
        "    direction LR\n"
        f"    Before: {b}\n"
        f"    After: {a}\n"
        f"    Before --> After: {trigger_escaped}\n"
    )


def story_path_diagram(story_id: str, transitions: list[tuple[str, str, str]]) -> str:
    lines = ["stateDiagram-v2", "    direction TB"]
    for i, (before, trigger, after) in enumerate(transitions):
        trigger_escaped = trigger.replace("\n", " ")
        lines.append(f"    {before} --> {after}: {trigger_escaped}")
    return "\n".join(lines) + "\n"


def mermaid_div(diagram_text: str, diagram_id: Optional[str] = None) -> str:
    did = f' id="{diagram_id}"' if diagram_id else ""
    escaped = diagram_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f'<div class="mermaid"{did}>{escaped}</div>'
