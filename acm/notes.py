"""The solver's annotations, either exported from IDA or typed by hand.

`notes.json` is written by `ida/export_comments.py` (run inside IDA, either from
the GUI or headless by this tool). `notes.md` is a plain-text fallback for when
you would rather just describe what you found.

Both are optional: a challenge can be submitted with no notes at all, it just
costs the "understanding" part of the score.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

NOTES_JSON = "notes.json"
NOTES_MARKDOWN = "notes.md"

# IDA's own generated names, which say nothing about understanding. Note that a
# bare leading "a" (IDA's `aSomeString` style) is deliberately *not* filtered:
# real renames like `aes_key` start with it.
AUTO_NAME_PREFIXES = (
    "sub_",
    "loc_",
    "unk_",
    "nullsub_",
    "byte_",
    "word_",
    "dword_",
    "qword_",
    "off_",
    "def_",
    "j_",
    "asc_",
    "flt_",
    "dbl_",
    "str_",
    "utf16_",
    "anonymous_",
)


@dataclass
class Comment:
    text: str
    function: str = ""
    ea: str = ""
    repeatable: bool = False
    kind: str = "line"


@dataclass
class Notes:
    source: str = "none"
    comments: list[Comment] = field(default_factory=list)
    function_comments: list[Comment] = field(default_factory=list)
    renames: list[tuple[str, str]] = field(default_factory=list)
    free_text: str = ""
    exported_at: float = 0.0
    ida_version: str = ""

    @property
    def text(self) -> str:
        """Every scrap of annotation, lowercased, for keyword matching."""
        parts = [c.text for c in self.comments]
        parts += [c.text for c in self.function_comments]
        parts += [name for _, name in self.renames]
        if self.free_text:
            parts.append(self.free_text)
        return "\n".join(parts).lower()

    @property
    def comment_count(self) -> int:
        return len(self.comments) + len(self.function_comments)

    @property
    def commented_functions(self) -> int:
        """Distinct functions the solver bothered to annotate."""
        names = {c.function for c in self.comments if c.function}
        names |= {c.function or c.ea for c in self.function_comments}
        return len(names)

    @property
    def renamed(self) -> int:
        """Renames that are not IDA's own auto-generated names."""
        return sum(
            1
            for _, name in self.renames
            if name and not name.startswith(AUTO_NAME_PREFIXES)
        )

    def is_empty(self) -> bool:
        return not (self.comment_count or self.renames or self.free_text.strip())


def load_notes(directory: Path) -> Notes:
    """Read whichever notes exist in a challenge directory."""
    notes = Notes()
    json_path = Path(directory) / NOTES_JSON
    if json_path.exists():
        notes = _from_json(json_path, notes)

    text_path = Path(directory) / NOTES_MARKDOWN
    if text_path.exists():
        try:
            free = text_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            free = ""
        # A template that was never filled in does not count as notes.
        notes.free_text = "" if _looks_like_template(free) else free
        if notes.free_text:
            notes.source = "both" if notes.source == "ida" else "text"

    if notes.source == "none" and not notes.is_empty():
        notes.source = "ida"
    return notes


def _from_json(path: Path, notes: Notes) -> Notes:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return notes
    if not isinstance(raw, dict):
        return notes

    for entry in raw.get("comments") or []:
        if not isinstance(entry, dict):
            continue
        text = str(entry.get("text") or "").strip()
        if text:
            notes.comments.append(
                Comment(
                    text=text,
                    function=str(entry.get("function") or ""),
                    ea=str(entry.get("ea") or ""),
                    repeatable=bool(entry.get("repeatable")),
                )
            )
    for entry in raw.get("function_comments") or []:
        if not isinstance(entry, dict):
            continue
        text = str(entry.get("text") or "").strip()
        if text:
            notes.function_comments.append(
                Comment(text=text, function=str(entry.get("name") or ""), ea=str(entry.get("ea") or ""), kind="function")
            )
    for entry in raw.get("renames") or []:
        if isinstance(entry, dict) and entry.get("name"):
            notes.renames.append((str(entry.get("ea") or ""), str(entry["name"])))

    notes.exported_at = float(raw.get("exported_at") or 0.0)
    notes.ida_version = str(raw.get("ida_version") or "")
    if notes.comment_count or notes.renames:
        notes.source = "ida"
    return notes


def _looks_like_template(text: str) -> bool:
    """True for the untouched blank that `new` writes."""
    meaningful = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith(("#", "-", "<!--"))
    ]
    return not meaningful
