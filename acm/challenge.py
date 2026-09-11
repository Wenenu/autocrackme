"""Where a challenge lives on disk.

    challenges/crackme_001/
        crackme.exe            <- open this in IDA
        notes.md               <- optional hand-written notes
        notes.json             <- written by the IDA export
        submission.json        <- what was reported, and how it scored
        .solution/             <- everything that spoils the puzzle
            crackme.c
            build.bat
            answer.json

The split exists so the play area stays clean and the answer is available for
scoring, hints and rebuilds without being in your face.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .composer import Composition
from .config import Settings
from .generator import Generated
from .notes import NOTES_JSON

SOLUTION_DIR = ".solution"
ANSWER_NAME = "answer.json"
SUBMISSION_NAME = "submission.json"
NOTES_MARKDOWN = "notes.md"
SOURCE_NAME = "crackme.c"


def challenge_dir(settings: Settings, challenge_id: int) -> Path:
    return Path(settings.challenges_dir) / f"crackme_{challenge_id:03d}"


def solution_dir(directory: Path) -> Path:
    return Path(directory) / SOLUTION_DIR


def answer_path(directory: Path) -> Path:
    return solution_dir(directory) / ANSWER_NAME


def exe_path(directory: Path) -> Path:
    return Path(directory) / "crackme.exe"


def latest_challenge_id(settings: Settings) -> int | None:
    """Highest numbered challenge directory that exists on disk."""
    root = Path(settings.challenges_dir)
    if not root.exists():
        return None
    found = []
    for entry in root.iterdir():
        if entry.is_dir() and entry.name.startswith("crackme_"):
            suffix = entry.name[len("crackme_") :]
            if suffix.isdigit():
                found.append(int(suffix))
    return max(found) if found else None


def save_answer(directory: Path, generated: Generated, *, hints: list[str], verified: bool) -> Path:
    """Record the answer and how the challenge was built, inside .solution/."""
    comp = generated.composition
    payload: dict[str, Any] = {
        "challenge_id": comp.challenge_id,
        "seed": comp.seed,
        "password": generated.password,
        "format": comp.format,
        "techniques": list(comp.techniques),
        "features": asdict(comp.features),
        "cost": comp.cost,
        "fingerprint": comp.fingerprint,
        "internals": generated.internals,
        "hints": hints,
        "hints_seen": [],
        "verified": verified,
        "created_at": time.time(),
    }
    path = answer_path(directory)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    return path


def load_answer(directory: Path) -> dict[str, Any]:
    path = answer_path(directory)
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def mark_hints_seen(directory: Path, hint_numbers: list[int]) -> None:
    answer = load_answer(directory)
    if not answer:
        return
    seen = {int(n) for n in answer.get("hints_seen") or []}
    seen.update(int(n) for n in hint_numbers)
    answer["hints_seen"] = sorted(seen)
    answer_path(directory).write_text(
        json.dumps(answer, indent=2, default=str) + "\n", encoding="utf-8"
    )


def save_submission(directory: Path, payload: dict[str, Any]) -> Path:
    path = Path(directory) / SUBMISSION_NAME
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    return path


def write_notes_template(directory: Path, composition: Composition) -> Path:
    """Drop in a blank notes.md, but never overwrite one that has content."""
    path = Path(directory) / NOTES_MARKDOWN
    if path.exists():
        return path
    path.write_text(
        f"# Notes for crackme_{composition.challenge_id:03d}\n"
        "\n"
        "Annotate in IDA if you like (line comments, function comments, renamed\n"
        "functions) and run `python autocrackme.py export` to pull them out.\n"
        "\n"
        "Or write here instead — what each comparison does, which constants matter,\n"
        "and how you derived the answer. These notes are what decides which\n"
        "challenges get generated next, so describing the mechanism pays off.\n"
        "\n"
        "<!-- Everything in this file is read, except comment-only templates like this one. -->\n",
        encoding="utf-8",
    )
    return path


def notes_path(directory: Path) -> Path:
    return Path(directory) / NOTES_JSON
