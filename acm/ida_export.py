"""Driving IDA headlessly to pull the solver's comments out of a database.

The database is copied before being opened, because IDA refuses to open a
database that the GUI already has open — and the copy is a snapshot of whatever
was last saved, which is exactly what we want to read.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .build import EXE_NAME
from .config import ROOT, Settings
from .notes import NOTES_JSON

IDA_SCRIPT = ROOT / "ida" / "export_comments.py"
LOG_NAME = "ida_export.log"
DATABASE_SUFFIXES = (".i64", ".idb")


@dataclass
class ExportResult:
    ok: bool
    notes_path: Path
    message: str
    log: str = ""


def find_database(directory: Path) -> Path | None:
    """Prefer a saved IDA database, falling back to the binary itself."""
    for suffix in DATABASE_SUFFIXES:
        candidate = Path(directory) / f"{EXE_NAME}{suffix}"
        if candidate.exists():
            return candidate
    binary = Path(directory) / EXE_NAME
    return binary if binary.exists() else None


def export_notes(directory: Path, settings: Settings, *, timeout: int | None = None) -> ExportResult:
    """Run IDA over this challenge's database and write notes.json into it."""
    directory = Path(directory)
    notes_path = directory / NOTES_JSON

    if not settings.idat:
        return ExportResult(
            False, notes_path, "IDA not found: install it or set \"ida_path\" in config.json"
        )

    database = find_database(directory)
    if database is None:
        return ExportResult(False, notes_path, f"no {EXE_NAME} or saved database to analyse yet")

    has_saved_db = database.suffix.lower() in DATABASE_SUFFIXES
    limit = timeout or settings.ida_timeout
    log_path = directory / LOG_NAME

    with tempfile.TemporaryDirectory(prefix="acm_ida_") as tmp:
        target = Path(tmp) / database.name
        shutil.copy2(database, target)  # never fight the GUI for the original
        environment = dict(os.environ, ACM_NOTES_OUT=str(notes_path), ACM_HEADLESS="1")
        command = [
            str(settings.idat),
            "-A",
            f"-S{IDA_SCRIPT}",
            f"-L{log_path}",
            str(target),
        ]
        try:
            proc = subprocess.run(
                command,
                cwd=tmp,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=limit,
            )
        except subprocess.TimeoutExpired:
            return ExportResult(False, notes_path, f"IDA timed out after {limit}s")
        except OSError as exc:
            return ExportResult(False, notes_path, f"could not start IDA: {exc}")

    log = ""
    if log_path.exists():
        log = log_path.read_text(encoding="utf-8", errors="replace").strip()[-2000:]

    if not notes_path.exists():
        detail = log.splitlines()[-1] if log else f"exit code {proc.returncode}"
        return ExportResult(False, notes_path, f"IDA did not produce notes ({detail})", log)

    if not has_saved_db:
        return ExportResult(
            True,
            notes_path,
            "analysed the binary directly: no saved database yet, so any notes you "
            "wrote in IDA are not in there. Use Ctrl+W in IDA to save, then export again",
            log,
        )
    return ExportResult(True, notes_path, "notes exported from IDA", log)
