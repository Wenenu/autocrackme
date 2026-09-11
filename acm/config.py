"""Paths, settings, and toolchain discovery (MSVC cl.exe, IDA idat.exe)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config.json"
HISTORY_PATH = ROOT / "history.json"
DEFAULT_CHALLENGES_DIR = ROOT / "challenges"

# Weights for the skill score. Positive signals reward understanding, and the
# two negative ones punish patch-and-hope and leaning on hints.
DEFAULT_WEIGHTS: dict[str, float] = {
    "solved": 0.35,
    "technique": 0.25,
    "understanding": 0.15,
    "effort": 0.10,
    "speed": 0.10,
    "bypass": -0.15,
    "hints": -0.10,
}


def _glob_any(patterns: list[str]) -> list[Path]:
    found: list[Path] = []
    for pattern in patterns:
        for base in (Path("C:/"), Path("D:/"), Path("E:/")):
            if not base.exists():
                continue
            try:
                found.extend(base.glob(pattern))
            except OSError:
                continue
    return found


def find_vcvars() -> Path | None:
    """Locate vcvars64.bat from any Visual Studio 2022+ install."""
    patterns = [
        "Program Files*/Microsoft Visual Studio/*/*/VC/Auxiliary/Build/vcvars64.bat",
        "Program Files*/Microsoft Visual Studio/*/BuildTools/VC/Auxiliary/Build/vcvars64.bat",
        "Program Files*/Microsoft Visual Studio/*/*/VC/Auxiliary/Build/vcvarsall.bat",
    ]
    for match in sorted(str(p) for p in _glob_any(patterns)):
        path = Path(match)
        if path.name.lower() == "vcvarsall.bat":
            path = path.with_name("vcvars64.bat")
            if not path.exists():
                continue
        return path
    return None


def find_idat() -> Path | None:
    """Locate IDA's text-mode executable, which is what headless exports need."""
    patterns = [
        "*IDA*/idat.exe",
        "*IDA*/*/idat.exe",
        "*IDA*/*/*/idat.exe",
        "Program Files/*IDA*/idat.exe",
        "Program Files (x86)/*IDA*/idat.exe",
    ]
    for match in sorted(str(p) for p in _glob_any(patterns)):
        return Path(match)
    return None


@dataclass
class Settings:
    challenges_dir: Path = DEFAULT_CHALLENGES_DIR
    vcvars: Path | None = None
    idat: Path | None = None
    arch: str = "x64"
    optimize: bool = True
    ida_timeout: int = 300
    antidebug: bool = True
    start_level: int = 1
    skill_alpha: float = 0.35
    expected_minutes_base: float = 20.0
    expected_minutes_per_level: float = 15.0
    weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    # Raw "composer" block from config.json; parsed by composer.Policy.from_json.
    composer_raw: dict[str, Any] | None = None

    def expected_minutes(self, level: int) -> float:
        """Roughly how long a challenge at this level should take."""
        return self.expected_minutes_base + self.expected_minutes_per_level * (level - 1)


def load_settings(path: Path | None = None) -> Settings:
    """Read config.json if present; anything missing falls back to detection."""
    config_path = Path(path) if path else CONFIG_PATH
    raw: dict[str, Any] = {}
    if config_path.exists():
        try:
            raw = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{config_path}: invalid JSON ({exc})") from exc
        if not isinstance(raw, dict):
            raise ValueError(f"{config_path}: expected a JSON object")

    settings = Settings()
    settings.challenges_dir = Path(raw.get("challenges_dir") or DEFAULT_CHALLENGES_DIR)
    settings.vcvars = Path(raw["vcvars_path"]) if raw.get("vcvars_path") else find_vcvars()
    settings.idat = Path(raw["ida_path"]) if raw.get("ida_path") else find_idat()
    settings.arch = str(raw.get("arch", "x64"))
    settings.optimize = bool(raw.get("optimize", True))
    settings.ida_timeout = int(raw.get("ida_timeout_seconds", 300))
    settings.antidebug = bool(raw.get("antidebug", True))
    settings.start_level = int(raw.get("start_level", 1))
    settings.skill_alpha = float(raw.get("skill_alpha", 0.35))
    settings.expected_minutes_base = float(raw.get("expected_minutes_base", 20))
    settings.expected_minutes_per_level = float(raw.get("expected_minutes_per_level", 15))
    if isinstance(raw.get("weights"), dict):
        weights = dict(DEFAULT_WEIGHTS)
        for key, value in raw["weights"].items():
            weights[str(key)] = float(value)
        settings.weights = weights
    if isinstance(raw.get("composer"), dict):
        # Kept raw: composer.Policy.from_json applies it, ignoring unknown keys
        # and raising a clear error for a value it cannot cast.
        settings.composer_raw = dict(raw["composer"])

    if not 0 <= settings.skill_alpha <= 1:
        raise ValueError("skill_alpha must be between 0 and 1")
    if settings.arch not in ("x64", "x86"):
        raise ValueError("arch must be 'x64' or 'x86'")
    if settings.start_level < 1 or settings.start_level > 10:
        raise ValueError("start_level must be between 1 and 10")
    return settings
