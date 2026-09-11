"""Persistent history: every attempt, and the profile derived from them.

history.json is the memory that makes challenges adapt. It holds the skill
estimate, the per-technique evidence and the recent structure fingerprints, so
restarting the tool never restarts the learning.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import HISTORY_PATH
from .profile import Profile, TechniqueStat

VERSION = 1


@dataclass
class Attempt:
    """One generated challenge and what happened with it."""

    challenge_id: int
    fingerprint: str
    format: str
    techniques: list[str]
    features: str
    password: str
    solved: bool = False
    score: float = 0.0
    minutes: float | None = None
    hints_used: int = 0
    notes_source: str = "none"
    comments: int = 0
    renames: int = 0
    signals: list[dict[str, Any]] = field(default_factory=list)
    created_at: float = 0.0
    submitted_at: float = 0.0

    def to_json(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "fingerprint": self.fingerprint,
            "format": self.format,
            "techniques": self.techniques,
            "features": self.features,
            "password": self.password,
            "solved": self.solved,
            "score": round(self.score, 4),
            "minutes": self.minutes,
            "hints_used": self.hints_used,
            "notes_source": self.notes_source,
            "comments": self.comments,
            "renames": self.renames,
            "signals": self.signals,
            "created_at": self.created_at,
            "submitted_at": self.submitted_at,
        }

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "Attempt":
        return cls(
            challenge_id=int(raw.get("challenge_id", 0)),
            fingerprint=str(raw.get("fingerprint", "")),
            format=str(raw.get("format", "")),
            techniques=[str(t) for t in raw.get("techniques") or []],
            features=str(raw.get("features", "")),
            password=str(raw.get("password", "")),
            solved=bool(raw.get("solved", False)),
            score=float(raw.get("score", 0.0)),
            minutes=None if raw.get("minutes") is None else float(raw["minutes"]),
            hints_used=int(raw.get("hints_used", 0)),
            notes_source=str(raw.get("notes_source", "none")),
            comments=int(raw.get("comments", 0)),
            renames=int(raw.get("renames", 0)),
            signals=list(raw.get("signals") or []),
            created_at=float(raw.get("created_at", 0.0)),
            submitted_at=float(raw.get("submitted_at", 0.0)),
        )


def blend_skill(previous: float, score: float, *, solved: bool, alpha: float) -> float:
    """Move the skill estimate toward the newest score.

    A failed attempt can only hold the estimate steady or lower it: one guess
    should never level anyone up.
    """
    updated = alpha * score + (1.0 - alpha) * previous
    if not solved:
        updated = min(updated, previous)
    return max(0.0, min(1.0, updated))


class History:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else HISTORY_PATH
        self.profile = Profile()
        self.attempts: list[Attempt] = []
        self.next_challenge_id = 1
        self.load()

    # -- persistence -------------------------------------------------------

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(raw, dict):
            return
        self.next_challenge_id = int(raw.get("next_challenge_id", 1))
        if isinstance(raw.get("profile"), dict):
            self.profile = Profile.from_json(raw["profile"])
        for entry in raw.get("attempts") or []:
            if isinstance(entry, dict):
                self.attempts.append(Attempt.from_json(entry))

    def save(self) -> None:
        payload = {
            "version": VERSION,
            "next_challenge_id": self.next_challenge_id,
            "profile": self.profile.to_json(),
            "attempts": [attempt.to_json() for attempt in self.attempts],
        }
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # -- queries -----------------------------------------------------------

    @property
    def last_attempt(self) -> Attempt | None:
        return self.attempts[-1] if self.attempts else None

    def attempt(self, challenge_id: int) -> Attempt | None:
        for item in reversed(self.attempts):
            if item.challenge_id == challenge_id:
                return item
        return None

    def register(self, attempt: Attempt) -> None:
        """Record a freshly generated challenge (before it is solved)."""
        self.attempts.append(attempt)
        self.profile.note_seen(attempt.techniques, attempt.challenge_id)
        self.profile.record_fingerprint(attempt.fingerprint)
        self.next_challenge_id = max(self.next_challenge_id, attempt.challenge_id + 1)
        self.save()

    # -- learning ----------------------------------------------------------

    def learn(
        self,
        attempt: Attempt,
        *,
        score: float,
        solved: bool,
        observations: dict[str, dict[str, object]],
        alpha: float,
        hints_used: int = 0,
    ) -> tuple[float, float]:
        """Fold one result into the profile. Returns (old skill, new skill)."""
        previous = self.profile.skill
        self.profile.skill = blend_skill(previous, score, solved=solved, alpha=alpha)

        for name, obs in observations.items():
            stat: TechniqueStat = self.profile.stat(name)
            coverage = float(obs.get("coverage", 0.0))
            stat.understanding = alpha * coverage + (1.0 - alpha) * stat.understanding
            if obs.get("solved"):
                stat.solved += 1
            if obs.get("bypassed"):
                stat.bypassed += 1

        attempt.score = score
        attempt.solved = solved
        attempt.hints_used = hints_used
        attempt.submitted_at = time.time()
        self.profile.attempted += 1
        if solved:
            self.profile.solved += 1
        self.profile.hints_used += hints_used
        self.save()
        return previous, self.profile.skill
