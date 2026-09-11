"""What the tool has observed about the solver.

Two things are tracked, both persisted in history.json:

*   `Profile.skill` — one continuous 0..1 estimate of overall ability. This drives
    how much challenge the composer is allowed to build (budget, layer count,
    obfuscation).
*   `Profile.techniques` — per-technique evidence: how often a technique has been
    seen, whether it was solved, how well the accompanying notes showed it was
    understood, and whether it was defeated by patching instead. This drives
    *which* techniques the composer picks: unseen ones are surfaced, weak ones
    are reinforced, mastered ones are retired.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TechniqueStat:
    """Evidence about one technique, accumulated across challenges."""

    seen: int = 0
    solved: int = 0
    understanding: float = 0.0
    bypassed: int = 0
    last_challenge: int = 0

    @property
    def mastery(self) -> float:
        """How well this technique is handled: mostly understanding, gated by solving."""
        if self.seen <= 0:
            return 0.0
        solve_rate = self.solved / self.seen
        return max(0.0, min(1.0, self.understanding * 0.7 + solve_rate * 0.3))

    def to_json(self) -> dict[str, Any]:
        return {
            "seen": self.seen,
            "solved": self.solved,
            "understanding": round(self.understanding, 4),
            "bypassed": self.bypassed,
            "last_challenge": self.last_challenge,
        }

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "TechniqueStat":
        return cls(
            seen=int(raw.get("seen", 0)),
            solved=int(raw.get("solved", 0)),
            understanding=float(raw.get("understanding", 0.0)),
            bypassed=int(raw.get("bypassed", 0)),
            last_challenge=int(raw.get("last_challenge", 0)),
        )


@dataclass
class Profile:
    """Everything observed about the solver, used to compose the next challenge."""

    skill: float = 0.0
    solved: int = 0
    attempted: int = 0
    hints_used: int = 0
    techniques: dict[str, TechniqueStat] = field(default_factory=dict)
    recent_fingerprints: list[str] = field(default_factory=list)

    def stat(self, technique: str) -> TechniqueStat:
        return self.techniques.setdefault(technique, TechniqueStat())

    def note_seen(self, techniques: list[str], challenge_id: int) -> None:
        for name in techniques:
            stat = self.stat(name)
            stat.seen += 1
            stat.last_challenge = challenge_id

    def record_fingerprint(self, fingerprint: str, keep: int = 12) -> None:
        self.recent_fingerprints.append(fingerprint)
        del self.recent_fingerprints[:-keep]

    def to_json(self) -> dict[str, Any]:
        return {
            "skill": round(self.skill, 4),
            "solved": self.solved,
            "attempted": self.attempted,
            "hints_used": self.hints_used,
            "techniques": {name: stat.to_json() for name, stat in sorted(self.techniques.items())},
            "recent_fingerprints": self.recent_fingerprints,
        }

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "Profile":
        profile = cls(
            skill=float(raw.get("skill", 0.0)),
            solved=int(raw.get("solved", 0)),
            attempted=int(raw.get("attempted", 0)),
            hints_used=int(raw.get("hints_used", 0)),
        )
        techniques = raw.get("techniques")
        if isinstance(techniques, dict):
            for name, value in techniques.items():
                if isinstance(value, dict):
                    profile.techniques[str(name)] = TechniqueStat.from_json(value)
        fingerprints = raw.get("recent_fingerprints")
        if isinstance(fingerprints, list):
            profile.recent_fingerprints = [str(f) for f in fingerprints]
        return profile
