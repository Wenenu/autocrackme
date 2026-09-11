"""Turns a solver's annotations into a score and per-technique observations.

The score deliberately rewards *understanding* over outcome: solving counts, but
being able to explain the check in your own IDA comments counts more, and
patching past a check while staying silent about how it works is penalised. That
is what keeps the generated challenges aimed at the solver's actual weak spots.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .composer import Composition
from .config import DEFAULT_WEIGHTS
from .notes import Notes
from .techniques import BYPASS_WORDS, POOL, UNDERSTANDING_WORDS

# How many lexicon hits count as full credit for a technique.
HITS_FOR_FULL_CREDIT = 2
# Comments/renames needed for full credit on the "understanding" signal.
FULL_CREDIT_COMMENTS = 8
FULL_CREDIT_RENAMES = 3
FULL_CREDIT_FUNCTIONS = 3
FULL_CREDIT_HINTS = 3
# A bypass only counts against you if it is not backed by understanding.
BYPASS_COVERAGE_FLOOR = 0.35


@dataclass
class Signal:
    """One scored input, kept so the decision can be shown and argued with."""

    name: str
    weight: float
    value: float
    detail: str = ""

    @property
    def contribution(self) -> float:
        return self.weight * self.value

    def line(self) -> str:
        return f"{self.name:<15} {self.value:>5.2f} × {self.weight:+.2f} = {self.contribution:+.3f}  {self.detail}"


@dataclass
class Assessment:
    score: float
    signals: list[Signal] = field(default_factory=list)
    coverage: dict[str, float] = field(default_factory=dict)
    bypassed: bool = False

    def lines(self) -> list[str]:
        return [signal.line() for signal in self.signals]


def lexicon_coverage(text: str, technique: str) -> float:
    """How much of a technique's vocabulary shows up in the notes (0..1)."""
    terms = POOL[technique].lexicon if technique in POOL else ()
    if not text or not terms:
        return 0.0
    hits = sum(1 for term in terms if term in text)
    return min(1.0, hits / HITS_FOR_FULL_CREDIT)


def mentions_bypass(text: str) -> bool:
    return any(word in text for word in BYPASS_WORDS)


def assess(
    notes: Notes,
    composition: Composition,
    *,
    solved: bool,
    hints_used: int = 0,
    minutes: float | None = None,
    expected_minutes: float = 30.0,
    weights: dict[str, float] | None = None,
) -> Assessment:
    """Score this attempt from 0..1, with every input recorded for inspection."""
    weights = weights or DEFAULT_WEIGHTS
    text = notes.text

    coverage = {name: lexicon_coverage(text, name) for name in composition.techniques}
    technique_value = sum(coverage.values()) / len(coverage) if coverage else 0.0

    renamed_part = min(1.0, notes.renamed / FULL_CREDIT_RENAMES)
    function_part = min(1.0, notes.commented_functions / FULL_CREDIT_FUNCTIONS)
    vocab_part = 1.0 if any(word in text for word in UNDERSTANDING_WORDS) else 0.0
    understanding_value = 0.4 * renamed_part + 0.4 * function_part + 0.2 * vocab_part

    effort_value = min(1.0, notes.comment_count / FULL_CREDIT_COMMENTS)
    bypassed = mentions_bypass(text) and technique_value < BYPASS_COVERAGE_FLOOR
    hints_value = min(1.0, hints_used / FULL_CREDIT_HINTS)

    if minutes is None:
        speed_value = 0.5
        speed_detail = "no timing reported, neutral"
    elif minutes <= expected_minutes:
        speed_value = 1.0
        speed_detail = f"{minutes:.0f} min vs {expected_minutes:.0f} expected"
    else:
        speed_value = max(0.0, expected_minutes / minutes)
        speed_detail = f"{minutes:.0f} min vs {expected_minutes:.0f} expected"

    signals = [
        Signal("solved", weights.get("solved", 0.35), 1.0 if solved else 0.0,
               "binary accepted your answer" if solved else "not solved"),
        Signal("technique", weights.get("technique", 0.25), technique_value,
               ", ".join(f"{n}={c:.2f}" for n, c in coverage.items()) or "no layers"),
        Signal("understanding", weights.get("understanding", 0.15), understanding_value,
               f"{notes.renamed} renames, {notes.commented_functions} functions annotated"),
        Signal("effort", weights.get("effort", 0.10), effort_value,
               f"{notes.comment_count} comments"),
        Signal("speed", weights.get("speed", 0.10), speed_value, speed_detail),
        Signal("bypass", weights.get("bypass", -0.15), 1.0 if bypassed else 0.0,
               "patched without explaining" if bypassed else "no patch-and-hope detected"),
        Signal("hints", weights.get("hints", -0.10), hints_value, f"{hints_used} hints used"),
    ]

    positive = sum(s.weight for s in signals if s.weight > 0) or 1.0
    score = sum(s.contribution for s in signals) / positive
    return Assessment(
        score=max(0.0, min(1.0, score)),
        signals=signals,
        coverage=coverage,
        bypassed=bypassed,
    )


def technique_observations(
    composition: Composition, assessment: Assessment, *, solved: bool
) -> dict[str, dict[str, object]]:
    """Per-technique evidence to fold into the profile."""
    return {
        name: {
            "coverage": round(assessment.coverage.get(name, 0.0), 4),
            "bypassed": bool(assessment.bypassed),
            "solved": bool(solved),
        }
        for name in composition.techniques
    }
