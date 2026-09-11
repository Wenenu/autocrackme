"""Composes each challenge from the whole pool, based on the observed profile.

There is no fixed ordering of techniques. Every run:

1.  sizes a *budget* from the solver's skill estimate,
2.  picks a password format, weighted by how much the format's techniques are
    currently needed,
3.  stacks one to three techniques from that format's compatible set, weighted
    so that unseen techniques get surfaced, weak ones get reinforced and
    mastered ones get retired,
4.  spends whatever budget is left on obfuscation (masked strings, opaque
    predicates, a decoy function, junk arithmetic, anti-debug),
5.  rejects anything structurally close to a recent challenge and re-rolls.

Because the password is fixed before the layers are instantiated, every layer
checks the *same* answer in a different way — that is what makes stacking
solvable rather than contradictory.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field, replace
from typing import Any, Iterable

from .profile import Profile
from .techniques import FORMATS, PASSWORD_SOURCES, POOL, Technique


@dataclass
class Policy:
    """Tunable policy for what to build next. Override under "composer" in config.json."""

    budget_base: float = 5.0
    budget_skill: float = 28.0
    max_layers: int = 3
    novelty_weight: float = 3.0
    reinforce_weight: float = 2.5
    retire_weight: float = 0.25
    weak_threshold: float = 0.35
    strong_threshold: float = 0.70
    bypass_weight_mult: float = 1.4
    cooldown_mult: float = 0.35
    recent_cooldown: int = 2
    repeat_window: int = 6
    compose_attempts: int = 12

    @classmethod
    def from_json(cls, raw: dict[str, Any] | None) -> "Policy":
        policy = cls()
        if not isinstance(raw, dict):
            return policy
        for key, value in raw.items():
            if not hasattr(policy, key):
                continue
            current = getattr(policy, key)
            try:
                setattr(policy, key, type(current)(value))
            except (TypeError, ValueError):
                raise ValueError(f"composer.{key}: expected {type(current).__name__}")
        return policy


@dataclass(frozen=True)
class Features:
    """Obfuscation the challenge is built with."""

    encrypt_strings: bool = False
    opaque_predicates: bool = False
    decoy_function: bool = False
    antidebug: bool = False
    junk: int = 0

    def flags(self) -> str:
        bits = []
        if self.encrypt_strings:
            bits.append("strings")
        if self.opaque_predicates:
            bits.append("opaque")
        if self.decoy_function:
            bits.append("decoy")
        if self.antidebug:
            bits.append("antidbg")
        if self.junk:
            bits.append("junk%d" % self.junk)
        return "+".join(bits) or "none"

    def labels(self) -> list[str]:
        out = []
        if self.encrypt_strings:
            out.append("masked strings")
        if self.opaque_predicates:
            out.append("opaque predicate")
        if self.decoy_function:
            out.append("decoy function")
        if self.antidebug:
            out.append("anti-debug check")
        if self.junk:
            out.append(f"{self.junk} junk ops")
        return out


@dataclass(frozen=True)
class Composition:
    """The structure of one challenge, reproducible from its seed.

    The password is deliberately absent: it is derived by the generator (some
    techniques dictate its shape) and lives on the Generated result.
    """

    seed: int
    challenge_id: int
    format: str
    techniques: tuple[str, ...]
    features: Features
    cost: int
    fingerprint: str

    @property
    def format_title(self) -> str:
        return FORMATS[self.format].title

    @property
    def titles(self) -> list[str]:
        return [POOL[name].title for name in self.techniques]

    def describe(self) -> str:
        layers = " + ".join(self.titles)
        extras = self.features.labels()
        suffix = f" [{', '.join(extras)}]" if extras else ""
        return f"{layers} · {self.format_title}{suffix}"


# What each obfuscation feature costs out of the budget, and how likely it is to
# be picked at a given skill level: chance = base + ramp * skill.
_FEATURE_COST = {"encrypt_strings": 4, "opaque_predicates": 3, "decoy_function": 4, "antidebug": 3}
_FEATURE_CHANCE = {
    "encrypt_strings": (0.20, 0.70),
    "opaque_predicates": (0.10, 0.70),
    "decoy_function": (0.05, 0.80),
    "antidebug": (0.00, 0.60),
}
# Anti-debug is only rolled in once the solver is clearly comfortable, and only
# if it is enabled in config.
_ANTIDEBUG_MIN_SKILL = 0.70


def compose(
    profile: Profile,
    policy: Policy,
    *,
    seed: int,
    challenge_id: int,
    allow_antidebug: bool = True,
) -> Composition:
    """Build the next challenge, avoiding anything structurally recent."""
    rng = random.Random(seed)
    recent = set(profile.recent_fingerprints[-policy.repeat_window :])
    previous = profile.recent_fingerprints[-1] if profile.recent_fingerprints else ""

    candidate: Composition | None = None
    for _ in range(max(1, policy.compose_attempts)):
        candidate = _roll(rng, profile, policy, seed, challenge_id, allow_antidebug)
        if candidate.fingerprint in recent:
            continue
        if previous and _technique_set(candidate.fingerprint) == _technique_set(previous):
            continue
        return candidate

    assert candidate is not None
    return candidate


def _technique_set(fingerprint: str) -> str:
    parts = fingerprint.split("|")
    return parts[1] if len(parts) > 1 else fingerprint


def _weight(profile: Profile, policy: Policy, technique: Technique, challenge_id: int) -> float:
    """How much this technique should be used next, given what has been observed."""
    stat = profile.techniques.get(technique.name)
    if stat is None or stat.seen == 0:
        return policy.novelty_weight  # never seen: surface it

    mastery = stat.mastery
    if mastery < policy.weak_threshold:
        weight = policy.reinforce_weight  # struggled with it: bring it back
    elif mastery > policy.strong_threshold:
        weight = policy.retire_weight  # mastered: rarely repeat it
    else:
        weight = 1.0

    if stat.bypassed:
        weight *= policy.bypass_weight_mult  # patched rather than solved: try again
    if challenge_id - stat.last_challenge <= policy.recent_cooldown:
        weight *= policy.cooldown_mult  # keep consecutive challenges varied
    return max(weight, 0.01)


def _roll(
    rng: random.Random,
    profile: Profile,
    policy: Policy,
    seed: int,
    challenge_id: int,
    allow_antidebug: bool,
) -> Composition:
    skill = max(0.0, min(1.0, profile.skill))
    budget = policy.budget_base + policy.budget_skill * skill
    max_layers = max(1, min(policy.max_layers, 1 + int(skill * 2.5)))

    weights = {name: _weight(profile, policy, tech, challenge_id) for name, tech in POOL.items()}

    # Choose the format by how much the techniques it enables are needed.
    format_scores: dict[str, float] = {}
    for fname, fmt in FORMATS.items():
        compatible = [t for t in POOL.values() if fname in t.formats and t.cost <= budget]
        if not compatible:
            continue
        ranked = sorted((weights[t.name] for t in compatible), reverse=True)
        format_scores[fname] = sum(ranked[:2]) * (1.0 + rng.random() * 0.25)
    if not format_scores:
        format_scores = {"generic": 1.0}
    chosen_format = _weighted_choice(rng, format_scores)

    # Stack layers that will all check the same password.
    candidates = [
        t for t in POOL.values() if chosen_format in t.formats and t.cost <= budget
    ]
    layers: list[Technique] = []
    remaining = budget
    while candidates and len(layers) < max_layers:
        affordable = [t for t in candidates if t.cost <= remaining]
        if not affordable:
            break
        pool = {t.name: weights[t.name] for t in affordable}
        technique = POOL[_weighted_choice(rng, pool)]
        layers.append(technique)
        remaining -= technique.cost
        candidates = [t for t in candidates if t.name != technique.name]
        if technique.name in PASSWORD_SOURCES:
            # Only one layer may dictate the password's shape.
            candidates = [t for t in candidates if t.name not in PASSWORD_SOURCES]

    if not layers:  # budget below the cheapest technique: still return something
        layers = [min(POOL.values(), key=lambda t: t.cost)]

    cost = sum(t.cost for t in layers)
    features = _roll_features(rng, policy, skill, remaining, allow_antidebug)

    names = tuple(t.name for t in layers)
    fingerprint = "|".join([chosen_format, "+".join(names), features.flags()])
    return Composition(
        seed=seed,
        challenge_id=challenge_id,
        format=chosen_format,
        techniques=names,
        features=features,
        cost=cost,
        fingerprint=fingerprint,
    )


def _roll_features(
    rng: random.Random,
    policy: Policy,
    skill: float,
    leftover: float,
    allow_antidebug: bool,
) -> Features:
    choices = dict(
        encrypt_strings=False,
        opaque_predicates=False,
        decoy_function=False,
        antidebug=False,
    )
    order = list(_FEATURE_COST)
    rng.shuffle(order)

    for name in order:
        if name == "antidebug" and (not allow_antidebug or skill < _ANTIDEBUG_MIN_SKILL):
            continue
        cost = _FEATURE_COST[name]
        if cost > leftover:
            continue
        base, ramp = _FEATURE_CHANCE[name]
        if rng.random() <= base + ramp * skill:
            choices[name] = True
            leftover -= cost

    junk = int(leftover // 2) if leftover >= 2 else 0
    junk = min(junk, 10)
    return Features(junk=junk, **choices)


def _weighted_choice(rng: random.Random, weights: dict[str, float]) -> str:
    total = sum(max(0.0, w) for w in weights.values())
    if total <= 0:
        return sorted(weights)[0]
    pick = rng.random() * total
    upto = 0.0
    for key in sorted(weights):
        upto += max(0.0, weights[key])
        if pick <= upto:
            return key
    return sorted(weights)[-1]


def explain(profile: Profile, policy: Policy, composition: Composition) -> list[str]:
    """Why this challenge was built this way — printed by `next` and `status`."""
    lines = [
        f"skill estimate {profile.skill:.2f} → challenge budget "
        f"{policy.budget_base + policy.budget_skill * profile.skill:.0f} "
        f"(used {composition.cost}), up to {max(1, min(policy.max_layers, 1 + int(profile.skill * 2.5)))} layers",
    ]
    for name in composition.techniques:
        stat = profile.techniques.get(name)
        if stat is None or stat.seen == 0:
            lines.append(f"  {name}: never seen before, picked for novelty")
        else:
            reason = "needs work" if stat.mastery < policy.weak_threshold else (
                "mastered, kept rare" if stat.mastery > policy.strong_threshold else "mid-progress"
            )
            lines.append(
                f"  {name}: seen {stat.seen}x, solved {stat.solved}x, "
                f"understanding {stat.understanding:.2f} ({reason})"
            )
    return lines


def pool_summary(profile: Profile, policy: Policy, challenge_id: int) -> list[tuple[str, float, str]]:
    """The whole pool with its current selection weight, for `status`."""
    rows = []
    for name, tech in sorted(POOL.items(), key=lambda kv: _weight(profile, policy, kv[1], challenge_id), reverse=True):
        stat = profile.techniques.get(name)
        if stat is None or stat.seen == 0:
            note = "unseen"
        else:
            note = f"seen {stat.seen}, solved {stat.solved}, u={stat.understanding:.2f}"
            if stat.bypassed:
                note += f", patched {stat.bypassed}x"
        rows.append((name, _weight(profile, policy, tech, challenge_id), note))
    return rows
