"""Command line interface.

Deliberately tight-lipped: `new`/`next` do not say which techniques the challenge
uses, because that is the puzzle. The reasoning is shown after a submission (and
on request with --show-reasoning), and `reveal` gives the answer when you want it.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from dataclasses import asdict
from pathlib import Path

from . import build as builder
from . import challenge as chal
from . import composer, generator, ida_export, skill
from .config import Settings, load_settings
from .history import Attempt, History
from .notes import load_notes
from .profile import Profile
from .techniques import POOL

# Elapsed wall time is only trusted as a speed signal up to this long; beyond it
# the gap almost certainly includes time away from the keyboard.
MAX_TRUSTED_ELAPSED_MINUTES = 8 * 60

BANNER = "autocrackme — generated IDA crackmes that follow how you work"


# -- helpers ----------------------------------------------------------------


def _print_header(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


def _resolve_challenge(settings: Settings, history: History, requested: int | None) -> int:
    """Pick the challenge to act on: the one asked for, else the newest."""
    if requested:
        return requested
    latest = chal.latest_challenge_id(settings)
    if latest is None:
        raise SystemExit("no challenges yet — run: python autocrackme.py new")
    return latest


def _policy(settings: Settings) -> composer.Policy:
    return composer.Policy.from_json(getattr(settings, "composer_raw", None))


def _profile(history: History) -> Profile:
    return history.profile


# -- commands ---------------------------------------------------------------


def cmd_new(args: argparse.Namespace, settings: Settings, history: History) -> int:
    policy = _policy(settings)
    challenge_id = history.next_challenge_id
    seed = random.SystemRandom().randrange(1 << 31)

    composition = composer.compose(
        history.profile,
        policy,
        seed=seed,
        challenge_id=challenge_id,
        allow_antidebug=settings.antidebug,
    )
    generated = generator.generate(composition)

    directory = chal.challenge_dir(settings, challenge_id)
    solution = chal.solution_dir(directory)
    solution.mkdir(parents=True, exist_ok=True)

    source_path = solution / chal.SOURCE_NAME
    source_path.write_text(generated.source, encoding="utf-8")

    hints = [hint for name in composition.techniques for hint in POOL[name].hints]
    chal.save_answer(directory, generated, hints=hints, verified=False)
    chal.write_notes_template(directory, composition)

    _print_header(f"crackme_{challenge_id:03d}")
    try:
        result = builder.build(
            directory,
            settings,
            source=f"{chal.SOLUTION_DIR}/{chal.SOURCE_NAME}",
            obj_dir=chal.SOLUTION_DIR,
        )
    except builder.BuildError as exc:
        print(f"build failed:\n{exc}")
        return 1

    # Prove the thing is actually solvable before handing it over.
    verified = builder.accepts(result.exe, generated.password)
    wrong_ok = not builder.accepts(result.exe, "obviously-not-the-answer")
    chal.save_answer(directory, generated, hints=hints, verified=verified and wrong_ok)
    if not (verified and wrong_ok):
        print("warning: self-verification failed — the generated crackme may not behave")

    # Explain against the profile *before* this challenge is folded into it,
    # otherwise a technique being seen for the first time reports "seen 1x".
    reasoning = composer.explain(history.profile, policy, composition)

    history.register(
        Attempt(
            challenge_id=challenge_id,
            fingerprint=composition.fingerprint,
            format=composition.format,
            techniques=list(composition.techniques),
            features=composition.features.flags(),
            password=generated.password,
            created_at=time.time(),
        )
    )

    print(f"binary     {chal.exe_path(directory)}")
    print(f"notes      {chal.notes_path(directory)}  or  {directory / chal.NOTES_MARKDOWN}")
    print(f"layers     {len(composition.techniques)}, budget used {composition.cost}")
    print("\nOpen the binary in IDA, work out the accepted input, then:")
    print(f"  python autocrackme.py export            # pull your IDA comments out")
    print(f"  python autocrackme.py submit --password <what you found>")
    print(f"  python autocrackme.py hint              # if you want a nudge")
    if args.show_reasoning:
        _print_header("why this challenge (spoilers)")
        for line in reasoning:
            print(f"  {line}")
        print(f"  it is: {composition.describe()}")
    return 0


def cmd_export(args: argparse.Namespace, settings: Settings, history: History) -> int:
    directory = chal.challenge_dir(settings, _resolve_challenge(settings, history, args.id))
    result = ida_export.export_notes(directory, settings)
    print(result.message)
    if not result.ok:
        return 1

    notes = load_notes(directory)
    print(
        f"read back: {notes.comment_count} comments, {notes.renamed} names, "
        f"{notes.commented_functions} annotated functions"
    )
    if notes.comment_count == 0 and notes.renamed == 0:
        print("nothing found yet — add comments in IDA and save the database (Ctrl+W)")
    return 0


def cmd_hint(args: argparse.Namespace, settings: Settings, history: History) -> int:
    challenge_id = _resolve_challenge(settings, history, args.id)
    directory = chal.challenge_dir(settings, challenge_id)
    answer = chal.load_answer(directory)
    if not answer:
        print(f"crackme_{challenge_id:03d} has no stored answer to hint from")
        return 1

    hints: list[str] = list(answer.get("hints") or [])
    if not hints:
        print("no hints recorded for this challenge")
        return 1

    limit = len(hints)
    if args.n is not None:
        limit = max(1, min(len(hints), args.n))
    _print_header(f"hints for crackme_{challenge_id:03d}")
    for index, hint in enumerate(hints[:limit], start=1):
        print(f"{index}. {hint}")

    seen = list(range(1, limit + 1))
    chal.mark_hints_seen(directory, seen)
    print(f"\n{limit} of {len(hints)} hints seen; these count against your score.")
    return 0


def cmd_reveal(args: argparse.Namespace, settings: Settings, history: History) -> int:
    challenge_id = _resolve_challenge(settings, history, args.id)
    directory = chal.challenge_dir(settings, challenge_id)
    answer = chal.load_answer(directory)
    if not answer:
        print(f"crackme_{challenge_id:03d} has no stored answer")
        return 1

    _print_header(f"crackme_{challenge_id:03d} — spoilers")
    print(f"answer     {answer.get('password')}")
    print(f"layers     {', '.join(answer.get('techniques') or [])}")
    print(f"format     {answer.get('format')}")
    print(f"features   {answer.get('features')}")
    for entry in answer.get("internals") or []:
        print(f"  - {entry}")
    return 0


def _elapsed_minutes(answer: dict) -> tuple[float | None, str]:
    created = float(answer.get("created_at") or 0.0)
    if not created:
        return None, "unknown"
    elapsed = (time.time() - created) / 60.0
    if elapsed > MAX_TRUSTED_ELAPSED_MINUTES:
        return None, f"{elapsed:.0f} min elapsed, treated as unknown"
    return elapsed, f"{elapsed:.0f} min since it was generated"


def cmd_submit(args: argparse.Namespace, settings: Settings, history: History) -> int:
    if not (args.password or args.solved or args.failed):
        print("report something: --password <text>, --solved or --failed")
        return 1

    challenge_id = _resolve_challenge(settings, history, args.id)
    directory = chal.challenge_dir(settings, challenge_id)
    answer = chal.load_answer(directory)
    if not answer:
        print(f"crackme_{challenge_id:03d} has no stored answer; was it generated by this tool?")
        return 1

    attempt = history.attempt(challenge_id) or Attempt(
        challenge_id=challenge_id,
        fingerprint=str(answer.get("fingerprint") or ""),
        format=str(answer.get("format") or ""),
        techniques=[str(t) for t in answer.get("techniques") or []],
        features="",
        password=str(answer.get("password") or ""),
    )
    composition = composer.Composition(
        seed=int(answer.get("seed") or 0),
        challenge_id=challenge_id,
        format=str(answer.get("format") or "generic"),
        techniques=tuple(str(t) for t in answer.get("techniques") or []),
        features=composer.Features(**(answer.get("features") or {})),
        cost=int(answer.get("cost") or 0),
        fingerprint=str(answer.get("fingerprint") or ""),
    )

    # Verify against the binary whenever possible: a claim is not evidence.
    solved = bool(args.solved)
    detail = "reported as solved by you"
    if args.password:
        exe = chal.exe_path(directory)
        if exe.exists():
            solved = builder.accepts(exe, args.password)
            detail = "binary accepted the password" if solved else "binary rejected the password"
        else:
            solved = args.password == answer.get("password")
            detail = "no binary to test, compared against the stored answer"
    elif args.failed:
        solved = False
        detail = "reported as unsolved"
    print(f"verdict: {'solved' if solved else 'not solved'} ({detail})")

    notes = load_notes(directory)
    if notes.source == "none":
        print("no notes found — annotate in IDA (then `export`) or write notes.md to earn credit")

    hints_seen = len(answer.get("hints_seen") or [])
    hints_used = args.hints if args.hints is not None else hints_seen
    if args.minutes is not None:
        minutes, minutes_note = float(args.minutes), f"{args.minutes} min (reported)"
    else:
        minutes, minutes_note = _elapsed_minutes(answer)

    assessment = skill.assess(
        notes,
        composition,
        solved=solved,
        hints_used=hints_used,
        minutes=minutes,
        expected_minutes=settings.expected_minutes(composition.cost),
        weights=settings.weights,
    )
    observations = skill.technique_observations(composition, assessment, solved=solved)

    previous, updated = history.learn(
        attempt,
        score=assessment.score,
        solved=solved,
        observations=observations,
        alpha=settings.skill_alpha,
        hints_used=hints_used,
    )

    _print_header("score")
    for line in assessment.lines():
        print(f"  {line}")
    print(f"\n  score {assessment.score:.3f}   ({minutes_note})")
    print(f"  skill estimate {previous:.2f} -> {updated:.2f}")

    _print_header("what this means for the next one")
    policy = _policy(settings)
    budget = policy.budget_base + policy.budget_skill * updated
    for name in composition.techniques:
        stat = history.profile.stat(name)
        print(
            f"  {name}: understanding {stat.understanding:.2f}, solved {stat.solved}/{stat.seen}"
            + (f", patched {stat.bypassed}x" if stat.bypassed else "")
        )
    print(f"  next challenge budget {budget:.0f} (about {1 + int(updated * 2.5)} layer(s))")

    chal.save_submission(
        directory,
        {
            "challenge_id": challenge_id,
            "solved": solved,
            "password": args.password or "",
            "minutes": minutes,
            "hints_used": hints_used,
            "score": assessment.score,
            "skill_before": previous,
            "skill_after": updated,
            "signals": [asdict(signal) for signal in assessment.signals],
            "notes_source": notes.source,
        },
    )
    print("\nrun: python autocrackme.py next")
    return 0 if solved else 1


def cmd_status(args: argparse.Namespace, settings: Settings, history: History) -> int:
    profile = history.profile
    policy = _policy(settings)
    _print_header("observed")
    print(f"  skill estimate      {profile.skill:.2f}")
    print(f"  attempts            {profile.attempted} ({profile.solved} solved)")
    print(f"  hints used          {profile.hints_used}")
    budget = policy.budget_base + policy.budget_skill * profile.skill
    print(f"  next budget         {budget:.0f} (up to {1 + int(profile.skill * 2.5)} layers)")
    print(f"  toolchain           {settings.vcvars or 'MISSING: set vcvars_path'}")
    print(f"  IDA                 {settings.idat or 'MISSING: set ida_path'}")

    _print_header("technique pool (weight = how likely it is next)")
    for name, weight, note in composer.pool_summary(profile, policy, history.next_challenge_id):
        print(f"  {name:<15} {weight:>5.2f}  {note}")

    if history.attempts:
        _print_header("recent challenges")
        for attempt in history.attempts[-6:]:
            mark = "solved" if attempt.solved else ("open" if not attempt.submitted_at else "unsolved")
            techniques = "+".join(attempt.techniques)
            print(
                f"  #{attempt.challenge_id:<3} {mark:<8} {attempt.score:.2f}  "
                f"{attempt.format:<8} {techniques}"
                + (f" [{attempt.features}]" if attempt.features else "")
            )
    return 0


def cmd_pool(args: argparse.Namespace, settings: Settings, history: History) -> int:
    policy = _policy(settings)
    profile = history.profile
    _print_header("techniques that can be drawn from")
    for name, weight, note in composer.pool_summary(profile, policy, history.next_challenge_id):
        tech = POOL[name]
        print(f"  {name} (cost {tech.cost}) — {tech.title}")
        print(f"      teaches: {tech.teaches}")
        print(f"      formats: {', '.join(tech.formats)} · weight {weight:.2f} · {note}")
    return 0


# -- entry point ------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autocrackme.py",
        description=BANNER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "typical loop:\n"
            "  python autocrackme.py next\n"
            "  (solve it in IDA, write comments)\n"
            "  python autocrackme.py export\n"
            "  python autocrackme.py submit --password <what you found>\n"
        ),
    )
    parser.add_argument("--config", default=None, help="path to config.json")
    sub = parser.add_subparsers(dest="command")

    new = sub.add_parser("new", aliases=["next"], help="generate the next challenge")
    new.add_argument("--show-reasoning", action="store_true", help="print why it was built (spoilers)")

    export = sub.add_parser("export", help="pull your comments out of IDA")
    export.add_argument("--id", type=int, default=None)

    submit = sub.add_parser("submit", help="report the outcome of a challenge")
    submit.add_argument("--id", type=int, default=None)
    submit.add_argument("--password", default=None, help="what the binary accepted")
    submit.add_argument("--minutes", type=float, default=None, help="how long it took you")
    submit.add_argument("--hints", type=int, default=None, help="hints you looked at")
    submit.add_argument("--solved", action="store_true", help="claim solved without a password")
    submit.add_argument("--failed", action="store_true", help="gave up on this one")

    hint = sub.add_parser("hint", help="show progressive hints for a challenge")
    hint.add_argument("--id", type=int, default=None)
    hint.add_argument("--n", type=int, default=None, help="how many hints to reveal (default all)")

    reveal = sub.add_parser("reveal", help="show the answer and how it was built")
    reveal.add_argument("--id", type=int, default=None)

    sub.add_parser("status", help="what has been observed and what comes next")
    sub.add_parser("pool", help="list every technique and its current weight")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1

    try:
        settings = load_settings(Path(args.config) if args.config else None)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    history = History()
    if getattr(settings, "start_level", 1) > 1 and not history.attempts:
        history.profile.skill = min(1.0, (settings.start_level - 1) / 9.0)

    handlers = {
        "new": cmd_new,
        "next": cmd_new,
        "export": cmd_export,
        "submit": cmd_submit,
        "hint": cmd_hint,
        "reveal": cmd_reveal,
        "status": cmd_status,
        "pool": cmd_pool,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 1
    return handler(args, settings, history)
