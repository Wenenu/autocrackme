# autocrackme

Generates crackme binaries for IDA practice — and decides what to build next from
**how you actually solved the last one**.

There is no level ladder and no fixed sequence of challenges. Every challenge is
composed fresh from a pool of techniques, weighted by what has been observed
about you. Solve something cleanly with good notes and the pool shifts toward
harder, unseen material; patch past a check and stay quiet about how it works,
and that technique comes back.

```
python autocrackme.py next                          # build crackme_001
   (open it in IDA, work out the accepted input, annotate as you go)
python autocrackme.py export                        # pull your IDA comments out
python autocrackme.py submit --password <answer>    # score it
python autocrackme.py status                        # what it now thinks of you
```

## Requirements

| Thing | Why | Notes |
| --- | --- | --- |
| Python 3.9+ | the tool itself | no third-party packages |
| Visual Studio 2022 Build Tools (C++) | compiling the generated C | `vcvars64.bat` is found automatically |
| IDA 9.x (any edition with `idat.exe`) | the target environment | only needed for `export` |

Both tools are auto-detected across `C:`, `D:` and `E:`. If detection fails, set
`vcvars_path` / `ida_path` in `config.json`.

## Quick start

```bash
cd D:/autocrackme
cp config.example.json config.json      # optional — defaults work
python autocrackme.py status            # confirms the toolchain is visible
python autocrackme.py next              # generates challenges/crackme_001/
```

`next` is self-verifying: it compiles the generated source, runs it with the
canonical answer to confirm it is solvable, runs it with junk to confirm it is
not trivially open, and only then hands you the binary. A challenge that fails
either check tells you so instead of pretending.

## What lands on disk

```
challenges/crackme_001/
    crackme.exe        <- open this in IDA
    notes.md           <- optional: write your reasoning here instead
    notes.json         <- written by `export`, read for scoring
    submission.json    <- what you reported, and how it scored
    build.bat          <- rebuild it by hand if you want
    .solution/         <- spoilers
        crackme.c
        answer.json
```

The answer is kept on disk so the tool can verify your submission, serve hints,
and rebuild the binary — but it is tucked into `.solution/` so it is not in your
face while you work.

## Importing your IDA comments

`export` copies the database (so it never fights the IDA GUI for the file),
opens the copy headlessly with `idat.exe -A -S<script>`, and writes every line
comment, function comment and rename it finds into `notes.json`.

**Save your database in IDA first (Ctrl+W).** The export reads what was last
saved; if there is no `.i64`, it falls back to analysing the binary from scratch,
which cannot contain your annotations — the command warns you when that happens.

If you would rather not use IDA for note-taking, `notes.md` is read too.

## How the next challenge is chosen

Two things are tracked, both in `history.json`:

**A skill estimate (0..1).** One number, blended toward each new score
(`skill_alpha`). It sizes the challenge *budget*, which sets how many stacked
layers and how much obfuscation the composer may spend.

**Per-technique evidence.** For each technique: how often it was seen, how often
it was solved, how well your notes showed it was understood, and whether it was
beaten by patching. That produces a mastery score, which sets the technique's
selection *weight*:

| Observed | Weight | Effect |
| --- | --- | --- |
| never seen | `novelty_weight` (3.0) | surfaced deliberately |
| mastery < 0.35 | `reinforce_weight` (2.5) | brought back to practise |
| mastery > 0.70 | `retire_weight` (0.25) | kept rare |
| beaten by patching | × `bypass_weight_mult` | tried again |
| used in the last 2 challenges | × `cooldown_mult` | keeps runs varied |

The composer then picks a password format weighted by how much the techniques it
enables are needed, stacks 1–3 compatible techniques on that one password, and
spends the leftover budget on obfuscation (masked strings, opaque predicates, a
decoy function, junk, and anti-debug once skill is above 0.70). Compositions that
match a recent fingerprint are rolled again — so you will not get the same
technique *set* twice in a row.

Because the password is fixed *before* the layers are built, every stacked layer
checks the same answer in a different way. That is what makes stacking solvable
instead of contradictory.

### The pool

| Technique | Cost | Password shape | Teaches |
| --- | --- | --- | --- |
| `plain_strcmp` | 2 | any | reading strings, finding the comparison |
| `xor_mask` | 4 | any | spotting byte-wise de-obfuscation loops |
| `per_char_table` | 5 | any | inverting position-dependent arithmetic |
| `weighted_sum` | 6 | digits | solving arithmetic constraints, no stored answer |
| `crc32` | 8 | any | recognising a standard polynomial and inverting it |
| `hash_fnv` | 9 | any | identifying hash constants (FNV-1a + djb2) |
| `layered` | 12 | any | unpicking sequential stages in reverse |
| `tea` | 13 | 32 hex | reimplementing a block cipher |
| `rc4_serial` | 13 | dashed serial | rebuilding a stream cipher's key schedule |
| `vm` | 15 | any | writing an emulator for a custom instruction set |

`python autocrackme.py pool` lists them with their current weights,
`python autocrackme.py status` summarises the state, and `--show-reasoning`
on `next` prints why that particular challenge was built (spoilers).

## How you are scored

Understanding is rewarded over outcome, and patching past a check while saying
nothing about how it works is penalised:

| Signal | Default weight | Based on |
| --- | --- | --- |
| `solved` | +0.35 | the binary accepting your answer (it is re-run to check) |
| `technique` | +0.25 | technique vocabulary in your notes |
| `understanding` | +0.15 | your renames and annotated functions |
| `effort` | +0.10 | how many comments you left |
| `speed` | +0.10 | time taken vs. what is expected at this budget |
| `bypass` | −0.15 | talk of patching/nop/brute-force *without* explanation |
| `hints` | −0.10 | hints revealed via `hint` |

Weights are configurable. `submit` prints every signal with its contribution, and
moves the skill estimate — a failed attempt can only hold it steady or lower it,
so a lucky guess cannot level you up.

```bash
python autocrackme.py hint               # progressive hints (cost you score)
python autocrackme.py reveal             # full spoilers for a challenge
python autocrackme.py submit --failed    # give up, recorded honestly
```

## Configuration

Copy `config.example.json` to `config.json` (gitignored) and edit what you need.

| Key | Default | Meaning |
| --- | --- | --- |
| `challenges_dir` | `<repo>/challenges` | where challenges are written |
| `vcvars_path` | auto-detected | path to `vcvars64.bat` |
| `ida_path` | auto-detected | path to `idat.exe` |
| `arch` | `x64` | `x64` or `x86` |
| `optimize` | `true` | `/O2` vs `/Od` |
| `ida_timeout_seconds` | `300` | headless export timeout |
| `antidebug` | `true` | allow anti-debug layers (only above skill 0.70) |
| `start_level` | `1` | optionally seed the skill estimate (1–10) |
| `skill_alpha` | `0.35` | how fast the skill estimate moves |
| `expected_minutes_base` / `_per_level` | `20` / `15` | sets the `speed` target |
| `weights` | see above | scoring signal weights |
| `composer` | see above | how challenges are composed |

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite compiles every generated technique, every stacked combination, and
every obfuscation feature with the real `cl.exe`, then runs each binary to prove
it accepts the canonical answer and rejects a wrong one. It is slow (~2 minutes)
because it is doing the real thing; without MSVC it skips instead of passing
vacuously.

## Scope

This generates practice targets for **you to reverse on your own machine** — the
tool's whole purpose is that you solve your own binaries. The `export` step reads
annotations out of your own IDA database for your own project. Nothing here
defeats a protection on software you do not control.
