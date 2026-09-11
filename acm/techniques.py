"""The pool of techniques a challenge can be built from.

Nothing here maps a level to a technique: the composer draws from the whole pool,
weighted by what has been observed about the solver. Each technique declares

*   `cost`     — how much of the challenge budget one layer of it consumes,
*   `formats`  — which password formats it can be instantiated against. This is
                 what makes stacking possible: several layers check the *same*
                 password in different ways, so they must agree on its shape.
*   `lexicon`  — words in the solver's notes that show the check was understood.
*   `hints`    — three progressive nudges, served one at a time.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable

PW_ALPHABET = "abcdefghijkmnopqrstuvwxyzACDEFGHJKLMNPQRSTUVWXYZ23456789"
SERIAL_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


@dataclass(frozen=True)
class Format:
    """A password shape. Techniques sharing a format can be stacked."""

    name: str
    title: str
    description: str
    make: Callable[[random.Random], str]
    matches: Callable[[str], bool]


HEX_DIGITS = "0123456789abcdef"


def _generic(rng: random.Random) -> str:
    return "".join(rng.choice(PW_ALPHABET) for _ in range(rng.randint(8, 16)))


def _generic_ok(value: str) -> bool:
    return 8 <= len(value) <= 16 and all(c in PW_ALPHABET for c in value)


def _digits(rng: random.Random) -> str:
    return "".join(str(rng.randrange(10)) for _ in range(rng.randint(12, 16)))


def _digits_ok(value: str) -> bool:
    return 12 <= len(value) <= 16 and value.isdigit()


def _hex32(rng: random.Random) -> str:
    return "".join(rng.choice(HEX_DIGITS) for _ in range(32))


def _hex32_ok(value: str) -> bool:
    return len(value) == 32 and all(c in HEX_DIGITS for c in value.lower())


def _serial(rng: random.Random) -> str:
    payload = "".join(rng.choice(SERIAL_ALPHABET) for _ in range(12))
    return "-".join(payload[i : i + 4] for i in range(0, 12, 4))


def _serial_ok(value: str) -> bool:
    parts = value.split("-")
    return (
        len(parts) == 3
        and all(len(p) == 4 for p in parts)
        and all(c in SERIAL_ALPHABET for p in parts for c in p)
    )


FORMATS: dict[str, Format] = {
    "generic": Format(
        "generic",
        "mixed alphanumeric",
        "8-16 characters, mixed case and digits",
        _generic,
        _generic_ok,
    ),
    "digits": Format(
        "digits",
        "numeric serial",
        "12-16 decimal digits",
        _digits,
        _digits_ok,
    ),
    "hex32": Format(
        "hex32",
        "32 hex characters",
        "exactly 32 hexadecimal characters (16 bytes)",
        _hex32,
        _hex32_ok,
    ),
    "serial": Format(
        "serial",
        "dashed serial",
        "XXXX-XXXX-XXXX, uppercase letters and digits",
        _serial,
        _serial_ok,
    ),
}

# Techniques that decide the password instead of adapting to it. A composition
# may contain at most one of these, and the generator builds the password from
# its parameters before emitting any layer.
PASSWORD_SOURCES: frozenset[str] = frozenset({"tea"})


@dataclass(frozen=True)
class Technique:
    name: str
    title: str
    cost: int
    formats: tuple[str, ...]
    teaches: str
    lexicon: tuple[str, ...]
    hints: list[str] = field(default_factory=list)


# Costs order the pool from cheapest to most demanding. They are added up into a
# budget, so stacking two mid-cost techniques is roughly as hard as one big one.
POOL: dict[str, Technique] = {
    "plain_strcmp": Technique(
        name="plain_strcmp",
        title="plain string compare",
        cost=2,
        formats=("generic", "digits", "hex32", "serial"),
        teaches="reading strings and finding the comparison",
        lexicon=("strcmp", "string compare", "literal", "password string", "hardcoded", "strings window"),
        hints=[
            "A literal is being compared. Start with the strings window.",
            "There may be more than one check: enumerate every comparison against the input.",
            "Any layer that compares your input to a stored literal gives you that literal as an answer.",
        ],
    ),
    "xor_mask": Technique(
        name="xor_mask",
        title="XOR-masked material",
        cost=4,
        formats=("generic", "digits", "hex32", "serial"),
        teaches="spotting byte-wise de-obfuscation loops",
        lexicon=("xor", "^=", "obfuscat", "mask", "key byte", "single byte"),
        hints=[
            "Stored bytes are not the answer: something is applied to them per byte.",
            "Find the byte the input is combined with, and the length check that precedes it.",
            "Reversing a byte-wise XOR is just XORing again with the same key.",
        ],
    ),
    "per_char_table": Technique(
        name="per_char_table",
        title="per-index transform table",
        cost=5,
        formats=("generic", "digits", "hex32", "serial"),
        teaches="inverting position-dependent arithmetic",
        lexicon=("table", "per-index", "index", "position", "offset", "positional"),
        hints=[
            "The expected value at each position differs, so position matters.",
            "Track how the loop counter feeds the arithmetic before the comparison table.",
            "Invert per byte: undo the index term first, then the key.",
        ],
    ),
    "weighted_sum": Technique(
        name="weighted_sum",
        title="weighted checksum serial",
        cost=6,
        formats=("digits",),
        teaches="solving arithmetic constraints instead of reading a stored answer",
        lexicon=("checksum", "sum", "weight", "modul", "modulo", "digit", "equation"),
        hints=[
            "Nothing is stored: the digits are checked with arithmetic.",
            "Every digit is multiplied by a weight that repeats; a second relation ties digits together.",
            "Write both relations down and satisfy them — many serials work, the intended one is just one of them.",
        ],
    ),
    "crc32": Technique(
        name="crc32",
        title="CRC32 of the input",
        cost=8,
        formats=("generic", "digits", "hex32", "serial"),
        teaches="recognising a standard polynomial and inverting a linear checksum",
        lexicon=("crc", "0xedb88320", "edb88320", "polynomial", "8544", "checksum", "redundancy"),
        hints=[
            "The input is condensed into one 32-bit value before being compared.",
            "The constant 0xEDB88320 in a table-building loop is the CRC32 polynomial.",
            "To invert it, walk the CRC backwards, or use the fact that the final bytes are free.",
        ],
    ),
    "hash_fnv": Technique(
        name="hash_fnv",
        title="dual hashes (FNV-1a and djb2)",
        cost=9,
        formats=("generic", "digits", "hex32", "serial"),
        teaches="identifying hash constants and combining constraints",
        lexicon=("fnv", "0x811c9dc5", "811c9dc5", "16777619", "djb2", "5381", "hash"),
        hints=[
            "More than one value derived from the input is compared.",
            "Look for the seeds 0x811C9DC5 and 5381 with the multipliers 16777619 and 33.",
            "Two 32-bit constraints together pin down the answer; satisfy them jointly, not separately.",
        ],
    ),
    "layered": Technique(
        name="layered",
        title="layered transform with table indirection",
        cost=12,
        formats=("generic", "digits", "hex32", "serial"),
        teaches="unpicking several sequential stages in reverse order",
        lexicon=("stage", "layer", "permut", "shuffl", "indirection", "pipeline", "reverse", "invert"),
        hints=[
            "One function applies several transforms before a single final comparison.",
            "Identify each stage separately: a per-index combine, then a shuffle through a table.",
            "Invert in reverse order: comparison target first, then the permutation, then the index maths.",
        ],
    ),
    "tea": Technique(
        name="tea",
        title="XTEA-encrypted token",
        cost=13,
        formats=("hex32",),
        teaches="reimplementing a block cipher from disassembly",
        lexicon=("tea", "xtea", "delta", "0x9e3779b9", "9e3779b9", "feistel", "block cipher", "key schedule", "rounds"),
        hints=[
            "The input is a hex token decrypted in 8-byte blocks before being compared.",
            "The delta constant 0x9E3779B9 identifies the cipher and its round count.",
            "Decrypt the comparison target with the same key, then encrypt that result back to get the token.",
        ],
    ),
    "rc4_serial": Technique(
        name="rc4_serial",
        title="RC4 keystream serial",
        cost=13,
        formats=("serial",),
        teaches="rebuilding a stream cipher's key schedule",
        lexicon=("rc4", "ksa", "keystream", "s-box", "sbox", "256", "prga"),
        hints=[
            "A 256-byte permutation is built from a key, then used to unmask stored bytes.",
            "The 256-entry init loop with a swap is the RC4 KSA; the second loop is the keystream generator.",
            "Rebuild the keystream with the same key and XOR it with the stored bytes to get the serial.",
        ],
    ),
    "vm": Technique(
        name="vm",
        title="bytecode VM dispatcher",
        cost=15,
        formats=("generic", "digits", "hex32", "serial"),
        teaches="writing an emulator for a custom instruction set",
        lexicon=("vm", "bytecode", "opcode", "dispatcher", "interpreter", "handler", "switch", "emulat"),
        hints=[
            "There is no obvious comparison: a byte array is interpreted by a loop.",
            "Find the dispatcher (a chain of comparisons on a byte) and the operand bytes that follow each opcode.",
            "Write the interpreter in Python and log every compare — the bytes that satisfy them spell the answer.",
        ],
    ),
}


# Words that suggest the check was defeated without being understood.
BYPASS_WORDS: tuple[str, ...] = (
    "patch",
    "patched",
    "nop",
    "bypass",
    "skip the check",
    "force the jump",
    "flip the flag",
    "jz to jnz",
    "brute force",
    "bruteforce",
    "guessed",
    "trial and error",
)

# Words showing general comprehension, whatever the technique.
UNDERSTANDING_WORDS: tuple[str, ...] = (
    "compare",
    "serial",
    "password",
    "loop",
    "length",
    "check",
    "decrypt",
    "encrypt",
    "derive",
    "invert",
    "solve",
    "reverse",
    "table",
    "key",
)


def cheapest_cost(formats: tuple[str, ...] | None = None) -> int:
    """Cost of the cheapest technique, optionally restricted to some formats."""
    costs = [
        tech.cost
        for tech in POOL.values()
        if not formats or any(f in formats for f in tech.formats)
    ]
    return min(costs) if costs else 1
