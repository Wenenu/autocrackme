"""Compiles the generated crackmes and runs them.

This is the test that matters: it proves the emitted C and the Python that
derives the answer really do agree, for every technique, for stacked layers and
for every obfuscation feature. It needs MSVC; without it the tests skip.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from acm import build, generator  # noqa: E402
from acm.composer import Composition, Features  # noqa: E402
from acm.config import load_settings  # noqa: E402
from acm.techniques import FORMATS, POOL  # noqa: E402

SETTINGS = load_settings()
HAVE_MSVC = SETTINGS.vcvars is not None

WRONG = "this-is-not-the-answer"

# Which format each technique can be instantiated against, narrowest first.
FORMAT_FOR = {
    "weighted_sum": "digits",
    "tea": "hex32",
    "rc4_serial": "serial",
}


def make_composition(techniques, fmt="generic", *, seed=1, challenge_id=1, features=None):
    cost = sum(POOL[name].cost for name in techniques)
    fingerprint = "|".join([fmt, "+".join(techniques), (features or Features()).flags()])
    return Composition(
        seed=seed,
        challenge_id=challenge_id,
        format=fmt,
        techniques=tuple(techniques),
        features=features or Features(),
        cost=cost,
        fingerprint=fingerprint,
    )


@unittest.skipUnless(HAVE_MSVC, "MSVC (vcvars) not found, skipping compile tests")
class GeneratorBuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="acm_gen_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def compile_and_probe(self, composition):
        generated = generator.generate(composition)
        directory = self.tmp / f"c{composition.challenge_id}"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "crackme.c").write_text(generated.source, encoding="utf-8")
        result = build.build(directory, SETTINGS)
        return generated, result.exe

    def assert_solvable(self, composition):
        generated, exe = self.compile_and_probe(composition)
        accepted = build.accepts(exe, generated.password)
        rejected = not build.accepts(exe, WRONG)
        self.assertTrue(accepted, f"{composition.techniques}: canonical answer rejected")
        self.assertTrue(rejected, f"{composition.techniques}: wrong input accepted")
        return generated

    def test_every_technique_alone(self):
        for index, name in enumerate(POOL, start=1):
            with self.subTest(technique=name):
                fmt = FORMAT_FOR.get(name, "generic")
                composition = make_composition([name], fmt, seed=index, challenge_id=index)
                generated = self.assert_solvable(composition)
                self.assertTrue(
                    FORMATS[fmt].matches(generated.password),
                    f"{name} produced a password outside {fmt}",
                )

    def test_stacked_layers_agree_on_one_answer(self):
        stacks = [
            ("generic", ["xor_mask", "crc32"]),
            ("generic", ["per_char_table", "hash_fnv"]),
            ("generic", ["plain_strcmp", "layered"]),
            ("generic", ["xor_mask", "per_char_table", "vm"]),
            ("digits", ["weighted_sum", "hash_fnv"]),
            ("serial", ["rc4_serial", "xor_mask"]),
            ("hex32", ["tea", "per_char_table"]),
            ("hex32", ["tea"]),
        ]
        for index, (fmt, names) in enumerate(stacks, start=20):
            with self.subTest(stack="+".join(names)):
                self.assert_solvable(make_composition(names, fmt, seed=index, challenge_id=index))

    def test_same_seed_is_reproducible(self):
        one = generator.generate(make_composition(["xor_mask", "crc32"], seed=99, challenge_id=5))
        two = generator.generate(make_composition(["xor_mask", "crc32"], seed=99, challenge_id=5))
        self.assertEqual(one.source, two.source)
        self.assertEqual(one.password, two.password)

    def test_different_seeds_change_the_binary(self):
        one = generator.generate(make_composition(["xor_mask"], seed=1, challenge_id=1))
        two = generator.generate(make_composition(["xor_mask"], seed=2, challenge_id=1))
        self.assertNotEqual(one.source, two.source)
        self.assertNotEqual(one.password, two.password)

    def test_features_still_compile_and_accept(self):
        feature_sets = [
            Features(encrypt_strings=True),
            Features(opaque_predicates=True),
            Features(decoy_function=True, junk=6),
            Features(encrypt_strings=True, opaque_predicates=True, decoy_function=True, junk=8),
        ]
        for index, features in enumerate(feature_sets, start=40):
            with self.subTest(features=features.flags()):
                composition = make_composition(
                    ["xor_mask", "hash_fnv"], seed=index, challenge_id=index, features=features
                )
                self.assert_solvable(composition)

    def test_antidebug_builds_and_still_accepts(self):
        composition = make_composition(
            ["per_char_table"], seed=55, challenge_id=55, features=Features(antidebug=True)
        )
        self.assert_solvable(composition)


if __name__ == "__main__":
    unittest.main(verbosity=2)
