"""The IDA export must report only what the solver actually wrote.

IDA decorates a database heavily on its own: names derived from type
information, canned instruction comments, switch and jump-table annotations, and
library signature text. Every one of them comes back through the same
`get_cmt` / `get_name` calls as a genuine annotation, so the sharpest possible
test is a database that has never been touched in the GUI — it must export
nothing.

Without this guard, an untouched database exported 1335 comments, 16 function
comments and 527 names, which handed any submission full marks for
"understanding" and "effort" without the solver writing a single word.

Needs both MSVC and IDA; it skips when either is missing.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from acm import build, generator, ida_export  # noqa: E402
from acm.composer import Composition, Features  # noqa: E402
from acm.config import load_settings  # noqa: E402
from acm.notes import NOTES_JSON  # noqa: E402
from acm.techniques import POOL  # noqa: E402

SETTINGS = load_settings()
HAVE_TOOLCHAIN = SETTINGS.vcvars is not None and SETTINGS.idat is not None

# A few runtime names IDA applies (the CRT's own helpers) cannot be told from a
# solver's rename by any flag. They are documented, and must stay negligible
# rather than growing with the size of the runtime.
MAX_SPURIOUS_RENAMES = 5


@unittest.skipUnless(HAVE_TOOLCHAIN, "MSVC and IDA are both needed for this test")
class PristineExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="acm_ida_"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def build_challenge(self):
        composition = Composition(
            seed=7,
            challenge_id=1,
            format="generic",
            techniques=("xor_mask",),
            features=Features(),
            cost=POOL["xor_mask"].cost,
            fingerprint="generic|xor_mask|none",
        )
        generated = generator.generate(composition)
        (self.tmp / "crackme.c").write_text(generated.source, encoding="utf-8")
        return build.build(self.tmp, SETTINGS)

    def test_untouched_database_exports_no_annotations(self):
        self.build_challenge()

        # No database exists yet, so IDA analyses the binary from scratch — a
        # database no human has ever opened, let alone annotated.
        result = ida_export.export_notes(self.tmp, SETTINGS)
        self.assertTrue(result.ok, result.message)

        notes_path = self.tmp / NOTES_JSON
        self.assertTrue(notes_path.exists(), f"no notes written: {result.message}")
        counts = json.loads(notes_path.read_text(encoding="utf-8"))["counts"]

        self.assertEqual(counts["comments"], 0, "IDA's own comments leaked into the export")
        self.assertEqual(
            counts["function_comments"], 0, "library signature comments leaked into the export"
        )
        self.assertLessEqual(
            counts["renames"],
            MAX_SPURIOUS_RENAMES,
            "IDA's own names leaked into the export",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
