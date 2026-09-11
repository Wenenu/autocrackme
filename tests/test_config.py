"""Config loading, including the composer policy wiring.

The "composer" block in config.json only takes effect if load_settings keeps it
and the CLI hands it to Policy.from_json; these tests pin that path down so it
cannot silently regress into being ignored again.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from acm.composer import Policy  # noqa: E402
from acm.config import DEFAULT_WEIGHTS, load_settings  # noqa: E402


def write_config(payload: dict) -> Path:
    directory = Path(tempfile.mkdtemp(prefix="acm_cfg_"))
    path = directory / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class ConfigTests(unittest.TestCase):
    def test_composer_block_reaches_the_policy(self):
        path = write_config({"composer": {"max_layers": 5, "budget_base": 9.0}})
        settings = load_settings(path)

        policy = Policy.from_json(settings.composer_raw)
        self.assertEqual(policy.max_layers, 5)
        self.assertEqual(policy.budget_base, 9.0)

    def test_missing_config_uses_defaults(self):
        settings = load_settings(Path(tempfile.mkdtemp(prefix="acm_cfg_")) / "config.json")

        self.assertIsNone(settings.composer_raw)
        self.assertEqual(Policy.from_json(settings.composer_raw).max_layers, 3)
        self.assertEqual(settings.weights, DEFAULT_WEIGHTS)

    def test_unknown_composer_key_is_ignored(self):
        settings = load_settings(write_config({"composer": {"max_layerz": 5}}))

        self.assertEqual(Policy.from_json(settings.composer_raw).max_layers, 3)

    def test_uncastable_composer_value_is_reported(self):
        settings = load_settings(write_config({"composer": {"max_layers": "lots"}}))

        with self.assertRaises(ValueError) as caught:
            Policy.from_json(settings.composer_raw)
        self.assertIn("max_layers", str(caught.exception))

    def test_weight_overrides_are_merged_over_defaults(self):
        settings = load_settings(write_config({"weights": {"hints": -0.5}}))

        self.assertEqual(settings.weights["hints"], -0.5)
        self.assertEqual(settings.weights["solved"], DEFAULT_WEIGHTS["solved"])

    def test_invalid_json_is_reported(self):
        path = Path(tempfile.mkdtemp(prefix="acm_cfg_")) / "config.json"
        path.write_text("{ not json", encoding="utf-8")

        with self.assertRaises(ValueError):
            load_settings(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
