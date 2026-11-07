"""tests for configuration defaults, profiles, and validation."""

import json
import tempfile
import unittest
from pathlib import Path

from rootrot.core.config import profile_modules, configuration_error, rootrot_config


class test_rootrot_config(unittest.TestCase):
    def test_default_config_uses_multi_stage_profile(self):
        config = rootrot_config()
        self.assertEqual(config.profile, "multi_stage")
        self.assertEqual(config.enabled_modules, profile_modules["multi_stage"])

    def test_basic_profile_selects_a_smaller_module_set(self):
        config = rootrot_config(profile="basic")
        self.assertEqual(config.enabled_modules, profile_modules["basic"])

    def test_custom_modules_are_kept_in_requested_order(self):
        config = rootrot_config(enabled_modules=("staging", "file_intel"))
        self.assertEqual(config.profile, "custom")
        self.assertEqual(config.enabled_modules, ("staging", "file_intel"))

    def test_custom_profile_requires_modules(self):
        with self.assertRaises(configuration_error):
            rootrot_config(profile="custom")

    def test_invalid_module_names_are_rejected(self):
        with self.assertRaises(configuration_error):
            rootrot_config(enabled_modules=("Bad-Name",))

    def test_duplicate_modules_are_rejected(self):
        with self.assertRaises(configuration_error):
            rootrot_config(enabled_modules=("file_intel", "file_intel"))

    def test_invalid_numeric_values_are_rejected(self):
        with self.assertRaises(configuration_error):
            rootrot_config(staging_chunk_size=0)
        with self.assertRaises(configuration_error):
            rootrot_config(beacon_count=True)

    def test_mapping_round_trip(self):
        original = rootrot_config(profile="basic", staging_chunk_size=128)
        restored = rootrot_config.from_mapping(original.to_dict())
        self.assertEqual(restored, original)

    def test_unknown_keys_are_rejected(self):
        with self.assertRaises(configuration_error):
            rootrot_config.from_mapping({"profile": "basic", "debug": True})

    def test_config_can_be_loaded_from_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "config.json"
            path.write_text(json.dumps({"profile": "file_analysis"}), encoding="utf-8")
            config = rootrot_config.from_file(path)
        self.assertEqual(config.enabled_modules, ("file_intel",))

    def test_invalid_json_has_a_useful_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "config.json"
            path.write_text("{bad", encoding="utf-8")
            with self.assertRaises(configuration_error):
                rootrot_config.from_file(path)


if __name__ == "__main__":
    unittest.main()
