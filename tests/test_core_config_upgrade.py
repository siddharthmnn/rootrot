"""tests for simulation-specific configuration and safety limits."""

import unittest

from rootrot.core.config import configuration_error, rootrot_config


class test_simulation_configuration(unittest.TestCase):
    def test_new_simulation_settings_round_trip(self):
        config = rootrot_config(
            c2_command_ttl_seconds=120,
            c2_queue_limit=16,
            persistence_platform="linux",
            ransomware_target_extensions=(".TXT", ".csv"),
            ransomware_excluded_paths=("safe", "demo/keep"),
            max_staging_bytes=500_000,
        )
        restored = rootrot_config.from_mapping(config.to_dict())
        self.assertEqual(restored, config)
        self.assertEqual(config.ransomware_target_extensions, (".txt", ".csv"))

    def test_config_rejects_invalid_persistence_platform(self):
        with self.assertRaises(configuration_error):
            rootrot_config(persistence_platform="freebsd")

    def test_config_rejects_invalid_command_ttl_and_queue_limit(self):
        with self.assertRaises(configuration_error):
            rootrot_config(c2_command_ttl_seconds=float("inf"))
        with self.assertRaises(configuration_error):
            rootrot_config(c2_queue_limit=0)

    def test_config_rejects_unsafe_excluded_paths(self):
        with self.assertRaises(configuration_error):
            rootrot_config(ransomware_excluded_paths=("../outside",))
        with self.assertRaises(configuration_error):
            rootrot_config(ransomware_excluded_paths=("C:\\Users\\Public",))

    def test_config_rejects_bad_extensions(self):
        with self.assertRaises(configuration_error):
            rootrot_config(ransomware_target_extensions=("txt",))
        with self.assertRaises(configuration_error):
            rootrot_config(ransomware_target_extensions=(".txt", ".TXT"))

    def test_list_values_are_required_in_json_mapping(self):
        with self.assertRaises(configuration_error):
            rootrot_config.from_mapping({"ransomware_target_extensions": ".txt"})


if __name__ == "__main__":
    unittest.main()
