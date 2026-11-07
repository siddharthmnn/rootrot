"""tests for simulator settings passed through the lab configuration."""

import unittest

from rootrot.core.config import rootrot_config
from rootrot.lab import run_lab


class test_lab_simulation_settings(unittest.TestCase):
    def test_linux_persistence_profile_reaches_simulator(self):
        report = run_lab(rootrot_config(persistence_platform="linux"))
        profiles = {item["platform"] for item in report["persistence_simulation"]}
        self.assertEqual(profiles, {"linux"})

    def test_ransomware_exclusions_reach_simulator(self):
        report = run_lab(rootrot_config(ransomware_excluded_paths=("demo_files",)))
        self.assertEqual(report["ransomware_simulation"]["target_count"], 0)

    def test_file_analysis_profile_remains_compatible(self):
        report = run_lab(rootrot_config(profile="file_analysis"))
        self.assertEqual(len(report["file_inventory"]), 3)
        self.assertNotIn("c2_simulation", report)

    def test_default_run_remains_non_destructive(self):
        report = run_lab()
        self.assertTrue(report["event_log_integrity"])
        self.assertEqual(report["ransomware_simulation"]["files_modified"], 0)
        self.assertFalse(report["staging_simulation"]["transmitted"])


if __name__ == "__main__":
    unittest.main()
