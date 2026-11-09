"""checks that the full lab runs and returns its event evidence."""

import unittest

from rootrot.core.config import rootrot_config
from rootrot.lab import run_lab


class test_rootrot_lab(unittest.TestCase):
    def test_lab_returns_the_expected_sections(self):
        report = run_lab()
        expected_sections = {
            "project",
            "version",
            "run_id",
            "profile",
            "enabled_modules",
            "file_inventory",
            "persistence_simulation",
            "c2_simulation",
            "ransomware_simulation",
            "staging_simulation",
            "detections",
            "detection_rules",
            "events",
            "forensic_summary",
            "event_count",
            "event_log_integrity",
            "safety",
        }
        self.assertTrue(expected_sections.issubset(report))
        self.assertEqual(report["project"], "rootrot")
        self.assertEqual(report["version"], "1.0.0")
        self.assertEqual(report["profile"], "multi_stage")

    def test_lab_uses_only_the_simulated_behaviours(self):
        report = run_lab()
        safety = report["safety"]
        self.assertTrue(safety["temporary_workspace_only"])
        self.assertFalse(safety["network_connections"])
        self.assertFalse(safety["system_persistence"])
        self.assertFalse(safety["shell_commands"])
        self.assertFalse(safety["files_encrypted"])
        self.assertFalse(safety["data_transmitted"])

    def test_event_log_integrity_is_preserved(self):
        report = run_lab()
        self.assertTrue(report["event_log_integrity"])
        self.assertGreater(report["event_count"], 0)
        self.assertEqual(report["event_count"], len(report["events"]))
        self.assertTrue(report["forensic_summary"]["integrity"]["valid"])

    def test_c2_and_file_inventory_examples_run(self):
        report = run_lab()
        self.assertEqual(len(report["file_inventory"]), 3)
        self.assertEqual(len(report["c2_simulation"]), 3)
        self.assertEqual(
            {item["action"] for item in report["c2_simulation"]},
            {"status", "inventory", "hash_file"},
        )

    def test_detection_engine_reports_the_demo_behaviours(self):
        report = run_lab()
        rules = {item["rule"] for item in report["detections"]}
        self.assertIn("persistence_indicator", rules)
        self.assertIn("data_staging_indicator", rules)
        self.assertIn("ransomware_like_file_selection", rules)
        self.assertIn("repeated_beaconing", rules)

    def test_ransomware_and_staging_remain_non_destructive(self):
        report = run_lab()
        self.assertEqual(report["ransomware_simulation"]["files_encrypted"], 0)
        self.assertFalse(report["staging_simulation"]["transmitted"])

    def test_file_analysis_profile_skips_other_simulators(self):
        report = run_lab(rootrot_config(profile="file_analysis"))
        self.assertEqual(report["enabled_modules"], ["file_intel"])
        self.assertIn("file_inventory", report)
        self.assertNotIn("c2_simulation", report)
        self.assertEqual(report["detections"], [])
        self.assertEqual(report["event_count"], len(report["events"]))

    def test_configurable_chunk_size_reaches_staging_module(self):
        report = run_lab(rootrot_config(staging_chunk_size=64))
        self.assertEqual(report["staging_simulation"]["chunk_count"], 24)


if __name__ == "__main__":
    unittest.main()
