"""a few checks that the full lab still runs from start to finish."""

import unittest

from rootrot.lab import run_lab


class test_rootrot_lab(unittest.TestCase):
    def test_lab_returns_the_expected_sections(self):
        report = run_lab()

        expected_sections = {
            "project",
            "version",
            "file_inventory",
            "persistence_simulation",
            "c2_simulation",
            "ransomware_simulation",
            "staging_simulation",
            "detections",
            "event_count",
            "event_log_integrity",
            "safety",
        }
        self.assertTrue(expected_sections.issubset(report))
        self.assertEqual(report["project"], "rootrot")
        self.assertEqual(report["version"], "1.0.0")

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

        self.assertEqual(
            report["ransomware_simulation"]["files_encrypted"],
            0,
        )
        self.assertFalse(report["staging_simulation"]["transmitted"])


if __name__ == "__main__":
    unittest.main()
