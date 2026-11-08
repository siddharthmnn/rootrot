"""checks that detection settings are passed into the full lab run."""

import unittest

from rootrot.core.config import rootrot_config
from rootrot.lab import run_lab


class test_lab_detection_policy(unittest.TestCase):
    def test_minimum_severity_is_applied_to_findings(self):
        report = run_lab(rootrot_config(detection_min_severity="critical"))
        self.assertEqual(report["detections"], [])

    def test_excluded_rule_is_not_returned(self):
        report = run_lab(
            rootrot_config(detection_excluded_rules=("rr.c2.001",))
        )
        self.assertNotIn(
            "repeated_beaconing",
            {item["rule"] for item in report["detections"]},
        )

    def test_default_run_finds_a_multi_stage_sequence(self):
        report = run_lab()
        finding = next(
            item for item in report["detections"]
            if item["rule"] == "multi_stage_activity_sequence"
        )
        self.assertGreaterEqual(finding["evidence"]["category_count"], 3)
        self.assertLessEqual(
            finding["evidence"]["window_seconds"],
            120,
        )

    def test_rule_catalog_is_included_in_report(self):
        report = run_lab()
        rule_ids = {item["rule_id"] for item in report["detection_rules"]}
        self.assertIn("rr.persistence.001", rule_ids)
        self.assertIn("rr.sequence.001", rule_ids)

    def test_disabling_detection_returns_an_empty_rule_catalog(self):
        report = run_lab(rootrot_config(detection_enabled=False))
        self.assertEqual(report["detections"], [])
        self.assertEqual(report["detection_rules"], [])


if __name__ == "__main__":
    unittest.main()
