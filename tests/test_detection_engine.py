"""tests for detection policy, metadata, and failure handling."""

import unittest

from rootrot.detection_engine import detection_engine
from rootrot.detection_engine.engine import detection_error
from rootrot.detection_engine.rules.base import detection_rule
from rootrot.events import event_logger


class broken_test_rule(detection_rule):
    rule_id = "rr.test.broken"
    name = "broken_test_rule"
    description = "used to check that incomplete analysis is not hidden"
    base_score = 1

    def evaluate(self, events):
        raise RuntimeError("expected test failure")


class invalid_result_rule(detection_rule):
    rule_id = "rr.test.invalid"
    name = "invalid_result_rule"
    description = "returns a value that does not follow the rule contract"
    base_score = 10

    def evaluate(self, events):
        return [{"rule": "not a finding"}]


class test_detection_engine(unittest.TestCase):
    def setUp(self):
        self.logger = event_logger()
        self.logger.emit("c2", "c2.bad_signature", "alert", command_id="demo")

    def test_minimum_severity_filters_lower_findings(self):
        findings = detection_engine(
            self.logger,
            minimum_severity="critical",
        ).analyze()
        self.assertEqual(findings, [])

        findings = detection_engine(
            self.logger,
            minimum_severity="high",
        ).analyze()
        self.assertIn(
            "command_authentication_failure",
            {item["rule"] for item in findings},
        )

    def test_excluded_rules_can_be_selected_by_name_or_id(self):
        by_name = detection_engine(
            self.logger,
            excluded_rules=("command_authentication_failure",),
        )
        self.assertNotIn(
            "command_authentication_failure",
            {item["rule"] for item in by_name.analyze()},
        )

        by_id = detection_engine(
            self.logger,
            excluded_rules=("rr.c2.002",),
        )
        self.assertNotIn(
            "command_authentication_failure",
            {item["rule"] for item in by_id.analyze()},
        )

    def test_rule_catalog_reports_enabled_state(self):
        detector = detection_engine(self.logger, excluded_rules=("rr.c2.002",))
        catalog = {item["rule_id"]: item for item in detector.list_rules()}
        self.assertIn("rr.sequence.001", catalog)
        self.assertFalse(catalog["rr.c2.002"]["enabled"])
        self.assertTrue(catalog["rr.c2.001"]["enabled"])

    def test_duplicate_rule_ids_are_rejected(self):
        rule = broken_test_rule()
        with self.assertRaises(ValueError):
            detection_engine(self.logger, rules=(rule, rule))

    def test_rule_failure_is_reported_instead_of_returning_partial_results(self):
        detector = detection_engine(self.logger, rules=(broken_test_rule(),))
        with self.assertRaises(detection_error):
            detector.analyze()
        self.assertIn(
            "detection.rule_failed",
            {event["action"] for event in self.logger.events},
        )

    def test_non_object_event_details_are_rejected(self):
        with self.assertRaises(ValueError):
            detection_engine(self.logger).analyze([
                {"action": "file.extension_mismatch", "details": "not an object"}
            ])

    def test_invalid_event_input_is_rejected(self):
        with self.assertRaises(ValueError):
            detection_engine(self.logger).analyze([{"source": "missing-action"}])

    def test_rule_returning_invalid_data_is_not_silently_accepted(self):
        detector = detection_engine(self.logger, rules=(invalid_result_rule(),))
        with self.assertRaises(detection_error):
            detector.analyze()

    def test_invalid_policy_values_are_rejected(self):
        with self.assertRaises(ValueError):
            detection_engine(self.logger, minimum_severity="urgent")
        with self.assertRaises(ValueError):
            detection_engine(self.logger, correlation_window_seconds=0)
        with self.assertRaises(ValueError):
            detection_engine(self.logger, excluded_rules=("rr.c2.002", "rr.c2.002"))

    def test_analysis_summary_is_logged(self):
        detection_engine(self.logger).analyze()
        summary = [
            event for event in self.logger.events
            if event["action"] == "analysis.completed"
        ]
        self.assertEqual(len(summary), 1)
        self.assertGreater(summary[0]["details"]["evaluated_rule_count"], 0)


if __name__ == "__main__":
    unittest.main()
