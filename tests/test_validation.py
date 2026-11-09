"""regression coverage for synthetic detection validation and deterministic replay."""

import unittest

from rootrot.detection_engine.rules import build_default_rules
from rootrot.telemetry.integrity import verify_event_chain
from rootrot.validation.metrics import evaluate_detection_scenarios
from rootrot.validation.mutations import (
    run_integrity_mutation_suite,
    run_sequence_mutation_suite,
)
from rootrot.validation.replay import replay_scenario
from rootrot.validation.scenarios import (
    build_scenario_events,
    get_scenario,
    list_scenarios,
)


class test_validation_scenarios(unittest.TestCase):
    def test_scenario_catalog_has_unique_ids(self):
        scenarios = list_scenarios()
        ids = [item["scenario_id"] for item in scenarios]
        self.assertGreaterEqual(len(ids), 8)
        self.assertEqual(len(ids), len(set(ids)))

    def test_scenario_event_chains_are_reproducible_and_valid(self):
        for item in list_scenarios():
            with self.subTest(scenario=item["scenario_id"]):
                first = build_scenario_events(item["scenario_id"])
                second = build_scenario_events(item["scenario_id"])
                self.assertEqual(first, second)
                self.assertTrue(verify_event_chain(first)["valid"])

    def test_unknown_scenario_is_rejected(self):
        with self.assertRaises(ValueError):
            get_scenario("not-a-scenario")

    def test_scenario_labels_are_known_detection_rule_ids(self):
        known = {rule.rule_id for rule in build_default_rules()}
        for item in list_scenarios():
            with self.subTest(scenario=item["scenario_id"]):
                self.assertTrue(set(item["expected_rule_ids"]).issubset(known))


class test_detection_scenario_metrics(unittest.TestCase):
    def test_synthetic_ground_truth_is_classified_as_expected(self):
        result = evaluate_detection_scenarios()
        self.assertTrue(result["passed"])
        self.assertEqual(result["confusion_matrix"]["false_positive"], 0)
        self.assertEqual(result["confusion_matrix"]["false_negative"], 0)
        self.assertEqual(result["metrics"]["precision"], 1.0)
        self.assertEqual(result["metrics"]["recall"], 1.0)
        self.assertEqual(result["metrics"]["f1"], 1.0)
        self.assertIn("not a field-performance estimate", result["evaluation_basis"])

    def test_selected_scenarios_can_be_evaluated(self):
        result = evaluate_detection_scenarios(
            ("clean_inventory", "persistence_preview")
        )
        self.assertEqual(result["scenario_count"], 2)
        self.assertTrue(result["passed"])

    def test_empty_or_duplicate_scenario_selection_is_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_detection_scenarios(())
        with self.assertRaises(ValueError):
            evaluate_detection_scenarios(("clean_inventory", "clean_inventory"))


class test_deterministic_replay(unittest.TestCase):
    def test_replay_produces_stable_event_and_finding_digests(self):
        result = replay_scenario("multi_stage_chain", repetitions=4)
        self.assertTrue(result["deterministic"])
        self.assertTrue(result["integrity_valid_every_run"])
        self.assertEqual(result["repetitions"], 4)
        self.assertIn("rr.sequence.001", result["detected_rule_ids"])
        self.assertEqual(len(result["event_sha256"]), 64)
        self.assertEqual(len(result["findings_sha256"]), 64)

    def test_replay_rejects_invalid_repetition_counts(self):
        for value in (0, 26, True, 1.5):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    replay_scenario("clean_inventory", repetitions=value)


class test_event_sequence_mutations(unittest.TestCase):
    def test_integrity_mutations_are_all_rejected(self):
        result = run_integrity_mutation_suite()
        self.assertTrue(result["baseline_valid"])
        self.assertTrue(result["passed"])
        self.assertEqual(result["mutation_count"], 8)
        self.assertEqual(result["rejected_count"], 8)

    def test_sequence_mutations_preserve_expected_correlation_behaviour(self):
        result = run_sequence_mutation_suite()
        self.assertTrue(result["passed"])
        self.assertEqual(result["mutation_count"], 5)
        self.assertTrue(all(item["passed"] for item in result["mutations"]))


if __name__ == "__main__":
    unittest.main()
