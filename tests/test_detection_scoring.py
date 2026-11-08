"""tests for the rule score and severity thresholds."""

import unittest

from rootrot.detection_engine.scoring import (
    meets_minimum_severity,
    score_finding,
    severity_for_score,
)


class test_detection_scoring(unittest.TestCase):
    def test_repeated_evidence_adds_a_bounded_score_bonus(self):
        self.assertEqual(score_finding(50, 1), 50)
        self.assertEqual(score_finding(50, 3), 56)
        self.assertEqual(score_finding(50, 20), 65)

    def test_score_thresholds_map_to_severity(self):
        cases = {
            0: "info",
            19: "info",
            20: "low",
            39: "low",
            40: "medium",
            69: "medium",
            70: "high",
            89: "high",
            90: "critical",
            100: "critical",
        }
        for score, expected in cases.items():
            with self.subTest(score=score):
                self.assertEqual(severity_for_score(score), expected)

    def test_minimum_severity_is_ordered(self):
        self.assertTrue(meets_minimum_severity("critical", "high"))
        self.assertTrue(meets_minimum_severity("high", "high"))
        self.assertFalse(meets_minimum_severity("medium", "high"))

    def test_invalid_scores_and_counts_are_rejected(self):
        for score in (-1, 101, True, 1.5):
            with self.assertRaises(ValueError):
                severity_for_score(score)
        for count in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                score_finding(50, count)


if __name__ == "__main__":
    unittest.main()
