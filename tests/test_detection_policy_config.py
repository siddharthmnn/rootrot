"""tests for configurable detection thresholds and rule exclusions."""

import unittest

from rootrot.core.config import configuration_error, rootrot_config


class test_detection_policy_config(unittest.TestCase):
    def test_detection_settings_round_trip(self):
        config = rootrot_config(
            detection_min_severity="high",
            detection_excluded_rules=("rr.c2.002", "file_extension_mismatch"),
            detection_correlation_window_seconds=45,
        )
        restored = rootrot_config.from_mapping(config.to_dict())
        self.assertEqual(restored, config)

    def test_invalid_minimum_severity_is_rejected(self):
        with self.assertRaises(configuration_error):
            rootrot_config(detection_min_severity="urgent")

    def test_invalid_rule_exclusions_are_rejected(self):
        with self.assertRaises(configuration_error):
            rootrot_config(detection_excluded_rules=("../rule",))
        with self.assertRaises(configuration_error):
            rootrot_config(detection_excluded_rules=("rr.c2.002", "rr.c2.002"))

    def test_invalid_correlation_windows_are_rejected(self):
        with self.assertRaises(configuration_error):
            rootrot_config(detection_correlation_window_seconds=0)
        with self.assertRaises(configuration_error):
            rootrot_config(detection_correlation_window_seconds=3601)


if __name__ == "__main__":
    unittest.main()
