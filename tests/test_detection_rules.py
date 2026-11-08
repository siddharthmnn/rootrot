"""tests for the built-in event rules."""

import unittest

from rootrot.detection_engine import detection_engine
from rootrot.events import event_logger


class test_event_detection_rules(unittest.TestCase):
    def test_persistence_rule_keeps_the_original_rule_name_and_evidence(self):
        logger = event_logger(run_id="persistence-run")
        for technique in ("windows_run_key", "scheduled_task"):
            logger.emit(
                "persistence_simulator",
                "persistence.would_write",
                "warning",
                technique=technique,
                performed=False,
            )
        findings = detection_engine(logger).analyze()
        finding = next(item for item in findings if item["rule"] == "persistence_indicator")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["evidence"]["observed"], 2)
        self.assertFalse(finding["evidence"]["performed"])
        self.assertEqual(finding["evidence"]["run_id"], "persistence-run")

    def test_repeated_beacon_rule_requires_three_events_in_the_same_run(self):
        logger = event_logger(run_id="beacon-run")
        logger.emit("c2", "c2.beacon", agent_id="demo")
        logger.emit("c2", "c2.beacon", agent_id="demo")
        self.assertNotIn(
            "repeated_beaconing",
            {item["rule"] for item in detection_engine(logger).analyze()},
        )

        logger.emit("c2", "c2.beacon", agent_id="demo")
        findings = detection_engine(logger).analyze()
        self.assertIn("repeated_beaconing", {item["rule"] for item in findings})

    def test_beacons_from_different_runs_are_not_combined(self):
        logger = event_logger()
        events = []
        for run_id in ("run-a", "run-b"):
            for index in range(2):
                events.append({
                    "run_id": run_id,
                    "sequence": index + 1,
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "source": "c2",
                    "action": "c2.beacon",
                    "severity": "info",
                    "details": {},
                })
        findings = detection_engine(logger).analyze(events)
        self.assertNotIn("repeated_beaconing", {item["rule"] for item in findings})

    def test_extension_mismatch_becomes_a_triage_finding(self):
        logger = event_logger()
        logger.emit(
            "file_intel",
            "file.extension_mismatch",
            "warning",
            file="invoice.txt",
            extension=".txt",
            detected_type="pdf",
        )
        findings = detection_engine(logger).analyze()
        finding = next(item for item in findings if item["rule"] == "file_extension_mismatch")
        self.assertEqual(finding["evidence"]["files"], ["invoice.txt"])
        self.assertIn("not proof of malware", finding["explanation"])

    def test_authentication_and_replay_events_have_separate_rules(self):
        logger = event_logger()
        logger.emit("c2", "c2.bad_signature", "alert", command_id="one")
        logger.emit("c2", "c2.command_replayed", "alert", command_id="two")
        findings = detection_engine(logger).analyze()
        names = {item["rule"] for item in findings}
        self.assertIn("command_authentication_failure", names)
        self.assertIn("command_replay_attempt", names)

    def test_every_finding_has_rule_metadata_and_event_references(self):
        logger = event_logger()
        logger.emit("staging_simulator", "data.staged_in_memory", "warning")
        finding = detection_engine(logger).analyze()[0]
        self.assertTrue(finding["rule_id"].startswith("rr."))
        self.assertIsInstance(finding["score"], int)
        self.assertTrue(finding["explanation"])
        self.assertEqual(finding["events"][0]["action"], "data.staged_in_memory")


if __name__ == "__main__":
    unittest.main()
