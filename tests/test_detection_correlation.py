"""tests for time-window and per-run behaviour correlation."""

import unittest
from datetime import datetime, timedelta, timezone

from rootrot.detection_engine import detection_engine
from rootrot.events import event_logger


def make_event(run_id, sequence, action, seconds):
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    return {
        "run_id": run_id,
        "sequence": sequence,
        "timestamp": timestamp.isoformat(),
        "source": action.split(".")[0],
        "action": action,
        "severity": "info",
        "details": {},
    }


class test_temporal_correlation(unittest.TestCase):
    def setUp(self):
        self.logger = event_logger()

    def test_correlates_three_categories_inside_the_window(self):
        events = [
            make_event("run-a", 1, "persistence.would_write", 0),
            make_event("run-a", 2, "c2.command_queued", 4),
            make_event("run-a", 3, "data.staged_in_memory", 8),
        ]
        findings = detection_engine(
            self.logger,
            correlation_window_seconds=15,
        ).analyze(events)
        finding = next(
            item for item in findings
            if item["rule"] == "multi_stage_activity_sequence"
        )
        self.assertEqual(finding["evidence"]["category_count"], 3)
        self.assertEqual(finding["evidence"]["window_seconds"], 8.0)
        self.assertEqual(len(finding["events"]), 3)

    def test_events_outside_the_window_are_not_correlated(self):
        events = [
            make_event("run-a", 1, "persistence.would_write", 0),
            make_event("run-a", 2, "c2.command_queued", 10),
            make_event("run-a", 3, "data.staged_in_memory", 20),
        ]
        findings = detection_engine(
            self.logger,
            correlation_window_seconds=5,
        ).analyze(events)
        self.assertNotIn(
            "multi_stage_activity_sequence",
            {item["rule"] for item in findings},
        )

    def test_categories_from_different_runs_are_not_combined(self):
        events = [
            make_event("run-a", 1, "persistence.would_write", 0),
            make_event("run-a", 2, "c2.command_queued", 1),
            make_event("run-b", 1, "data.staged_in_memory", 2),
            make_event("run-b", 2, "ransomware.dry_run", 3),
        ]
        findings = detection_engine(self.logger).analyze(events)
        self.assertNotIn(
            "multi_stage_activity_sequence",
            {item["rule"] for item in findings},
        )

    def test_each_run_gets_its_own_correlation_finding(self):
        events = []
        for run_id, offset in (("run-a", 0), ("run-b", 20)):
            events.extend([
                make_event(run_id, 1, "persistence.would_write", offset),
                make_event(run_id, 2, "c2.command_queued", offset + 1),
                make_event(run_id, 3, "data.staged_in_memory", offset + 2),
            ])
        findings = detection_engine(self.logger).analyze(events)
        correlated = [
            item for item in findings
            if item["rule"] == "multi_stage_activity_sequence"
        ]
        self.assertEqual(len(correlated), 2)
        self.assertEqual(
            {item["evidence"]["run_id"] for item in correlated},
            {"run-a", "run-b"},
        )

    def test_bad_timestamps_are_ignored_for_correlation(self):
        events = [
            make_event("run-a", 1, "persistence.would_write", 0),
            make_event("run-a", 2, "c2.command_queued", 1),
            make_event("run-a", 3, "data.staged_in_memory", 2),
        ]
        events[1]["timestamp"] = "not-a-date"
        findings = detection_engine(self.logger).analyze(events)
        self.assertNotIn(
            "multi_stage_activity_sequence",
            {item["rule"] for item in findings},
        )


if __name__ == "__main__":
    unittest.main()
