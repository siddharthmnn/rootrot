"""tests for event filtering, jsonl, timelines, and integrity diagnostics."""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rootrot.events import event_logger
from rootrot.telemetry.integrity import (
    create_checkpoint,
    verify_checkpoint,
    verify_event_chain,
)
from rootrot.telemetry.jsonl import export_jsonl, load_jsonl
from rootrot.telemetry.query import filter_events
from rootrot.telemetry.summary import build_forensic_summary
from rootrot.telemetry.timeline import build_timeline


class test_event_queries(unittest.TestCase):
    def setUp(self):
        self.logger = event_logger(run_id="query-run")
        self.first = self.logger.emit("file_intel", "file.inspected", "info", file="a.txt")
        self.second = self.logger.emit("c2", "c2.command_rejected", "warning", reason="bad signature")
        self.third = self.logger.emit("file_intel", "file.inspected", "info", file="b.txt")

    def test_filters_can_be_combined(self):
        selected = filter_events(
            self.logger.events,
            source="file_intel",
            action="file.inspected",
            severities={"info"},
        )
        self.assertEqual(len(selected), 2)
        self.assertEqual(selected[0]["details"]["file"], "a.txt")

    def test_filter_can_select_a_time_range_and_limit(self):
        start = self.second["timestamp"]
        selected = filter_events(
            self.logger.events,
            start=start,
            end=start,
            limit=1,
        )
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["sequence"], 2)

    def test_filter_rejects_invalid_ranges_and_limits(self):
        with self.assertRaises(ValueError):
            filter_events(self.logger.events, start=self.third["timestamp"], end=self.first["timestamp"])
        with self.assertRaises(ValueError):
            filter_events(self.logger.events, limit=0)

    def test_filter_does_not_mutate_original_events(self):
        original = json.dumps(self.logger.events, sort_keys=True)
        filter_events(self.logger.events, source="c2")
        self.assertEqual(json.dumps(self.logger.events, sort_keys=True), original)


class test_event_timeline(unittest.TestCase):
    def test_timeline_sorts_by_timestamp_and_adds_elapsed_time(self):
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            {
                "sequence": 2,
                "timestamp": (base + timedelta(seconds=3)).isoformat(),
                "source": "c2",
                "action": "c2.completed",
                "severity": "info",
                "details": {},
            },
            {
                "sequence": 1,
                "timestamp": base.isoformat(),
                "source": "file_intel",
                "action": "file.inspected",
                "severity": "info",
                "details": {},
            },
        ]
        result = build_timeline(events)
        self.assertEqual([item["sequence"] for item in result], [1, 2])
        self.assertEqual(result[1]["elapsed_ms"], 3000.0)

    def test_timeline_handles_empty_input(self):
        self.assertEqual(build_timeline([]), [])

    def test_timeline_rejects_bad_timestamps(self):
        with self.assertRaises(ValueError):
            build_timeline([{"timestamp": "not-a-date", "sequence": 1}])


class test_event_jsonl(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.path = Path(self.temp_dir.name) / "events.jsonl"
        self.logger = event_logger(run_id="jsonl-run")
        self.logger.emit("file_intel", "file.inspected", file="notes.txt")
        self.logger.emit("detection", "analysis.completed", finding_count=1)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_jsonl_round_trip_preserves_event_records(self):
        result = export_jsonl(self.logger.events, self.path)
        loaded = load_jsonl(self.path)
        self.assertEqual(result["event_count"], 2)
        self.assertEqual(loaded, self.logger.events)

    def test_export_refuses_to_overwrite_without_opt_in(self):
        export_jsonl(self.logger.events, self.path)
        with self.assertRaises(FileExistsError):
            export_jsonl(self.logger.events, self.path)

    def test_export_can_explicitly_overwrite(self):
        self.path.write_text("old data", encoding="utf-8")
        result = export_jsonl(self.logger.events, self.path, overwrite=True)
        self.assertEqual(result["event_count"], 2)
        self.assertEqual(load_jsonl(self.path), self.logger.events)

    def test_export_rejects_a_tampered_chain(self):
        changed = [dict(item) for item in self.logger.events]
        changed[0]["details"]["file"] = "changed.txt"
        with self.assertRaises(ValueError):
            export_jsonl(changed, self.path)

    def test_loader_rejects_bad_json_and_oversized_lines(self):
        self.path.write_text("{bad json}\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_jsonl(self.path)
        self.path.write_bytes(b"x" * 20 + b"\n")
        with self.assertRaises(ValueError):
            load_jsonl(self.path, max_line_bytes=10)

    def test_loader_enforces_event_limit(self):
        export_jsonl(self.logger.events, self.path)
        with self.assertRaises(ValueError):
            load_jsonl(self.path, max_events=1)

    def test_loader_detects_tampering(self):
        export_jsonl(self.logger.events, self.path)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        event = json.loads(lines[0])
        event["details"]["file"] = "changed.txt"
        lines[0] = json.dumps(event)
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_jsonl(self.path)


class test_integrity_diagnostics(unittest.TestCase):
    def setUp(self):
        self.logger = event_logger(run_id="integrity-run")
        for index in range(4):
            self.logger.emit("test", "event.recorded", index=index)

    def test_valid_chain_returns_diagnostic_summary(self):
        result = verify_event_chain(self.logger.events)
        self.assertTrue(result["valid"])
        self.assertEqual(result["events_checked"], 4)
        self.assertIsNone(result["failed_sequence"])

    def test_chain_reports_the_first_tampered_event(self):
        changed = [dict(item) for item in self.logger.events]
        changed[2] = dict(changed[2])
        changed[2]["details"] = {"index": 99}
        result = verify_event_chain(changed)
        self.assertFalse(result["valid"])
        self.assertEqual(result["failed_sequence"], 3)
        self.assertEqual(result["reason"], "event_hash_mismatch")

    def test_checkpoint_verifies_events_after_the_anchor(self):
        checkpoint = create_checkpoint(self.logger.events[:2])
        result = verify_checkpoint(self.logger.events[2:], checkpoint)
        self.assertTrue(result["valid"])
        self.assertEqual(result["checkpoint_sequence"], 2)
        self.assertEqual(result["final_sequence"], 4)

    def test_checkpoint_detects_suffix_tampering(self):
        checkpoint = create_checkpoint(self.logger.events[:2])
        changed = [dict(item) for item in self.logger.events[2:]]
        changed[0]["details"] = {"index": 50}
        result = verify_checkpoint(changed, checkpoint)
        self.assertFalse(result["valid"])
        self.assertEqual(result["failed_sequence"], 3)

    def test_empty_chain_is_valid_but_cannot_be_checkpointed(self):
        self.assertTrue(verify_event_chain([])["valid"])
        with self.assertRaises(ValueError):
            create_checkpoint([])


class test_forensic_summary(unittest.TestCase):
    def test_summary_counts_events_findings_and_integrity(self):
        logger = event_logger(run_id="summary-run")
        logger.emit("file_intel", "file.inspected", "info")
        logger.emit("c2", "c2.command_rejected", "warning")
        findings = [{"rule": "command_authentication_failure", "severity": "high"}]
        summary = build_forensic_summary(logger.events, findings)
        self.assertEqual(summary["event_count"], 2)
        self.assertEqual(summary["run_count"], 1)
        self.assertEqual(summary["findings"]["count"], 1)
        self.assertTrue(summary["integrity"]["valid"])
        self.assertEqual(summary["events_by_source"]["c2"], 1)


if __name__ == "__main__":
    unittest.main()
