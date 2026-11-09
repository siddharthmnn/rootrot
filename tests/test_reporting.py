"""tests for json and self-contained html report output."""

import json
import tempfile
import unittest
from pathlib import Path

from rootrot.reporting.html_report import render_html_report, write_html_report
from rootrot.reporting.json_report import render_json_report, write_json_report


class test_report_rendering(unittest.TestCase):
    def setUp(self):
        self.report = {
            "project": "rootrot",
            "version": "1.0.0",
            "run_id": "report-run",
            "profile": "multi_stage",
            "event_count": 1,
            "events": [
                {
                    "sequence": 1,
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "source": "file_intel",
                    "action": "file.inspected",
                    "severity": "info",
                    "details": {"name": "notes.txt"},
                }
            ],
            "detections": [
                {
                    "rule_id": "rr.test.001",
                    "rule": "test_finding",
                    "severity": "high",
                    "score": 75,
                    "explanation": "<script>alert('x')</script>",
                    "evidence": {"file": "notes.txt"},
                }
            ],
            "forensic_summary": {
                "event_count": 1,
                "findings": {"count": 1},
                "integrity": {"valid": True},
            },
            "safety": {"network_connections": False},
        }

    def test_json_rendering_is_valid_and_deterministic(self):
        first = render_json_report(self.report)
        second = render_json_report(self.report)
        self.assertEqual(first, second)
        self.assertEqual(json.loads(first)["run_id"], "report-run")

    def test_html_report_escapes_event_and_finding_content(self):
        output = render_html_report(self.report)
        self.assertIn("rootrot run report", output)
        self.assertIn("<th>elapsed</th>", output)
        self.assertIn("&lt;script&gt;", output)
        self.assertNotIn("<script>", output)
        self.assertNotIn("https://", output)

    def test_html_event_limit_is_enforced(self):
        report = dict(self.report)
        report["events"] = self.report["events"] * 3
        output = render_html_report(report, max_events=2)
        self.assertIn("showing the first 2 of 3 events", output)

    def test_invalid_html_event_limit_is_rejected(self):
        with self.assertRaises(ValueError):
            render_html_report(self.report, max_events=0)


class test_report_files(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp_dir.name)
        self.report = {"project": "rootrot", "events": [], "detections": []}

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_json_report_is_written_and_can_be_read_back(self):
        path = self.directory / "report.json"
        result = write_json_report(self.report, path)
        self.assertEqual(result["format"], "json")
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), self.report)

    def test_html_report_is_written(self):
        path = self.directory / "report.html"
        result = write_html_report(self.report, path)
        self.assertEqual(result["format"], "html")
        self.assertIn("<!doctype html>", path.read_text(encoding="utf-8"))

    def test_report_writers_refuse_unrequested_overwrites(self):
        path = self.directory / "report.json"
        write_json_report(self.report, path)
        with self.assertRaises(FileExistsError):
            write_json_report(self.report, path)

    def test_report_writer_can_overwrite_when_requested(self):
        path = self.directory / "report.json"
        write_json_report(self.report, path)
        result = write_json_report(self.report, path, overwrite=True)
        self.assertTrue(path.exists())
        self.assertEqual(result["format"], "json")


if __name__ == "__main__":
    unittest.main()
