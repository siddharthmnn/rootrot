"""tests for config selection and local report export options."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from rootrot.cli import main
from rootrot.core.config import rootrot_config
from rootrot.telemetry.jsonl import load_jsonl


class test_cli_config_options(unittest.TestCase):
    @patch("rootrot.cli.run_lab")
    def test_profile_option_builds_the_requested_config(self, run_lab):
        run_lab.return_value = {"project": "rootrot"}
        output = io.StringIO()
        with patch("sys.argv", ["rootrot", "run", "--profile", "basic"]):
            with redirect_stdout(output):
                main()
        config = run_lab.call_args.args[0]
        self.assertEqual(config.profile, "basic")
        self.assertEqual(json.loads(output.getvalue()), {"project": "rootrot"})

    @patch("rootrot.cli.run_lab")
    def test_config_file_is_loaded(self, run_lab):
        run_lab.return_value = {"project": "rootrot"}
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "run.json"
            path.write_text('{"profile": "file_analysis"}', encoding="utf-8")
            with patch("sys.argv", ["rootrot", "run", "--config", str(path)]):
                with redirect_stdout(io.StringIO()):
                    main()
        self.assertEqual(
            run_lab.call_args.args[0],
            rootrot_config(profile="file_analysis"),
        )

    def test_config_and_profile_cannot_be_combined(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "run.json"
            path.write_text('{"profile": "basic"}', encoding="utf-8")
            with patch(
                "sys.argv",
                ["rootrot", "run", "--config", str(path), "--profile", "basic"],
            ):
                with self.assertRaises(SystemExit) as caught:
                    main()
        self.assertEqual(caught.exception.code, 2)

    @patch("rootrot.cli.run_lab")
    def test_all_report_formats_can_be_written(self, run_lab):
        report = {
            "project": "rootrot",
            "events": [],
            "detections": [],
            "forensic_summary": {},
            "safety": {},
        }
        run_lab.return_value = report
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            events_path = directory / "events.jsonl"
            json_path = directory / "report.json"
            html_path = directory / "report.html"
            args = [
                "rootrot", "run",
                "--events-jsonl", str(events_path),
                "--report-json", str(json_path),
                "--report-html", str(html_path),
            ]
            output = io.StringIO()
            with patch("sys.argv", args), redirect_stdout(output):
                main()
            self.assertEqual(load_jsonl(events_path), [])
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8")), report)
            self.assertIn("<!doctype html>", html_path.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(output.getvalue()), report)

    @patch("rootrot.cli.run_lab")
    def test_existing_output_requires_overwrite(self, run_lab):
        run_lab.return_value = {"project": "rootrot", "events": []}
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.jsonl"
            path.write_text("keep me", encoding="utf-8")
            with patch("sys.argv", ["rootrot", "run", "--events-jsonl", str(path)]):
                with self.assertRaises(SystemExit) as caught:
                    main()
            self.assertEqual(caught.exception.code, 2)
            self.assertEqual(path.read_text(encoding="utf-8"), "keep me")

    def test_output_paths_must_be_distinct(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "same.out"
            args = ["rootrot", "run", "--report-json", str(path), "--report-html", str(path)]
            with patch("sys.argv", args):
                with self.assertRaises(SystemExit) as caught:
                    main()
        self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
