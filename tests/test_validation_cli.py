"""tests for validation, replay and benchmark cli commands."""

import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from rootrot.cli import main


class test_validation_cli(unittest.TestCase):
    def test_validate_command_emits_a_passing_json_report(self):
        output = io.StringIO()
        with patch("sys.argv", ["rootrot", "validate", "--fuzz-cases", "20"]):
            with redirect_stdout(output):
                main()
        report = json.loads(output.getvalue())
        self.assertTrue(report["passed"])
        self.assertEqual(report["fuzz_cases"], 20)

    def test_replay_command_emits_stable_digests(self):
        output = io.StringIO()
        with patch(
            "sys.argv",
            [
                "rootrot",
                "replay",
                "--scenario",
                "multi_stage_chain",
                "--repeat",
                "2",
            ],
        ):
            with redirect_stdout(output):
                main()
        report = json.loads(output.getvalue())
        self.assertTrue(report["deterministic"])
        self.assertEqual(report["repetitions"], 2)

    def test_benchmark_command_emits_measurements(self):
        output = io.StringIO()
        with patch(
            "sys.argv",
            [
                "rootrot",
                "benchmark",
                "--sizes",
                "20,40",
                "--iterations",
                "1",
            ],
        ):
            with redirect_stdout(output):
                main()
        report = json.loads(output.getvalue())
        self.assertEqual(
            [item["event_count"] for item in report["results"]],
            [20, 40],
        )

    def test_replay_requires_a_known_scenario(self):
        with patch(
            "sys.argv",
            ["rootrot", "replay", "--scenario", "not-real"],
        ):
            with self.assertRaises(SystemExit) as caught:
                main()
        self.assertEqual(caught.exception.code, 2)

    def test_validation_commands_reject_run_only_options(self):
        with patch(
            "sys.argv",
            ["rootrot", "validate", "--report-json", "report.json"],
        ):
            with self.assertRaises(SystemExit) as caught:
                main()
        self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
