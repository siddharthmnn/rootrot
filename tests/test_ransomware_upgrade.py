"""tests for safe, bounded ransomware targeting previews."""

import tempfile
import unittest
from pathlib import Path

from rootrot.events import event_logger
from rootrot.ransomware_simulator import ransomware_simulator


class test_ransomware_dry_run(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name)
        (self.workspace / "notes.txt").write_text("demo", encoding="utf-8")
        (self.workspace / "image.png").write_bytes(b"png")
        (self.workspace / "nested").mkdir()
        (self.workspace / "nested" / "data.json").write_text("{}", encoding="utf-8")
        self.logger = event_logger()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_default_dry_run_reports_reason_without_modifying_files(self):
        before = {path: path.read_bytes() for path in self.workspace.rglob("*") if path.is_file()}
        report = ransomware_simulator(self.workspace, self.logger).dry_run()
        after = {path: path.read_bytes() for path in self.workspace.rglob("*") if path.is_file()}
        self.assertEqual(len(report["targets"]), 2)
        self.assertTrue(all(item["reason"] for item in report["targets"]))
        self.assertEqual(report["files_encrypted"], 0)
        self.assertEqual(report["files_modified"], 0)
        self.assertEqual(before, after)

    def test_custom_extensions_and_excluded_paths(self):
        report = ransomware_simulator(
            self.workspace,
            self.logger,
            target_extensions={".png", ".json"},
            exclude_paths={"nested"},
        ).dry_run()
        self.assertEqual([item["name"] for item in report["targets"]], ["image.png"])

    def test_candidate_limit_is_reported(self):
        report = ransomware_simulator(self.workspace, self.logger, max_candidates=1).dry_run()
        self.assertEqual(report["target_count"], 1)
        self.assertTrue(report["truncated"])

    def test_invalid_extension_and_exclusion_are_rejected(self):
        with self.assertRaises(ValueError):
            ransomware_simulator(self.workspace, self.logger, target_extensions={"txt"})
        with self.assertRaises(ValueError):
            ransomware_simulator(self.workspace, self.logger, exclude_paths={"../outside"})


if __name__ == "__main__":
    unittest.main()
