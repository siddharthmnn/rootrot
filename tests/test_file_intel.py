"""tests for file inspection inside a temporary lab workspace."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from rootrot.events import event_logger
from rootrot.file_intel import file_intel


class test_file_intel(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name)
        self.logger = event_logger()
        self.scanner = file_intel(self.workspace, self.logger)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_entropy_for_empty_and_repeated_data(self):
        self.assertEqual(file_intel.entropy(b""), 0.0)
        self.assertEqual(file_intel.entropy(b"aaaa"), 0.0)

    def test_entropy_for_four_equally_common_bytes(self):
        self.assertAlmostEqual(file_intel.entropy(b"abcd"), 2.0)

    def test_fingerprint_returns_hash_and_file_metadata(self):
        sample = self.workspace / "notes.txt"
        content = b"synthetic lab notes"
        sample.write_bytes(content)

        result = self.scanner.fingerprint(sample)

        self.assertEqual(result["name"], "notes.txt")
        self.assertEqual(result["size"], len(content))
        self.assertEqual(result["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(result["extension"], ".txt")
        self.assertIn("entropy", result)

    def test_inventory_only_returns_files_in_the_workspace(self):
        (self.workspace / "one.txt").write_text("one", encoding="utf-8")
        (self.workspace / "two.json").write_text("{}", encoding="utf-8")
        (self.workspace / "folder").mkdir()
        (self.workspace / "folder" / "three.log").write_text(
            "three", encoding="utf-8"
        )

        results = self.scanner.inventory()

        self.assertEqual(len(results), 3)
        self.assertEqual(
            {item["name"] for item in results},
            {"one.txt", "two.json", "three.log"},
        )

    def test_path_traversal_is_rejected(self):
        with self.assertRaises(ValueError):
            self.scanner.safe_path("../outside.txt")

    def test_oversized_file_is_rejected(self):
        sample = self.workspace / "large.txt"
        sample.write_bytes(b"12345")
        small_limit_scanner = file_intel(
            self.workspace,
            self.logger,
            max_file_size=4,
        )

        with self.assertRaises(ValueError):
            small_limit_scanner.fingerprint(sample)


if __name__ == "__main__":
    unittest.main()
