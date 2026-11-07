"""tests for streaming file inspection and type-mismatch reporting."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from rootrot.events import event_logger
from rootrot.file_intel import file_intel


class test_file_intel_upgrade(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name)
        self.logger = event_logger()
        self.scanner = file_intel(self.workspace, self.logger, chunk_size=1024)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_streaming_hash_matches_standard_sha256(self):
        content = b"rootrot-stream-check" * 10000
        path = self.workspace / "sample.txt"
        path.write_bytes(content)
        result = self.scanner.fingerprint(path)
        self.assertEqual(result["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(result["size"], len(content))

    def test_entropy_uses_the_entire_file_not_only_the_signature_sample(self):
        path = self.workspace / "large.txt"
        content = (b"a" * 9000) + bytes(range(64))
        path.write_bytes(content)
        result = self.scanner.fingerprint(path)
        self.assertGreater(result["entropy"], 0.0)
        self.assertAlmostEqual(result["entropy"], file_intel.entropy(content), places=4)

    def test_detects_pdf_signature(self):
        path = self.workspace / "sample.pdf"
        path.write_bytes(b"%PDF-1.7\nexample")
        result = self.scanner.fingerprint(path)
        self.assertEqual(result["file_type"], "pdf")
        self.assertFalse(result["extension_mismatch"])

    def test_flags_extension_mismatch(self):
        path = self.workspace / "invoice.txt"
        path.write_bytes(b"%PDF-1.7\nexample")
        result = self.scanner.fingerprint(path)
        self.assertEqual(result["file_type"], "pdf")
        self.assertTrue(result["extension_mismatch"])
        self.assertIn(
            "file.extension_mismatch",
            {event["action"] for event in self.logger.events},
        )

    def test_identifies_json_and_text_files(self):
        json_path = self.workspace / "settings.json"
        text_path = self.workspace / "notes.txt"
        json_path.write_text('{"safe": true}', encoding="utf-8")
        text_path.write_text("plain notes", encoding="utf-8")
        self.assertEqual(self.scanner.fingerprint(json_path)["file_type"], "json")
        self.assertEqual(self.scanner.fingerprint(text_path)["file_type"], "text")

    def test_reports_relative_path_and_modification_time(self):
        path = self.workspace / "nested" / "sample.txt"
        path.parent.mkdir()
        path.write_text("demo", encoding="utf-8")
        result = self.scanner.fingerprint(path)
        self.assertEqual(result["relative_path"], "nested/sample.txt")
        self.assertIn("modified_at", result)
        self.assertGreater(result["mtime_ns"], 0)

    def test_rejects_absolute_and_windows_paths(self):
        with self.assertRaises(ValueError):
            self.scanner.safe_path(str(self.workspace / "sample.txt"))
        with self.assertRaises(ValueError):
            self.scanner.safe_path("C:\\Users\\Public\\sample.txt")

    def test_rejects_symlink_escape(self):
        outside = self.workspace.parent / (self.workspace.name + "-outside.txt")
        outside.write_text("outside", encoding="utf-8")
        link = self.workspace / "link.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are not available")
        try:
            with self.assertRaises(ValueError):
                self.scanner.safe_path("link.txt")
        finally:
            outside.unlink(missing_ok=True)

    def test_rejects_file_over_size_limit(self):
        path = self.workspace / "large.txt"
        path.write_bytes(b"12345")
        scanner = file_intel(self.workspace, self.logger, max_file_size=4, chunk_size=1024)
        with self.assertRaises(ValueError):
            scanner.fingerprint(path)


if __name__ == "__main__":
    unittest.main()
