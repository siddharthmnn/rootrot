"""tests for in-memory chunk manifests and reassembly integrity."""

import hashlib
import unittest

from rootrot.events import event_logger
from rootrot.staging_simulator import staging_simulator


class test_staging_integrity(unittest.TestCase):
    def setUp(self):
        self.logger = event_logger()
        self.simulator = staging_simulator(self.logger, chunk_size=8, max_data_size=1024)

    def test_manifest_verifies_reassembly(self):
        data = b"synthetic-data-for-rootrot"
        report = self.simulator.run(data)
        self.assertTrue(report["integrity_verified"])
        self.assertEqual(report["sha256"], hashlib.sha256(data).hexdigest())
        self.assertTrue(staging_simulator.verify_manifest(data, report))
        self.assertFalse(report["transmitted"])

    def test_manifest_detects_tampered_chunk_metadata(self):
        data = b"synthetic-data"
        report = self.simulator.run(data)
        report["chunks"][0]["sha256"] = "0" * 64
        self.assertFalse(staging_simulator.verify_manifest(data, report))

    def test_empty_input_has_valid_empty_manifest(self):
        report = self.simulator.run(b"")
        self.assertEqual(report["chunk_count"], 0)
        self.assertTrue(report["integrity_verified"])

    def test_non_bytes_and_oversized_inputs_are_rejected(self):
        with self.assertRaises(TypeError):
            self.simulator.run("not bytes")
        with self.assertRaises(ValueError):
            self.simulator.run(b"x" * 1025)

    def test_invalid_chunk_size_is_rejected(self):
        with self.assertRaises(ValueError):
            staging_simulator(self.logger, chunk_size=0)

    def test_chunk_count_limit_is_enforced(self):
        limited = staging_simulator(self.logger, chunk_size=1, max_data_size=100, max_chunks=4)
        with self.assertRaises(ValueError):
            limited.run(b"12345")


if __name__ == "__main__":
    unittest.main()
