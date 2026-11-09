"""tests for benchmark input contracts and output structure."""

import unittest

from rootrot.validation.benchmark import run_detection_benchmark


class test_detection_benchmark(unittest.TestCase):
    def test_small_benchmark_returns_all_pipeline_measurements(self):
        result = run_detection_benchmark(sizes=(24, 48), iterations=2)
        self.assertEqual(result["benchmark"], "rootrot_detection_pipeline")
        self.assertEqual(
            [item["event_count"] for item in result["results"]],
            [24, 48],
        )
        for item in result["results"]:
            with self.subTest(size=item["event_count"]):
                self.assertGreaterEqual(item["detection"]["median_ms"], 0)
                self.assertGreaterEqual(
                    item["detection"]["events_per_second"],
                    0,
                )
                self.assertGreaterEqual(
                    item["integrity_verification"]["median_ms"],
                    0,
                )
                self.assertGreaterEqual(
                    item["event_filtering"]["median_ms"],
                    0,
                )

    def test_benchmark_rejects_invalid_parameters(self):
        invalid_sizes = ((), "100,200", (0,), (100_001,), (10, 10), (True,))
        for sizes in invalid_sizes:
            with self.subTest(sizes=sizes):
                with self.assertRaises(ValueError):
                    run_detection_benchmark(sizes=sizes, iterations=1)
        for iterations in (0, 21, True, 1.5):
            with self.subTest(iterations=iterations):
                with self.assertRaises(ValueError):
                    run_detection_benchmark(sizes=(10,), iterations=iterations)


if __name__ == "__main__":
    unittest.main()
