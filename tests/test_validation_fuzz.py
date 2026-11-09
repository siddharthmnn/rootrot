"""tests for the bounded seeded parser mutation harness."""

import unittest

from rootrot.validation.fuzz import run_parser_fuzz


class test_parser_fuzz(unittest.TestCase):
    def test_seeded_fuzz_run_rejects_every_invalid_input(self):
        result = run_parser_fuzz(seed=2026, cases=120)
        self.assertTrue(result["passed"])
        self.assertEqual(result["requested_cases"], 120)
        self.assertEqual(result["event_cases"], 60)
        self.assertEqual(result["config_cases"], 60)
        self.assertEqual(result["rejected_cases"], 120)
        self.assertEqual(result["accepted_invalid_inputs"], [])
        self.assertEqual(result["unexpected_errors"], [])

    def test_fuzz_output_is_deterministic_for_a_fixed_seed(self):
        first = run_parser_fuzz(seed=77, cases=40)
        second = run_parser_fuzz(seed=77, cases=40)
        self.assertEqual(first, second)

    def test_invalid_fuzz_parameters_are_rejected(self):
        for seed, cases in ((True, 10), (1, 1), (1, 10_001), ("seed", 10)):
            with self.subTest(seed=seed, cases=cases):
                with self.assertRaises(ValueError):
                    run_parser_fuzz(seed=seed, cases=cases)


if __name__ == "__main__":
    unittest.main()
