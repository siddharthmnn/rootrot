"""keep the install metadata aligned with the project support policy."""

import tomllib
import unittest
from pathlib import Path


class test_project_metadata(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        project_root = Path(__file__).resolve().parents[1]
        cls.metadata = tomllib.loads(
            (project_root / "pyproject.toml").read_text(encoding="utf-8")
        )

    def test_python_floor_matches_the_supported_runtime(self):
        project = self.metadata["project"]
        self.assertEqual(project["requires-python"], ">=3.11")

    def test_console_entry_point_targets_the_cli(self):
        scripts = self.metadata["project"]["scripts"]
        self.assertEqual(scripts["rootrot"], "rootrot.cli:main")

    def test_runtime_dependencies_remain_empty(self):
        self.assertEqual(self.metadata["project"]["dependencies"], [])

    def test_development_tools_are_optional(self):
        dev = self.metadata["project"]["optional-dependencies"]["dev"]
        names = {dependency.split(">=")[0] for dependency in dev}
        self.assertTrue({"build", "coverage[toml]", "ruff", "twine"}.issubset(names))

    def test_setuptools_only_discovers_rootrot_packages(self):
        package_find = self.metadata["tool"]["setuptools"]["packages"]["find"]
        self.assertIn("rootrot*", package_find["include"])
        self.assertIn("tests*", package_find["exclude"])


if __name__ == "__main__":
    unittest.main()
