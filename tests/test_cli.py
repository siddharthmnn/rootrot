"""tests for selecting a built-in profile or loading a config file."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from rootrot.cli import main
from rootrot.core.config import rootrot_config


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


if __name__ == "__main__":
    unittest.main()
