import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch


class SarifSuppressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = Path(__file__).parent
        cls.htmlConverter = runpy.run_path(str(directory / "sarif-to-html.py"))
        cls.gitlabConverter = runpy.run_path(str(directory / "sarif-to-gitlab.py"))

    def test_suppression_statuses_preserve_reporting_and_gating(self):
        cases = [
            ([], 1),
            ([{"kind": "inSource"}], 0),
            ([{"kind": "inSource", "status": "accepted"}], 0),
            ([{"kind": "external", "status": "accepted"}], 0),
            ([{"kind": "inSource", "status": "rejected"}], 1),
            ([{"kind": "external", "status": "underReview"}], 1),
        ]
        for suppressions, expected in cases:
            with self.subTest(suppressions=suppressions), tempfile.TemporaryDirectory() as directory:
                result = {
                    "ruleId": "test-rule",
                    "level": "error",
                    "message": {"text": "Test finding"},
                    "suppressions": suppressions,
                }
                sarif = {"runs": [{"results": [result]}]}
                self.assertEqual(len(self.htmlConverter["load_rows"](sarif)), expected)
                source = Path(directory) / "input.sarif"
                output = Path(directory) / "gitlab.json"
                source.write_text(json.dumps(sarif), encoding="utf-8")
                with patch.dict(os.environ, {"SAST_FAIL_SEVERITIES": "HIGH"}), contextlib.redirect_stderr(io.StringIO()):
                    code = self.gitlabConverter["main"](["converter", str(source), str(output), "semgrep"])
                report = json.loads(output.read_text(encoding="utf-8"))
                self.assertEqual(len(report["vulnerabilities"]), expected)
                self.assertEqual(report["scan"]["status"], "success")
                self.assertEqual(code, 3 if expected else 0)

    def test_invalid_scan_output_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.sarif"
            output = Path(directory) / "gitlab.json"
            source.write_text("{}", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                code = self.gitlabConverter["main"](["converter", str(source), str(output), "semgrep"])
            self.assertEqual(code, 2)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["scan"]["status"], "failure")


if __name__ == "__main__":
    unittest.main()