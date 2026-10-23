import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = (
    "ci/gitlab/jobs/security/sonarqube.yml",
    "ci/gitlab/jobs/security/sonarqube-cli.yml",
    ".github/workflows/sonarqube.yml",
)
BRANCH = "chore/issues-2422-after-release-24.0-and-25.0-develop"
API_MOCK = """
import json, os, sys
from urllib.parse import parse_qs, urlsplit
query = parse_qs(urlsplit(sys.argv[1]).query)
assert query["componentKeys"] == ["xs2a-connector-examples"], query
assert query["branch"] == [os.environ["SONAR_BRANCH_NAME"]], query
assert query["resolved"] == ["false"], query
assert query["ps"] == ["1"], query
if "MOCK_RESPONSE" in os.environ:
    print(os.environ["MOCK_RESPONSE"])
else:
    issues = json.loads(os.environ["MOCK_ISSUES"])
    count = sum(
        issue["status"] in ("OPEN", "CONFIRMED", "REOPENED")
        and all(
            key not in query or issue[field] in query[key][0].split(",")
            for key, field in (("types", "type"), ("severities", "severity"))
        )
        for issue in issues
    )
    print(json.dumps(
        {"paging": {"total": count}}
        if os.environ["MOCK_SHAPE"] == "paging" else {"total": count}
    ))
"""


def gate_script(template):
    source = (ROOT / template).read_text(encoding="utf-8")
    match = re.search(
        r'^ +issue_scope="branch=.*?^ +echo "SonarQube scan passed:.*?$',
        source,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"Missing issue gate in {template}")
    return textwrap.dedent(match.group())


class SonarQubeGateTest(unittest.TestCase):
    def run_gate(self, template, issues=(), shape="paging", response=None):
        env = {
            **os.environ,
            "SONAR_HOST_URL": "https://sonarqube.invalid",
            "SONAR_BRANCH_NAME": BRANCH,
            "CI_COMMIT_BRANCH": BRANCH,
            "CI_PIPELINE_SOURCE": "push",
            "sonar_branch_name": BRANCH,
            "project_key": "xs2a-connector-examples",
            "SONAR_FAIL_TYPES": "BUG,VULNERABILITY",
            "SONAR_FAIL_SEVERITIES": "BLOCKER,CRITICAL,MAJOR",
            "SONAR_COMPLIANCE_FILTERS": "Test=types=SECURITY_HOTSPOT",
            "MOCK_ISSUES": json.dumps(issues),
            "MOCK_SHAPE": shape,
        }
        env.pop("MOCK_RESPONSE", None)
        if response is not None:
            env["MOCK_RESPONSE"] = response
        api = "sonar_api_get() { python3 -c " + shlex.quote(API_MOCK) + ' "$1"; }\n'
        script = "set -eu\n" + api + gate_script(template)
        return subprocess.run(
            ["bash", "-c", script], env=env, text=True, capture_output=True
        )

    def test_each_severity_and_type_independently_blocks_open_and_confirmed_issues(self):
        for template in TEMPLATES:
            for shape in ("paging", "legacy"):
                for status in ("OPEN", "CONFIRMED"):
                    for issue_type, severity in (
                        ("CODE_SMELL", "MAJOR"),
                        ("CODE_SMELL", "CRITICAL"),
                        ("CODE_SMELL", "BLOCKER"),
                        ("BUG", "MINOR"),
                        ("VULNERABILITY", "MINOR"),
                    ):
                        with self.subTest(template=template, shape=shape, status=status, type=issue_type, severity=severity):
                            result = self.run_gate(template, [
                                {"type": issue_type, "severity": severity, "status": status}
                            ], shape)
                            self.assertEqual(result.returncode, 1, result.stderr)
                            self.assertIn("ERROR: SonarQube found", result.stdout)
                            self.assertNotIn("SonarQube scan passed", result.stdout)

    def test_clean_low_severity_and_resolved_issues_pass(self):
        for template in TEMPLATES:
            for shape in ("paging", "legacy"):
                for issues in (
                    [],
                    [{"type": "CODE_SMELL", "severity": "MINOR", "status": "OPEN"}],
                    [{"type": "BUG", "severity": "BLOCKER", "status": "FIXED"}],
                ):
                    with self.subTest(template=template, shape=shape, issues=issues):
                        result = self.run_gate(template, issues, shape)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn("SonarQube scan passed", result.stdout)

    def test_invalid_counts_fail_closed(self):
        for template in TEMPLATES:
            for payload in (
                {},
                {"total": None},
                {"total": "0"},
                {"total": -1},
                {"total": 0.5},
                {"total": False},
                {"paging": {"total": "0"}},
                {"paging": {"total": -1}},
                {"paging": {"total": False}},
                {"paging": {"total": False}, "total": 0},
                {"errors": [{"msg": "Search failed"}]},
            ):
                with self.subTest(template=template, payload=payload):
                    result = self.run_gate(template, response=json.dumps(payload))
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("no valid non-negative integer count", result.stderr)
                    self.assertNotIn("SonarQube scan passed", result.stdout)

    def test_null_paging_count_falls_back_to_legacy_total(self):
        for template in TEMPLATES:
            for paging in (None, {}, {"total": None}):
                with self.subTest(template=template, paging=paging):
                    result = self.run_gate(
                        template, response=json.dumps({"paging": paging, "total": 1})
                    )
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("ERROR: SonarQube found", result.stdout)

    def test_paging_total_takes_precedence_over_legacy_zero(self):
        for template in TEMPLATES:
            with self.subTest(template=template):
                result = self.run_gate(
                    template, response=json.dumps({"paging": {"total": 1}, "total": 0})
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("ERROR: SonarQube found", result.stdout)

    def test_compliance_gate_still_blocks(self):
        for template in TEMPLATES:
            with self.subTest(template=template):
                result = self.run_gate(template, [
                    {"type": "SECURITY_HOTSPOT", "severity": "MINOR", "status": "OPEN"}
                ])
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("mapped to Test", result.stdout)


if __name__ == "__main__":
    unittest.main()
