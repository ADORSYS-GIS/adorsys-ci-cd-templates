#!/usr/bin/env python3
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
NOTIFY_JOB = ROOT / "cd/gitlab/jobs/notify/slack-remediation-notify.yml"
REMEDIATION_JOB = ROOT / "ci/gitlab/jobs/security/unified-remediation.yml"
NOTIFY_SCRIPT = ROOT / "cd/gitlab/scripts/notify-remediation.sh"


class Loader(yaml.SafeLoader):
    pass


Loader.add_constructor("!reference", lambda loader, node: loader.construct_sequence(node))


class RemediationNotificationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.log = self.root / "curl.log"
        mock = self.root / "curl"
        mock.write_text(
            """#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["CURL_LOG"], "a") as out:
    out.write(json.dumps(args) + "\\n")
if os.environ.get("CURL_FAIL") == "1":
    sys.exit(22)
if "/repository/tags?" in " ".join(args):
    print(os.environ.get("CURL_TAGS", '[{"name":"tag/1"}]'))
elif "-o" in args:
    pathlib.Path(args[args.index("-o") + 1]).write_text("#!/bin/sh\\nexit 0\\n")
"""
        )
        mock.chmod(0o755)
        self.env = os.environ.copy()
        for key in ("GITLAB_TOKEN", "GITLAB_CI_TEMPLATES_REF", "ADORSYS_CI_TEMPLATES_REF",
                    "SLACK_WEBHOOK_URL", "SECURITY_BASE_BRANCH", "CI_PROJECT_ID"):
            self.env.pop(key, None)
        self.env.update({
            "PATH": f"{self.root}:{self.env['PATH']}",
            "CURL_LOG": str(self.log),
            "CI_JOB_TOKEN": "job-token",
            "CI_API_V4_URL": "https://gitlab.invalid/api/v4",
            "GITLAB_API": "https://gitlab.invalid",
            "ADORSYS_CI_TEMPLATES_PROJECT": "group/project",
            "CI_PIPELINE_URL": "https://gitlab.invalid/pipeline",
            "CI_PROJECT_URL": "https://gitlab.invalid/project",
        })

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def run_script(self, script, extra=None):
        env = self.env | (extra or {})
        return subprocess.run(["bash", "-c", script], cwd=self.root, env=env,
                              text=True, capture_output=True)

    def test_notification_download_auth_ref_and_errors(self):
        job = yaml.load(NOTIFY_JOB.read_text(), Loader=Loader)[".slack_notify_remediation"]
        self.assertNotIn("artifacts", job)
        script = job["script"][0].replace("/tmp/notify-remediation.sh", str(self.root / "notify.sh"))
        result = self.run_script(script, {
            "GITLAB_TOKEN": "private-token", "GITLAB_CI_TEMPLATES_REF": "feature/override",
            "ADORSYS_CI_TEMPLATES_REF": "feature/included",
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        call = self.calls()[-1]
        self.assertIn("PRIVATE-TOKEN: private-token", call)
        self.assertIn("ref=feature/override", call)
        self.assertTrue(any("group%2Fproject" in item for item in call))
        self.log.unlink()
        result = self.run_script(script, {"ADORSYS_CI_TEMPLATES_REF": "feature/included"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("JOB-TOKEN: job-token", self.calls()[-1])
        self.assertIn("ref=feature/included", self.calls()[-1])
        self.log.unlink()
        result = self.run_script(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ref=tag/1", self.calls()[-1])
        result = self.run_script(script, {"CURL_FAIL": "1", "ADORSYS_CI_TEMPLATES_REF": "main"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot download", result.stderr)
        result = self.run_script(script, {"CURL_TAGS": "[]"})
        self.assertNotEqual(result.returncode, 0)

    def test_remediation_downloads_share_auth_and_ref(self):
        job = yaml.load(REMEDIATION_JOB.read_text(), Loader=Loader)[".unified-remediation-download-scripts"]
        scripts = [item for item in job["before_script"] if isinstance(item, str) and "\n" in item]
        script = "\n".join(scripts).replace('"/scripts/', f'"{self.root}/scripts/')
        script = script.replace(" /scripts/", f" {self.root}/scripts/")
        (self.root / "scripts").mkdir()
        result = self.run_script(script, {"GITLAB_TOKEN": "private-token", "ADORSYS_CI_TEMPLATES_REF": "feature/ref"})
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertGreater(len(calls), 10)
        for call in calls:
            self.assertIn("PRIVATE-TOKEN: private-token", call)
            self.assertIn("ref=feature/ref", call)
        self.assertTrue(any("ci%2Fgitlab%2Fscripts%2Fsecurity_aggregator%2Fcli.py" in arg
                            for call in calls for arg in call))
        self.assertTrue((self.root / "scripts/security_aggregator/cli.py").is_file())
        self.log.unlink()
        result = self.run_script(script, {"GITLAB_CI_TEMPLATES_REF": "feature/override"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("JOB-TOKEN: job-token", self.calls()[0])
        self.assertIn("ref=feature/override", self.calls()[0])
        self.log.unlink()
        result = self.run_script(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ref=tag/1", self.calls()[-1])
        self.log.unlink()
        result = self.run_script(script, {"CURL_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot read template tags", result.stderr)
        result = self.run_script(script, {"CURL_FAIL": "1", "ADORSYS_CI_TEMPLATES_REF": "main"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Failed to download", result.stderr)

    def test_notification_rejects_missing_or_invalid_summary_and_reports_http_errors(self):
        env = {"SLACK_WEBHOOK_URL": "https://slack.invalid/hook"}
        command = f'bash "{NOTIFY_SCRIPT}"'
        result = self.run_script(command, env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("summary is missing", result.stderr)
        reports = self.root / "security-reports"
        reports.mkdir()
        summary = reports / "summary.json"
        summary.write_text('{"summary": {}, "error": "failed"}')
        result = self.run_script(command, env)
        self.assertNotEqual(result.returncode, 0)
        summary.write_text(json.dumps({"summary": {
            "total_cves": 0, "high_count": 0, "critical_count": 0, "actionable_count": 0,
        }}))
        result = self.run_script(command, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Notification sent", result.stdout)
        result = self.run_script(command, env | {"CURL_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Notification sent", result.stdout)


if __name__ == "__main__":
    unittest.main()
