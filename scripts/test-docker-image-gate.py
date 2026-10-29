import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "cd/gitlab/jobs/package/docker-build-push.yml"
).read_text(encoding="utf-8")
JOB = TEMPLATE.split(".docker-build-scan-push:\n", 1)[1].split(
    "\n.docker-login-registry:", 1
)[0]
SCRIPT = textwrap.dedent(
    re.search(r"  script:\n    - \|\n(.*?)  artifacts:", JOB, re.S).group(1)
)
TARGETS = " ".join(f"image-{i}=context-{i}" for i in range(7))


class DockerImageGateTest(unittest.TestCase):
    def run_gate(self, **overrides):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docker = root / "docker"
            docker.write_text(textwrap.dedent("""\
                #!/bin/sh
                echo "docker $*" >> "$CALLS"
                if [ "$1" = build ] && [ "${BUILD_ERROR:-0}" = 1 ]; then exit 2; fi
                if [ "$1 $2" = "image inspect" ]; then
                  for arg do last=$arg; done
                  echo "sha256:${last##*/}"
                fi
                """))
            trivy = root / "trivy"
            trivy.write_text(textwrap.dedent("""\
                #!/bin/sh
                echo "trivy $*" >> "$CALLS"
                if [ "$1 $2" = "image --download-db-only" ]; then
                  exit "${DB_ERROR:-0}"
                fi
                if [ "$1 $2" = "image --image-src" ]; then
                  report=''
                  while [ "$#" -gt 0 ]; do
                    if [ "$1" = --output ]; then report=$2; shift; fi
                    shift
                  done
                  if [ "${NO_REPORT:-0}" != 1 ]; then echo '{}' > "$report"; fi
                  if [ "${SCAN_FAIL_IMAGE:-}" = "$report" ]; then exit 1; fi
                  exit "${SCAN_EXIT:-0}"
                fi
                """))
            docker.chmod(0o755)
            trivy.chmod(0o755)
            calls = root / "calls"
            result = subprocess.run(
                ["sh", "-c", SCRIPT],
                cwd=root,
                env={
                    **os.environ,
                    "PATH": f"{root}:{os.environ['PATH']}",
                    "CALLS": str(calls),
                    "DOCKER_REGISTRY": "registry.example",
                    "DOCKERHUB_NAMESPACE": "team/project",
                    "DOCKER_TAG": "release",
                    "DOCKER_BUILD_TARGETS": TARGETS,
                    "DOCKER_SCAN_SEVERITY": "HIGH,CRITICAL",
                    "TRIVY_TIMEOUT": "15m0s",
                    **overrides,
                },
                text=True,
                capture_output=True,
            )
            return result, calls.read_text().splitlines() if calls.exists() else []

    def test_all_seven_images_are_scanned_before_any_push(self):
        result, calls = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        builds = [i for i, call in enumerate(calls) if call.startswith("docker build ")]
        scans = [i for i, call in enumerate(calls) if call.startswith("trivy image --image-src")]
        pushes = [i for i, call in enumerate(calls) if call.startswith("docker push ")]
        self.assertEqual((len(builds), len(scans), len(pushes)), (7, 7, 7))
        self.assertLess(max(builds), min(scans))
        self.assertLess(max(scans), min(pushes))
        for i in scans:
            self.assertIn("--scanners vuln --pkg-types os,library", calls[i])
            self.assertIn("--severity HIGH,CRITICAL", calls[i])
            self.assertIn("--ignore-unfixed=false --ignorefile /dev/null", calls[i])
            self.assertIn("--exit-code 1 sha256:", calls[i])

    def test_vulnerabilities_and_scanner_errors_block_all_pushes(self):
        for status in ("1", "2"):
            with self.subTest(status=status):
                result, calls = self.run_gate(SCAN_EXIT=status)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(sum(call.startswith("trivy image --image-src") for call in calls), 7)
                self.assertFalse(any(call.startswith("docker push ") for call in calls))

    def test_database_failure_blocks_scanning_and_publishing(self):
        result, calls = self.run_gate(DB_ERROR="2")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call.startswith("docker push ") for call in calls))
        self.assertFalse(any(call.startswith("trivy image --image-src") for call in calls))

    def test_one_failed_image_blocks_pushes_even_when_later_scans_pass(self):
        result, calls = self.run_gate(SCAN_FAIL_IMAGE="trivy-images/image-3.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sum(call.startswith("trivy image --image-src") for call in calls), 7)
        self.assertFalse(any(call.startswith("docker push ") for call in calls))

    def test_build_failure_blocks_scanning_and_publishing(self):
        result, calls = self.run_gate(BUILD_ERROR="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call.startswith(("trivy ", "docker push ")) for call in calls))

    def test_missing_reports_block_publishing_even_with_success_exit(self):
        result, calls = self.run_gate(NO_REPORT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing image scan report", result.stderr)
        self.assertFalse(any(call.startswith("docker push ") for call in calls))

    def test_empty_configuration_and_invalid_targets_fail_closed(self):
        for overrides in (
            {"DOCKER_BUILD_TARGETS": ""},
            {"DOCKER_BUILD_TARGETS": " \n "},
            {"DOCKER_BUILD_TARGETS": "missing-context"},
            {"DOCKER_BUILD_TARGETS": "image="},
            {"DOCKER_BUILD_TARGETS": "=context"},
            {"DOCKER_TAG": ""},
            {"DOCKER_SCAN_SEVERITY": ""},
        ):
            with self.subTest(overrides=overrides):
                result, calls = self.run_gate(**overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(call.startswith("docker push ") for call in calls))

    def test_gate_is_required_and_reports_survive_failure(self):
        self.assertIn("allow_failure: false", JOB)
        self.assertIn('when: always\n    paths:\n      - trivy-images/', JOB)
        self.assertIn('docker cp "$scanner_container:/usr/local/bin/trivy"', JOB)
        self.assertIn('trap \'docker rm "$scanner_container" >/dev/null\' EXIT', JOB)


if __name__ == "__main__":
    unittest.main()
