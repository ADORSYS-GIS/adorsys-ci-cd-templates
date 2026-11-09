#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "ci/gitlab/scripts/generate-maven-sbom.sh"
VALIDATOR = ROOT / "ci/gitlab/scripts/validate-maven-sbom.py"
SCHEMA = ROOT / "ci/gitlab/schemas/cyclonedx-bom-1.6.schema.json"
FIXTURES = ROOT / "tests/sbom"


def run(command, cwd, env=None, check=True):
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def init_repo(path, remote=None):
    run(["git", "init", "-q"], path)
    if remote:
        run(["git", "remote", "add", "origin", str(remote)], path)
    run(["git", "add", "."], path)
    run(
        [
            "git",
            "-c",
            "user.name=SBOM tests",
            "-c",
            "user.email=sbom@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        ],
        path,
    )


class MavenSbomTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="maven-sbom-test-")
        self.addCleanup(self.temp.cleanup)
        self.temp_path = Path(self.temp.name)

    def copy_fixture(self, name):
        destination = self.temp_path / name
        shutil.copytree(FIXTURES / name, destination)
        init_repo(destination)
        return destination

    def run_generator(self, cwd, extra_env=None, check=True):
        env = os.environ.copy()
        env.update(
            {
                "CI_COMMIT_BRANCH": "sbom-test",
                "CI_PIPELINE_SOURCE": "push",
                "CI_PIPELINE_ID": "test",
                "MAVEN_REPO_PATH": str(self.temp_path / "m2"),
            }
        )
        env.update(extra_env or {})
        return run(["bash", str(GENERATOR)], cwd, env, check=check)

    def test_java_presets_wire_independent_sbom_job_and_artifact(self):
        for preset in ("java-backend.yml", "java-multi-module.yml"):
            content = (ROOT / "presets" / preset).read_text()
            self.assertIn("ci/gitlab/jobs/security/sbom.yml", content)
            self.assertIn("\nsbom:\n  extends: .maven-sbom", content)
            self.assertIn("extends: .owasp-dependency-check", content)
        template = (ROOT / "ci/gitlab/jobs/security/sbom.yml").read_text()
        self.assertIn('name: "sbom"', template)
        self.assertIn("target/sbom.json", template)
        self.assertIn("when: always", template)
        self.assertIn("makeAggregateBom", (ROOT / "ci/gitlab/scripts/generate-maven-sbom.sh").read_text())
        cyclonedx_alias = (ROOT / "ci/gitlab/jobs/security/cyclonedx-owasp.yml").read_text()
        self.assertNotIn("makeBom", cyclonedx_alias)
        self.assertIn("expire_in: \"30 days\"", cyclonedx_alias)
        owasp = (ROOT / "ci/gitlab/jobs/security/owasp-dependency-check.yml").read_text()
        self.assertIn("allow_failure: true", owasp)
        self.assertIn("-DfailBuildOnCVSS=7", owasp)
        self.assertIn("dependency-check-data", owasp)
        self.assertIn(
            "- .owasp-dependency-check-strict",
            (ROOT / "ci/gitlab/jobs/security/cyclonedx-owasp-strict.yml").read_text(),
        )

    def test_remediation_resolves_the_dedicated_sbom_and_branch_artifact(self):
        helper = ROOT / "ci/gitlab/scripts/remediation-common-artifacts.sh"
        script = f"""
source "{helper}"
curl() {{ printf '[{{"id":123,"name":"sbom"}}]'; }}
resolve_artifact_links "https://git.example.invalid/api" token 1 2 develop
build_artifact_links "https://git.example.invalid/team/project" "" "" "" "$CYCLONEDX_JOB_ID" 2 "" "" develop "$CYCLONEDX_JOB_NAME"
"""
        output = run(["bash", "-c", script], ROOT).stdout
        self.assertIn("/123/artifacts/target/bom-develop.json", output)

    def test_single_module_has_transitives_and_excludes_test_scope(self):
        project = self.copy_fixture("single")
        self.run_generator(project)
        bom_path = project / "target/sbom.json"
        bom = json.loads(bom_path.read_text())
        components = {component["name"] for component in bom["components"]}
        self.assertIn("commons-text", components)
        self.assertIn("commons-lang3", components)
        self.assertIn("commons-collections4", components)
        self.assertIn("slf4j-api", components)
        self.assertNotIn("junit-jupiter", components)
        self.assertTrue(bom["dependencies"])
        self.assertEqual((project / "target/bom.json").read_bytes(), bom_path.read_bytes())

    def test_reactor_sbom_contains_modules_transitives_and_relationships(self):
        project = self.copy_fixture("reactor")
        self.run_generator(project)
        bom = json.loads((project / "target/sbom.json").read_text())
        components = {component["name"] for component in bom["components"]}
        self.assertIn("sbom-api-fixture", components)
        self.assertIn("sbom-service-fixture", components)
        self.assertIn("commons-text", components)
        self.assertIn("commons-lang3", components)
        self.assertNotIn("junit-jupiter", components)
        self.assertTrue(any(dependency.get("dependsOn") for dependency in bom["dependencies"]))
        refs = {component["name"]: component["bom-ref"] for component in bom["components"]}
        service_relationships = next(
            dependency
            for dependency in bom["dependencies"]
            if dependency["ref"] == refs["sbom-service-fixture"]
        )
        self.assertIn(refs["sbom-api-fixture"], service_relationships["dependsOn"])

    def test_generation_failure_does_not_reuse_previous_outputs(self):
        project = self.copy_fixture("single")
        target = project / "target"
        target.mkdir()
        (target / "sbom.json").write_text("stale SBOM")
        (target / "bom.json").write_text("stale compatibility BOM")
        fake_bin = self.temp_path / "fake-bin"
        fake_bin.mkdir()
        fake_mvn = fake_bin / "mvn"
        fake_mvn.write_text("#!/bin/sh\nexit 19\n")
        fake_mvn.chmod(0o755)
        result = self.run_generator(project, {"PATH": f"{fake_bin}:{os.environ['PATH']}"}, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((target / "sbom.json").exists())
        self.assertFalse((target / "bom.json").exists())

    def test_scheduled_branches_are_distinct_and_commit_associated(self):
        bare = self.temp_path / "origin.git"
        run(["git", "init", "--bare", "-q", str(bare)], self.temp_path)
        seed = self.temp_path / "seed"
        shutil.copytree(FIXTURES / "single", seed)
        run(["git", "init", "-q"], seed)
        run(["git", "add", "."], seed)
        run(
            [
                "git",
                "-c",
                "user.name=SBOM tests",
                "-c",
                "user.email=sbom@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "scheduled",
            ],
            seed,
        )
        commits = {}
        for branch in ("scheduled", "develop", "support-2.x"):
            run(["git", "checkout", "-q", "-B", branch], seed)
            marker = seed / f"branch-{branch}.txt"
            marker.write_text(branch)
            run(["git", "add", "."], seed)
            run(
                [
                    "git",
                    "-c",
                    "user.name=SBOM tests",
                    "-c",
                    "user.email=sbom@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-qm",
                    branch,
                ],
                seed,
            )
            commits[branch] = run(["git", "rev-parse", "HEAD"], seed).stdout.strip()
            run(["git", "push", "-q", str(bare), f"{branch}:{branch}"], seed)

        project = self.temp_path / "scheduled-checkout"
        run(["git", "clone", "-q", "--branch", "scheduled", str(bare), str(project)], self.temp_path)
        fake_bin = self.temp_path / "fake-mvn-bin"
        fake_bin.mkdir()
        fake_mvn = fake_bin / "mvn"
        fake_mvn.write_text(
            """#!/usr/bin/env python3
import json
import sys
from pathlib import Path

if not any(arg.endswith(":makeAggregateBom") for arg in sys.argv):
    raise SystemExit(0)
root = Path("pom.xml").read_text()
import re
artifact = re.search(r"<artifactId>([^<]+)</artifactId>", root).group(1)
version = re.search(r"<version>([^<]+)</version>", root).group(1)
ref = "pkg:maven/example.sbom/mock-library@1.0.0"
root_ref = f"pkg:maven/example.sbom/{artifact}@{version}"
bom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:12345678-1234-1234-1234-123456789abc",
    "version": 1,
    "metadata": {"component": {"type": "library", "name": artifact, "version": version, "bom-ref": root_ref}},
    "components": [{"type": "library", "name": "mock-library", "version": "1.0.0", "bom-ref": ref, "purl": ref}],
    "dependencies": [{"ref": root_ref, "dependsOn": [ref]}, {"ref": ref, "dependsOn": []}],
}
Path("target/sbom.json").write_text(json.dumps(bom))
"""
        )
        fake_mvn.chmod(0o755)
        env = os.environ.copy()
        env.update(
            {
                "CI_COMMIT_BRANCH": "scheduled",
                "CI_PIPELINE_SOURCE": "schedule",
                "SCHEDULE_TYPE": "security-scan",
                "MAVEN_REPO_PATH": str(self.temp_path / "m2"),
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
            }
        )
        run(["bash", str(GENERATOR)], project, env)

        manifest = json.loads((project / "target/sbom-manifest.json").read_text())
        self.assertEqual({entry["branch"]: entry["commit"] for entry in manifest}, commits)
        for branch, commit in commits.items():
            bom = json.loads((project / f"target/sbom-{branch}.json").read_text())
            properties = {item["name"]: item["value"] for item in bom["metadata"]["properties"]}
            self.assertEqual(properties["ci.branch"], branch)
            self.assertEqual(properties["ci.commit"], commit)
            self.assertTrue((project / f"target/bom-{branch}.json").is_file())
        self.assertEqual(
            (project / "target/sbom.json").read_bytes(),
            (project / "target/sbom-scheduled.json").read_bytes(),
        )
        remediation = (ROOT / "ci/gitlab/jobs/security/unified-remediation-scheduled.yml").read_text()
        self.assertIn('cp "target/bom-${label}.json" target/bom.json', remediation)

    def test_validator_rejects_missing_malformed_and_wrong_schema_output(self):
        project = self.copy_fixture("single")
        missing = project / "target/missing.json"
        command = ["python3", str(VALIDATOR), str(missing), str(SCHEMA), str(project / "pom.xml"), "branch", "commit"]
        self.assertNotEqual(run(command, project, check=False).returncode, 0)
        missing.parent.mkdir(exist_ok=True)
        missing.write_text("{malformed")
        self.assertNotEqual(run(command, project, check=False).returncode, 0)
        missing.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.7"}))
        self.assertNotEqual(run(command, project, check=False).returncode, 0)


if __name__ == "__main__":
    unittest.main()
