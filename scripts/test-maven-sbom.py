#!/usr/bin/env python3
import json
import io
import os
import runpy
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from html.parser import HTMLParser
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.error import HTTPError


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
        self.assertIn("\n  needs: []\n", template)
        self.assertIn("target/sbom.json", template)
        self.assertIn("target/sbom.html", template)
        self.assertIn("target/sbom-*.html", template)
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

    def test_remote_helpers_use_configured_project_ref_and_authentication(self):
        template = (ROOT / "ci/gitlab/jobs/security/sbom.yml").read_text()
        bootstrap = textwrap.dedent(template.split("python3 - <<'PY'\n", 1)[1].split("      PY\n", 1)[0])
        for token_env, header in (
            ({"CI_JOB_TOKEN": "fixture-job-token"}, "Job-token"),
            ({"GITLAB_TOKEN": "fixture-private-token"}, "Private-token"),
        ):
            with self.subTest(header=header):
                requests = []

                def download(request, timeout):
                    requests.append(request)
                    url = urlsplit(request.full_url)
                    self.assertIn("/projects/team%2Ftemplates/repository/files/", url.path)
                    self.assertEqual(parse_qs(url.query)["ref"], ["feature/improve-sbom-in-owasp-job"])
                    self.assertEqual(timeout, 60)
                    self.assertIn(header, dict(request.header_items()))
                    path = unquote(url.path.split("/repository/files/", 1)[1].removesuffix("/raw"))
                    return io.BytesIO((ROOT / path).read_bytes())

                environment = {
                    "ADORSYS_CI_TEMPLATES_PROJECT": "team/templates",
                    "ADORSYS_CI_TEMPLATES_REF": "feature/improve-sbom-in-owasp-job",
                    "CI_API_V4_URL": "https://git.example.invalid/api/v4",
                    "SBOM_HELPERS_DIR": str(self.temp_path / header),
                    **token_env,
                }
                with patch.dict(os.environ, environment, clear=True), patch(
                    "urllib.request.urlopen", side_effect=download
                ):
                    exec(compile(bootstrap, "<sbom-bootstrap>", "exec"), {})
                self.assertEqual(len(requests), 5)
                self.assertTrue(
                    (Path(environment["SBOM_HELPERS_DIR"]) / "ci/gitlab/scripts/generate-maven-sbom.sh").is_file()
                )
                for filename in ("spdx.schema.json", "jsf-0.82.schema.json"):
                    self.assertTrue(
                        (Path(environment["SBOM_HELPERS_DIR"]) / "ci/gitlab/schemas" / filename).is_file()
                    )
                with patch.dict(os.environ, environment, clear=True), patch(
                    "urllib.request.urlopen",
                    side_effect=HTTPError("https://git.example.invalid", 403, "Forbidden", {}, None),
                ):
                    with self.assertRaises(HTTPError):
                        exec(compile(bootstrap, "<sbom-bootstrap>", "exec"), {})

    def test_legacy_include_exposes_strict_alias_without_cycle(self):
        base = (ROOT / "ci/gitlab/jobs/security/cyclonedx-owasp.yml").read_text()
        strict = (ROOT / "ci/gitlab/jobs/security/cyclonedx-owasp-strict.yml").read_text()
        self.assertIn("local: 'ci/gitlab/jobs/security/cyclonedx-owasp-strict.yml'", base)
        self.assertNotIn("\ninclude:", strict)

    def test_detached_mr_and_tag_checkouts_have_source_labels(self):
        project = self.copy_fixture("single")
        run(["git", "checkout", "--detach"], project)
        fake_bin = self.temp_path / "fake-bin"
        fake_bin.mkdir()
        fake_mvn = fake_bin / "mvn"
        fake_mvn.write_text("#!/bin/sh\nexit 19\n")
        fake_mvn.chmod(0o755)
        for context, label in (
            ({"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "feature/sbom"}, "feature/sbom"),
            ({"CI_COMMIT_REF_NAME": "v1.0.0"}, "v1.0.0"),
        ):
            with self.subTest(label=label):
                result = self.run_generator(
                    project,
                    {
                        "CI_COMMIT_BRANCH": "",
                        "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "",
                        "CI_COMMIT_REF_NAME": "",
                        "PATH": f"{fake_bin}:{os.environ['PATH']}",
                        **context,
                    },
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"Generating SBOM for {label} at ", result.stdout)
                self.assertIn("Maven build failed", result.stdout)

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
        (target / "sbom.html").write_text("stale HTML")
        (target / "sbom-old.html").write_text("stale branch HTML")
        fake_bin = self.temp_path / "fake-bin"
        fake_bin.mkdir()
        fake_mvn = fake_bin / "mvn"
        fake_mvn.write_text("#!/bin/sh\nexit 19\n")
        fake_mvn.chmod(0o755)
        result = self.run_generator(project, {"PATH": f"{fake_bin}:{os.environ['PATH']}"}, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((target / "sbom.json").exists())
        self.assertFalse((target / "bom.json").exists())
        self.assertFalse((target / "sbom.html").exists())
        self.assertFalse((target / "sbom-old.html").exists())

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
            report = (project / f"target/sbom-{branch}.html").read_text()
            self.assertIn(f"<dd>{branch}</dd>", report)
            self.assertIn(f"<dd>{commit}</dd>", report)
        self.assertEqual(
            (project / "target/sbom.json").read_bytes(),
            (project / "target/sbom-scheduled.json").read_bytes(),
        )
        self.assertEqual(
            (project / "target/sbom.html").read_bytes(),
            (project / "target/sbom-scheduled.html").read_bytes(),
        )
        remediation = (ROOT / "ci/gitlab/jobs/security/unified-remediation-scheduled.yml").read_text()
        self.assertIn('cp "target/bom-${label}.json" target/bom.json', remediation)

    def test_validator_resolves_license_and_signature_schemas_offline(self):
        project = self.copy_fixture("single")
        bom_path = project / "sbom.json"
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {"component": {"type": "application", "name": "sbom-single-fixture", "bom-ref": "root"}},
            "components": [{
                "type": "library", "name": "dependency", "bom-ref": "dependency",
                "purl": "pkg:maven/example/dependency@1",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            }],
            "dependencies": [{"ref": "root", "dependsOn": ["dependency"]}, {"ref": "dependency"}],
            "signature": {"signers": [{"algorithm": "https://example.invalid/algorithm", "value": "fixture"}]},
        }
        command = [str(VALIDATOR), str(bom_path), str(SCHEMA), str(project / "pom.xml"), "branch", "commit"]
        with patch("socket.socket.connect", side_effect=AssertionError("network access is forbidden")), patch.dict(
            os.environ, {"NO_PROXY": "*"}
        ), patch("sys.argv", command):
            bom_path.write_text(json.dumps(bom))
            runpy.run_path(str(VALIDATOR), run_name="__main__")
            report_path = bom_path.with_suffix(".html")
            self.assertIn("Apache-2.0", report_path.read_text())
            self.assertIn("pkg:maven/example/dependency@1", report_path.read_text())
            for invalid in ("license", "signature"):
                with self.subTest(invalid=invalid):
                    broken = json.loads(json.dumps(bom))
                    if invalid == "license":
                        broken["components"][0]["licenses"][0]["license"]["id"] = "not-an-spdx-license"
                    else:
                        del broken["signature"]["signers"][0]["value"]
                    bom_path.write_text(json.dumps(broken))
                    report_path.write_text("stale report")
                    with self.assertRaisesRegex(SystemExit, "not valid against CycloneDX 1.6"):
                        runpy.run_path(str(VALIDATOR), run_name="__main__")
                    self.assertFalse(report_path.exists())
            bom_path.write_text(json.dumps(bom))
            write_text = Path.write_text

            def reject_html_write(path, *args, **kwargs):
                if path == report_path:
                    raise OSError("fixture disk error")
                return write_text(path, *args, **kwargs)

            with patch.object(Path, "write_text", reject_html_write):
                with self.assertRaisesRegex(SystemExit, "cannot write HTML inventory"):
                    runpy.run_path(str(VALIDATOR), run_name="__main__")
            self.assertFalse(report_path.exists())

    def test_html_inventory_escapes_values_and_links_all_dependencies(self):
        render = runpy.run_path(str(VALIDATOR))["render_html"]
        hostile = '<script>alert("inventory")</script>&'
        bom = {
            "specVersion": "1.6",
            "metadata": {"component": {
                "type": "application", "name": hostile, "version": "2.0", "bom-ref": "root",
            }},
            "components": [{
                "type": "library", "group": "example", "name": "library", "version": "1.0",
                "bom-ref": hostile, "scope": "required", "purl": hostile,
                "licenses": [{"expression": "MIT OR Apache-2.0"}, {"license": {"name": hostile}}],
            }],
            "dependencies": [{"ref": "root", "dependsOn": [hostile]}, {"ref": hostile}],
        }
        report = render(bom, hostile, "commit-sha")

        class ReportParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.ids = set()
                self.links = []
                self.sources = []
                self.tags = set()
                self.values = []

            def handle_starttag(self, tag, attrs):
                self.tags.add(tag)
                attrs = dict(attrs)
                if "id" in attrs:
                    self.ids.add(attrs["id"])
                if "href" in attrs:
                    self.links.append(attrs["href"])
                if "src" in attrs:
                    self.sources.append(attrs["src"])

            def handle_data(self, data):
                self.values.append(data)

        parser = ReportParser()
        parser.feed(report)
        self.assertNotIn("script", parser.tags)
        self.assertNotIn("link", parser.tags)
        self.assertEqual(parser.sources, [])
        self.assertNotIn(hostile, report)
        self.assertIn(hostile, parser.values)
        self.assertTrue(parser.links)
        for link in parser.links:
            self.assertTrue(link.startswith("#"))
            self.assertIn(link[1:], parser.ids)
        self.assertIn("MIT OR Apache-2.0", report)
        self.assertIn("<dd>commit-sha</dd>", report)
        self.assertIn("<dd>1</dd>", report)
        self.assertIn("No dependencies recorded", report)

    def test_validator_rejects_missing_or_modified_companion_schema(self):
        project = self.copy_fixture("single")
        local_schema = project / SCHEMA.name
        shutil.copyfile(SCHEMA, local_schema)
        bom_path = project / "sbom.json"
        bom_path.write_text("{}")
        command = [
            "python3", str(VALIDATOR), str(bom_path), str(local_schema),
            str(project / "pom.xml"), "branch", "commit",
        ]
        result = run(command, project, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot load schema", result.stdout)
        (project / "spdx.schema.json").write_text("{}")
        result = run(command, project, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("schema checksum mismatch", result.stdout)

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
