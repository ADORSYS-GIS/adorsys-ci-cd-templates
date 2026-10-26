import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


TEMPLATE = (
    Path(__file__).resolve().parents[1] / "ci/gitlab/jobs/test/java-tests.yml"
).read_text(encoding="utf-8")
HEADER = (
    "GROUP,PACKAGE,CLASS,INSTRUCTION_MISSED,INSTRUCTION_COVERED,"
    "BRANCH_MISSED,BRANCH_COVERED,LINE_MISSED,LINE_COVERED,"
    "COMPLEXITY_MISSED,COMPLEXITY_COVERED,METHOD_MISSED,METHOD_COVERED\n"
)


def anchor_script(name):
    match = re.search(
        rf"^.*: &{name} \|\n((?:  .*\n|\n)+)", TEMPLATE, re.MULTILINE
    )
    if match is None:
        raise AssertionError(f"Missing script anchor: {name}")
    return textwrap.dedent(match.group(1))


class JavaCoverageTest(unittest.TestCase):
    def run_script(self, directory, anchor, subdir="jacoco-unit", mode="all", shell=("sh", "-eu"), env=None):
        return subprocess.run(
            [*shell, "-c", anchor_script(anchor)],
            cwd=directory,
            env={
                **os.environ,
                "COVERAGE_LABEL": "test",
                "COVERAGE_SUBDIR": subdir,
                "COVERAGE_MINIMUM": "0.80",
                "COVERAGE_GATE_MODE": mode,
                **(env or {}),
            },
            text=True,
            capture_output=True,
        )

    def write_report(self, directory, name, row):
        report = Path(directory) / name / "target/site/jacoco"
        report.mkdir(parents=True)
        (report / "jacoco.xml").write_text("<report/>", encoding="utf-8")
        (report / "jacoco.csv").write_text(HEADER + row, encoding="utf-8")
        return report

    def test_publish_and_gate_all_modules_for_both_report_paths(self):
        for subdir in ("jacoco-unit", "jacoco-it"):
            with self.subTest(subdir=subdir), tempfile.TemporaryDirectory() as directory:
                for name in ("module-one", "nested/module two"):
                    self.write_report(
                        directory, name, f"{name},example,Logic,10,90,1,1,1,1,2,2,1,1\n"
                    )
                result = self.run_script(directory, "publish-jacoco", subdir)
                self.assertEqual(result.returncode, 0, result.stderr)
                for name in ("module-one", "nested/module two"):
                    output = Path(directory) / name / "target/site" / subdir
                    self.assertEqual(
                        (output / "jacoco.xml").read_text(encoding="utf-8"), "<report/>"
                    )
                    self.assertTrue((output / "jacoco.csv").is_file())
                result = self.run_script(directory, "coverage-gate", subdir)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("90.00% (180/200 instructions)", result.stdout)

    def test_one_module_below_threshold_fails_even_when_total_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write_report(directory, "covered", "covered,example,Logic,0,1000,1,1,1,1,2,2,1,1\n")
            self.write_report(directory, "gap", "gap,example,Logic,21,79,1,1,1,1,2,2,1,1\n")
            self.assertEqual(self.run_script(directory, "publish-jacoco").returncode, 0)
            result = self.run_script(directory, "coverage-gate")
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("Total modules below the test coverage minimum: 1", result.stdout)

    def test_missing_xml_or_csv_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            for anchor in ("publish-jacoco", "coverage-gate"):
                result = self.run_script(directory, anchor)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("report not found", result.stdout)
            report = self.write_report(directory, "module", "")
            (report / "jacoco.csv").unlink()
            self.assertEqual(self.run_script(directory, "publish-jacoco").returncode, 0)
            self.assertEqual(self.run_script(directory, "coverage-gate").returncode, 1)

    def test_empty_counters_fail_but_excluded_classes_still_pass(self):
        for row, mode, expected in (
            ("", "all", 1),
            ("module,example,Dto,0,100,0,0,0,1,0,1,0,1\n", "behavioral", 0),
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                self.write_report(directory, "module", row)
                self.assertEqual(self.run_script(directory, "publish-jacoco").returncode, 0)
                result = self.run_script(directory, "coverage-gate", mode=mode)
                self.assertEqual(result.returncode, expected, result.stderr)

    # GitLab runs job scripts with bash `set -eo pipefail`.
    GITLAB_SHELL = ("bash", "-eo", "pipefail")

    def test_integration_gate_without_service_or_marker_classes_does_not_abort(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "module/src/main/java/example/Logic.java"
            source.parent.mkdir(parents=True)
            source.write_text("package example;\nclass Logic {}\n", encoding="utf-8")
            self.write_report(directory, "module", "module,example,Logic,10,90,1,1,1,1,2,2,1,1\n")
            self.assertEqual(
                self.run_script(directory, "publish-jacoco", "jacoco-it", shell=self.GITLAB_SHELL).returncode, 0
            )
            result = self.run_script(
                directory, "coverage-gate", "jacoco-it", mode="integration", shell=self.GITLAB_SHELL
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Integration surface: 0 source classes", result.stdout)
            self.assertIn("no in-scope classes to gate", result.stdout)

    def test_integration_publish_without_its_skips_unless_required(self):
        it_env = {"COVERAGE_TEST_REPORTS_DIR": "failsafe-reports"}
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_script(
                directory, "publish-jacoco", "jacoco-it", shell=self.GITLAB_SHELL, env=it_env
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("no tests ran", result.stdout)
            result = self.run_script(
                directory, "publish-jacoco", "jacoco-it", shell=self.GITLAB_SHELL,
                env={**it_env, "INTEGRATION_TESTS_REQUIRED": "true"},
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("INTEGRATION_TESTS_REQUIRED=true", result.stdout)
            # ITs ran but JaCoCo produced no report: still a hard failure.
            reports = Path(directory) / "module/target/failsafe-reports"
            reports.mkdir(parents=True)
            (reports / "TEST-example.LogicIT.xml").write_text("<testsuite/>", encoding="utf-8")
            result = self.run_script(
                directory, "publish-jacoco", "jacoco-it", shell=self.GITLAB_SHELL, env=it_env
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("report not found", result.stdout)

    def test_integration_job_declares_test_reports_dir_and_presets_allow_opt_out(self):
        self.assertIn('COVERAGE_TEST_REPORTS_DIR: "failsafe-reports"', TEMPLATE)
        presets = Path(__file__).resolve().parents[1] / "presets"
        for preset in presets.glob("*.yml"):
            text = preset.read_text(encoding="utf-8")
            if "extends: .test-java-integration" in text:
                with self.subTest(preset=preset.name):
                    self.assertIn("""if: '$JAVA_INTEGRATION_TESTS_ENABLED == "false"'""", text)

    def test_every_maven_variant_uses_matching_paths_and_publishes_before_gating(self):
        commands = re.findall(r"^    - (mvn .*jacoco:report.*)$", TEMPLATE, re.MULTILINE)
        self.assertEqual(len(commands), 4)
        self.assertEqual(sum("failsafe:integration-test" in command for command in commands), 2)
        for command in commands:
            with self.subTest(command=command):
                self.assertIn("-Djacoco.destFile=target/jacoco.exec", command)
                self.assertIn("-Djacoco.dataFile=target/jacoco.exec", command)
                self.assertNotIn("-Djacoco.outputDirectory", command)
                self.assertIn("clean jacoco:prepare-agent", command)
                if "failsafe:integration-test" in command:
                    self.assertIn(
                        "test-compile failsafe:integration-test failsafe:verify jacoco:report",
                        command,
                    )
                    self.assertNotIn(" verify ", command)
                    self.assertNotIn("-Dsurefire.skip", command)
                    self.assertNotIn("-Dskip.unit.tests", command)
                    self.assertIn("-DskipITs=false", command)
        self.assertEqual(
            len(re.findall(r"- \*publish-jacoco\n(?:    #.*\n)*    - \*coverage-gate", TEMPLATE)),
            4,
        )

    def test_coverage_default_and_explicit_overrides(self):
        defaults = re.findall(
            r"""^    - '(: "\$\{COVERAGE_MINIMUM[^']+)'$""",
            TEMPLATE,
            re.MULTILINE,
        )
        self.assertEqual(len(defaults), 2)
        for default in defaults:
            for value, expected in ((None, "0.80"), ("", "0.80"), ("0", "0"), ("0.95", "0.95")):
                with self.subTest(default=default, value=value):
                    env = dict(os.environ)
                    env.pop("COVERAGE_MINIMUM", None)
                    if value is not None:
                        env["COVERAGE_MINIMUM"] = value
                    result = subprocess.run(
                        ["sh", "-eu", "-c", default + '; printf "%s" "$COVERAGE_MINIMUM"'],
                        env=env,
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, expected)


if __name__ == "__main__":
    unittest.main()
