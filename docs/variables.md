# CI/CD Variables Setup

Variables required by the shared job templates in `ci/` and `cd/`. Set these
in GitLab under **Settings → CI/CD → Variables**, at the scope indicated.
Group scope means set once on the `adorsys/xs2a` group; Project scope means
each consuming project sets its own value.

| Variable | Definition | Scope |
|---|---|---|
| `GITLAB_API` | Base URL of the GitLab instance | Group |
| `ADORSYS_CI_TEMPLATES_PROJECT` | Path of this templates repo | Group |
| `ADORSYS_CI_TEMPLATES_REF` | Ref/tag to pull shared scripts from | Group |
| `GITLAB_TOKEN` | PAT (api + write_repository scope) for MRs, releases, rollback, and Renovate | Group |
| `GITLAB_USER_NAME` / `GITLAB_USER_EMAIL` | Bot git commit identity | Group |
| `GITLAB_PAGES_DOMAIN` | Pages domain for vuln-report links | Group |
| `NVD_API_KEY` | NVD API key for OWASP scans | Group |
| `RENOVATE_GITHUB_TOKEN` | Renovate bot GitHub PAT (public deps) | Group |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook | Group |
| `SONAR_HOST_URL` / `SONAR_TOKEN` | SonarQube server + auth token | Group |
| `SONAR_PROJECT_KEY` | SonarQube project key | Project |
| `SONAR_JACOCO_REPORT_PATHS` | Path(s) to the JaCoCo XML coverage report passed to `sonar.coverage.jacoco.xmlReportPaths` (defaults to `$CI_PROJECT_DIR/**/target/site/jacoco-unit/jacoco.xml`) | Project (optional) |
| `COVERAGE_MINIMUM` | Minimum coverage ratio, between `0` and `1`; defaults to `0.80` (80%) when unset or empty. The unit-test job gates behavioural coverage against it; the integration-test job gates the integration surface against it | Group/Project (optional) |
| `COVERAGE_GATE_MODE` | Which classes the coverage gate measures: `behavioral` (unit-test job default — only classes with real decision logic are gated; enums/DTOs/constants/pure data holders are auto-excluded), `integration` (integration-test job default — only the integration surface is gated and classes with no IT are reported), or `all` (every class counts) | Project (optional) |
| `IT_SURFACE_MARKERS` | Integration-test job only. ERE of source markers that classify a `.java` under `src/main` as integration surface (needs an IT). Defaults to web endpoints (`@RestController`, `@RequestMapping`, `@GetMapping`…), persistence (`@Repository`, `@Entity`, `JpaRepository`, `EntityManager`, `JdbcTemplate`…), messaging (`@KafkaListener`, `@JmsListener`, `@EventListener`…), HTTP clients (`@FeignClient`, `RestTemplate`, `WebClient`), transactions (`@Transactional`), servlet filters and configuration (`@Configuration`, `@ConfigurationProperties`). Override to fit a project's stack. Validated before the scan; an invalid regex fails the job | Project (optional) |
| `IT_SERVICE_BOUNDARY_MARKERS` | Integration-test job only. ERE matched against `@Service` classes: a service whose source matches it (it depends on an SPI, remote client, repository/DAO, gateway/connector or messaging boundary) is also integration surface. Defaults to `Spi\|Remote\|Client\|Repository\|Dao\|Gateway\|Connector\|Publisher\|Producer\|Consumer\|Subscriber\|EventService\|Kafka\|Jms\|Rabbit\|JdbcTemplate\|DataSource\|EntityManager`. Validated before the scan; an invalid regex fails the job | Project (optional) |
| `JAVA_INTEGRATION_TESTS_ENABLED` | Presets only (`java-backend`, `java-multi-module`, `full-stack-build`). Set to `false` to remove the `Test (Integration)` job from the pipeline; any other value or unset keeps it | Project (optional) |
| `INTEGRATION_TESTS_REQUIRED` | Integration-test job only. Decides what happens when no integration tests ran (no Failsafe `target/failsafe-reports/TEST-*.xml`). `true`: the job fails. `false`: the coverage gate is skipped and the job ends with exit code `3`, shown as an allowed-failure warning. Unset (default): `true` if the repo has IT sources matching Failsafe's default includes (`IT*.java`, `*IT.java`, `*ITCase.java` under `src/test`), otherwise `false` | Project (optional) |
| `COVERAGE_TEST_REPORTS_DIR` | Internal; set by the integration-test job to `failsafe-reports`. Directory under `target/` that must contain `TEST-*.xml` for the job to count tests as having run. Do not override | — |
| `DOCKER_REGISTRY` | Docker registry host (we only push to our own registry, no Docker Hub) | Group |
| `DOCKER_REGISTRY_USER` / `DOCKER_REGISTRY_PASSWORD` | Docker registry login for Docker lint and package jobs | Group |
| `DOCKERHUB_NAMESPACE` | Docker image namespace | Project |
| `XS2A_VERSION` / `CONNECTOR_VERSION` / `LEDGERS_VERSION` | Versions resolved from pom.xml | Project |
| `GITHUB_DEPLOY_KEY_BASE64` / `GITHUB_TOKEN` | Auth for github-sync push | Project |
| `GITHUB_SSH_SERVER_FINGERPRINT` | github.com SSH host fingerprint | Group |
| `GITHUB_USERNAME` / `GITHUB_EMAIL` | Commit identity for github-sync | Group |

## Java coverage reports

Coverage defaults to 80%; set `COVERAGE_MINIMUM` to override it. Explicit values,
including `0`, are preserved.

The Java unit and integration templates (including their settings variants) run
`clean` before testing, write JaCoCo execution data to each module's
`target/jacoco.exec`, and generate reports in `target/site/jacoco`. Both
`jacoco.destFile` (agent output) and `jacoco.dataFile` (report input) are set to
the same path. Consuming POMs must retain these standard paths or bind their
`destFile`/`dataFile` configuration to the corresponding properties.

The templates copy the generated reports to `target/site/jacoco-unit` or
`target/site/jacoco-it` before evaluating coverage. These separate directories
remain the artifact and SonarQube input paths. Report output is not redirected
with `-Djacoco.outputDirectory`: JaCoCo's report goal has no such user property.
Consuming POMs must generate XML and CSV reports in `target/site/jacoco`.
Missing XML or CSV reports fail the job instead of silently bypassing the gate.
Individual modules may still opt out with `jacoco.skip`, but a job with no
reports fails. The integration job treats one case differently: when no
integration tests ran at all, see `INTEGRATION_TESTS_REQUIRED` and the migration
note below.

### Migration: integration-test job and projects without ITs

The presets always include `Test (Integration)`, which gates JaCoCo coverage.
What happens when Failsafe ran no tests (no `target/failsafe-reports/TEST-*.xml`):

| Situation | Result |
|---|---|
| No IT sources in the repo (`IT*.java`, `*IT.java`, `*ITCase.java` under `src/test`) | Gate skipped. Job exits `3` and shows as a **warning** (allowed failure); the pipeline stays green |
| IT sources exist, but none ran (renamed tests, custom includes, Failsafe only declared in `<pluginManagement>` or a profile the CLI goals don't activate) | Job **fails** |
| `INTEGRATION_TESTS_REQUIRED=true` | Job **fails** |
| `INTEGRATION_TESTS_REQUIRED=false` | Warning, as in the first row, even if IT sources exist |

Recommended actions for consuming projects:

- **No integration tests:** set `JAVA_INTEGRATION_TESTS_ENABLED: "false"` to
  remove the job (no warning, and no wasted dind runner time), or accept the
  warning.
- **ITs with non-default names** (not matched by the patterns above): set
  `INTEGRATION_TESTS_REQUIRED: "true"`, because auto-detection can't see them.
- **Custom `IT_SURFACE_MARKERS` / `IT_SERVICE_BOUNDARY_MARKERS`:** they must be
  valid POSIX extended regexes (`grep -E`). Invalid values now fail the job
  instead of yielding an empty integration surface.

Projects with ITs but no `@Service`/integration-marker classes no longer stop
silently during the integration-surface scan. The gate reports
"no in-scope classes to gate" instead.

Integration jobs run `test-compile` followed by `failsafe:integration-test` and
`failsafe:verify`, not the full `verify` lifecycle. This compiles main and test
sources without invoking Surefire or plugins bound to later lifecycle phases,
keeping unit-test execution and coverage out of the IT job. Plugins bound to
phases through `test-compile` (including `validate`) still run. Projects requiring
packaging or `pre-integration-test`/`post-integration-test` setup and teardown must
explicitly add those steps in their project-specific IT job.

## Template-Specific Inputs

Set these only when using the listed jobs. Values not marked optional are
required by that job.

| Variables | Jobs | Scope |
|---|---|---|
| `JAVA_MAVEN_IMAGE` | Java build, test, lint, SonarQube, and Maven release jobs | Project/group |
| `MAVEN_SETTINGS_PATH`, `MAVEN_DEPLOY_PROFILE`, `MAVEN_PRELEASE_PROFILE`, `MAVEN_RELEASE_PROFILE` | Maven release jobs | Project |
| `RELEASE_DEVELOP_MODE`, `RELEASE_DEVELOP_BRANCH` | Maven release plugin jobs | Project |
| `RELEASE_SUPPORT_MODE`, `RELEASE_SUPPORT_BRANCH_FORMAT` | Support-branch Maven release plugin jobs | Project |
| `RELEASE_VERSION`/`SNAPSHOT_VERSION` (develop) and `SUP_RELEASE_VERSION`/`SUP_SNAPSHOT_VERSION` (support) | Release + hotfix jobs. A three-segment release version with its snapshot variable **unset** is a hotfix; `RELEASE_SUPPORT_MASTER_BRANCH_FORMAT` + `RELEASE_SUPPORT_BRANCH_CAPTURE_REGEX` + `RELEASE_MAIN_BRANCH` drive the hotfix master/branch derivation | Pipeline/Project |
| `DOCKERHUB_NAMESPACE`, `DOCKER_IMAGE_NAME` | Single-image Docker package job | Project |
| `DOCKERHUB_NAMESPACE`, `DOCKER_IMAGE_NAMES` | Multi-image Docker package jobs | Project |
| `ANGULAR_LINT_TARGET`, `JAVA_LINT_TARGET`, `PMD_MAKE_TARGET`, `DOCKERFILE_MAKE_TARGET` | Corresponding Makefile lint jobs; optional overrides | Project |
| `LINT_YAML_ENABLED`, `LINT_XML_ENABLED` | YAML/XML lint; optional, default `false` | Project |
| `TYPECHECK_DIR` | Type-check lint; directory to run detection/checking in; optional, default `.` | Project |
| `TYPECHECK_COMMAND` | Type-check lint; overrides auto-detection with a custom command; optional | Project |
| `NPM_AUDIT_DIRS`, `NPM_AUDIT_LEVEL` | npm audit; optional, defaults to `.` and `high` | Project |
| `TRIVY_IMAGE` | Trivy image scan | Project |
| `TRIVY_SEVERITY`, `TRIVY_SKIP_FILES`, `TRIVY_TIMEOUT`, `TRIVY_FORMAT` | Trivy scans; optional overrides | Project |
| `SONAR_SOURCE_DIRS`, `SONAR_EXCLUSIONS`, `SONAR_JAVASCRIPT_LCOV_REPORT_PATHS` | SonarQube CLI scans; optional overrides | Project |
| `SONAR_ENABLE_SUPPORT_BRANCH_ANALYSIS`, `SONAR_ANALYSIS_TIMEOUT`, `SONAR_FAIL_TYPES`, `SONAR_FAIL_SEVERITIES`, `SONAR_COMPLIANCE_FILTERS` | SonarQube Maven and CLI scans; optional overrides (`SONAR_FAIL_TYPES` defaults `BUG,VULNERABILITY`, `SONAR_FAIL_SEVERITIES` defaults `BLOCKER,CRITICAL,MAJOR`, `SONAR_COMPLIANCE_FILTERS` is a `;`-separated list of `Label=filter=values` (explicit categories) or `Label=facet` (all categories, discovered from the `api/issues/search` facet) entries, defaulting to OWASP Top 10 2021 + CWE Top 25 2024 + PCI DSS 4.0 + OWASP ASVS 4.0 + STIG ASD V5R3 + CASA — set empty to disable the compliance gate) | Project |
| `GITLAB_CI_TEMPLATES_REF`, `SECURITY_BASE_BRANCH`, `SEVERITY_FILTER`, `OFFLINE_MODE` | Unified remediation; optional overrides | Project |
| `SCHEDULE_TYPE` | Scheduled npm audit, Renovate, and remediation jobs | Pipeline schedule |

## GitHub Actions secrets (this repo's own mirror workflow)

Set in `ADORSYS-GIS/adorsys-ci-cd-templates` → **Settings → Secrets and variables → Actions**.

| Secret | Definition |
|---|---|
| `XS2A_GITLAB_SYNC_TOKEN` | GitLab PAT/project-token (write_repository) used to push the mirror |
| `XS2A_GITLAB_SYNC_URL` | Host + path of the GitLab mirror target (no scheme/credentials) |
