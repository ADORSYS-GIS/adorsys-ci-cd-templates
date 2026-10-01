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
| `COVERAGE_MINIMUM` | Minimum unit-test and integration-test coverage ratio, between `0` and `1` | Group/Project |
| `DOCKER_REGISTRY` | Docker registry host (we only push to our own registry, no Docker Hub) | Group |
| `DOCKER_REGISTRY_USER` / `DOCKER_REGISTRY_PASSWORD` | Docker registry login for Docker lint and package jobs | Group |
| `DOCKERHUB_NAMESPACE` | Docker image namespace | Project |
| `XS2A_VERSION` / `CONNECTOR_VERSION` / `LEDGERS_VERSION` | Versions resolved from pom.xml | Project |
| `GITHUB_DEPLOY_KEY_BASE64` / `GITHUB_TOKEN` | Auth for github-sync push | Project |
| `GITHUB_SSH_SERVER_FINGERPRINT` | github.com SSH host fingerprint | Group |
| `GITHUB_USERNAME` / `GITHUB_EMAIL` | Commit identity for github-sync | Group |

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
