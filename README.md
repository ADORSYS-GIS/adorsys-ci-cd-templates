# adorsys CI/CD Templates Repository

This repository contains reusable CI/CD templates for adorsys projects on **both
GitLab CI and GitHub Actions**. GitLab projects consume it via GitLab's
`include:` directive; GitHub projects consume it via reusable **composite
actions** and **reusable workflows**. The heavy lifting lives once in
platform-neutral scripts under `scripts/ci/`, so the same logic backs both
platforms.

## Architecture

The repository is one source of truth with two thin platform adapters over a
single set of scripts:

```
adorsys-ci-templates/
  scripts/ci/            # platform-NEUTRAL logic (pure POSIX/pwsh, env-driven)
    generate-checksums.sh
    lint-shell.sh
    scan-secrets.sh
    lint-powershell.ps1
  templates/ , presets/  # GitLab adapter  -> included with `include: project:`
  .github/actions/       # GitHub adapter  -> composite actions call scripts/ci
  .github/workflows/     # GitHub adapter  -> reusable workflows (workflow_call)
```

- **Platform-neutral scripts** do the real work (checksums, shell/PowerShell
  linting, secret grep). They read only their own flags/arguments — no
  `CI_*` / `GITHUB_*` variables — so they are identical on every platform.
- **GitLab jobs** and **GitHub actions** are wrappers that call those scripts.
  New logic is added to the script once and both platforms get it.

### How each platform reaches this repo

| | GitLab consumers (e.g. `ledgers`) | GitHub consumers (e.g. `wazuh-*`) |
|---|---|---|
| Mechanism | `include: project: … file: …` | `uses: <owner>/<repo>/…@<ref>` |
| Requirement | repo on the same GitLab instance | repo reachable on **GitHub** |

GitHub Actions can only `uses:` actions/workflows that are hosted on GitHub, so
the GitHub side requires this repo to have a **read-only GitHub mirror**
(source of truth stays on GitLab; the mirror is auto-synced). The GitHub
examples below assume the mirror slug `ADORSYS-GIS/adorsys-ci-templates`.

## GitHub Actions Usage

### Composite actions (step-level reuse)

Drop a shared step into any GitHub workflow after checking out your repo:

```yaml
jobs:
  checks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # ShellCheck + PSScriptAnalyzer
      - uses: ADORSYS-GIS/adorsys-ci-templates/.github/actions/lint-scripts@main
        with:
          shell-paths: "scripts lib"        # space-separated (ShellCheck)
          powershell-paths: "scripts,lib"   # comma-separated (PSScriptAnalyzer)

      # Trivy filesystem scan + hardcoded-secret grep
      - uses: ADORSYS-GIS/adorsys-ci-templates/.github/actions/security-scan@main
        with:
          scan-paths: "scripts lib"

      # SHA-256 checksums -> checksums.sha256
      - uses: ADORSYS-GIS/adorsys-ci-templates/.github/actions/generate-checksums@main
        with:
          paths: "scripts lib assets version.txt"
          sort: "true"
```

Committing/uploading `checksums.sha256` and creating releases stays in the
consumer repo, because those rules differ per project.

### Reusable workflow (job-level preset)

For a one-line lint + security bundle:

```yaml
jobs:
  checks:
    uses: ADORSYS-GIS/adorsys-ci-templates/.github/workflows/scripts-checks.yml@main
    with:
      shell-paths: "scripts lib"
      powershell-paths: "scripts,lib"
      scan-paths: "scripts lib"
```

### Available GitHub components

| Component | Type | Purpose |
|-----------|------|---------|
| `.github/actions/lint-scripts` | composite | ShellCheck + PSScriptAnalyzer |
| `.github/actions/security-scan` | composite | Trivy FS scan + secret grep |
| `.github/actions/generate-checksums` | composite | `checksums.sha256` generation |
| `.github/workflows/scripts-checks.yml` | reusable workflow | lint + security bundle |

### Migrating a GitHub repo to the shared CI

1. Replace the inline ShellCheck/PSScriptAnalyzer steps with the `lint-scripts`
   action.
2. Replace the inline Trivy + secret-grep steps with the `security-scan` action.
3. Replace the inline `find … sha256sum` step with the `generate-checksums`
   action (keep your own commit/push/upload steps).
4. Keep job names and `needs:` graphs so gating/behavior is preserved.

## Usage

### Including Templates in Your Project

Add this to your `.gitlab-ci.yml`:

```yaml
include:
  - project: 'adorsys/xs2a/gitlab-ci-templates'
    ref: 'v1.1.2'
    file: 'presets/java-backend.yml'
```

### Including Individual Jobs

```yaml
include:
  - project: 'adorsys/xs2a/gitlab-ci-templates'
    ref: 'v1.1.2'
    file: 'templates/jobs/security/owasp-dependency-check.yml'
  - project: 'adorsys/xs2a/gitlab-ci-templates'
    ref: 'v1.1.2'
    file: 'templates/services/docker-dind.yml'

stages:
  - Lint
  - Compile
  - Test
  - Package
  - Release

# Use the extended job
OWASP Dependency Check:
  extends: .owasp-dependency-check
  variables:
    JAVA_TOOL_OPTIONS: "-XX:+UnlockExperimentalVMOptions -Xmx2048m"
```

### Using Presets (Recommended for Quick Setup)

Presets bundle common job combinations for typical project types:

```yaml
include:
  - project: 'adorsys/xs2a/gitlab-ci-templates'
    ref: 'v1.1.2'
    file: 'presets/java-backend.yml'

# Override project-specific variables
variables:
  DOCKER_IMAGE_NAMES: "my-app"
  JAVA_VERSION: "21.0.2-open"
```

## Template Versioning

- Use semantic versioning for releases (v1.0.0, v1.1.0, etc.)
- Pin to specific versions in production projects
- Use branch names for development testing

```yaml
# Production - pinned version
include:
  - project: 'adorsys/xs2a/gitlab-ci-templates'
    ref: 'v1.2.0'
    file: 'presets/java-backend.yml'
```

```yaml
# Development - latest from main
include:
  - project: 'adorsys/xs2a/gitlab-ci-templates'
    ref: 'main'
    file: 'presets/java-backend.yml'
```

## Available Templates

### Job Templates

| Template | Description |
|----------|-------------|
| `dockerfile-lint.yml` | Hadolint-based Dockerfile linting |
| `yaml-json-xml-lint.yml` | Lint YAML, JSON, XML files |
| `docker-compose-lint.yml` | Docker Compose file validation |
| `ci-file-lint.yml` | GitLab CI file linting with yamllint |
| `shell-lint.yml` | ShellCheck via shared `scripts/ci/lint-shell.sh` (opt-in) |
| `secret-scan.yml` | Hardcoded-secret grep via shared `scripts/ci/scan-secrets.sh` (opt-in) |
| `pmd-cpd.yml` | PMD/CPD static analysis |
| `owasp-dependency-check.yml` | OWASP dependency vulnerability scan |
| `java-maven.yml` | Java Maven build with caching |
| `docker.yml` | Docker build operations |
| `java-unit-tests.yml` | Java unit test execution |
| `java-integration-tests.yml` | Java integration tests with Testcontainers |
| `javadoc.yml` | Javadoc generation |
| `docker-build-push.yml` | Multi-image Docker build & push |
| `sonarqube.yml` | SonarQube analysis integration |
| `maven-release.yml` | Maven artifact deployment |
| `github-sync.yml` | GitHub repository synchronization |

### Service Templates

| Template | Description |
|----------|-------------|
| `docker-dind.yml` | Docker-in-Docker service configuration |

### Variable Templates

| Template | Description |
|----------|-------------|
| `java-variables.yml` | Common Java/SDKMan variables |
| `docker-variables.yml` | Docker registry variables |
| `maven-variables.yml` | Maven cache and repository variables |

## Extending Templates

Templates use hidden jobs (prefixed with `.`) that can be extended:

```yaml
# In your project's .gitlab-ci.yml
include:
  - project: 'adorsys/xs2a/gitlab-ci-templates'
    ref: 'v1.1.2'
    file: 'templates/jobs/build/java-maven.yml'

Build Java:
  extends: .build-java-maven
  variables:
    JAVA_VERSION: "21.0.2-open"
    MAVEN_OPTS: "-Dmaven.repo.local=${CI_PROJECT_DIR}/.m2/repository"
  script:
    - !reference [.build-java-maven, script]
    - echo "Additional project-specific build steps"
```

## Customization Points

Most templates accept variables for customization:

| Variable | Default | Description |
|----------|---------|-------------|
| `JAVA_VERSION` | `21.0.2-open` | SDKMan Java version |
| `MAVEN_REPO_PATH` | `.m2/repository` | Maven local repository path |
| `DOCKER_TAG` | `$CI_COMMIT_REF_SLUG` | Docker image tag |
| `DOCKERHUB_REGISTRY` | `gitlab-registry.adorsys.de` | Docker registry URL |
| `DOCKERHUB_NAMESPACE` | Project-specific | Docker image namespace |
| `SONAR_PROJECT_KEY` | Auto-detected | SonarQube project key |
| `OWASP_CACHE_KEY` | `dependency-check` | OWASP NVD cache key |

## SonarQube Integration

`.sonarqube-security-gate` performs Maven scanner analysis and waits for the
server-side quality gate. It relies on the scanner's GitLab CI auto-detection
for branch and merge-request parameters; do not set `sonar.branch.name` or
`sonar.pullrequest.*` manually in projects that use this template.

The job runs for internal merge requests and for `develop` pushes. For normal
projects it also considers `support-N.x` pushes and MR targets, but uses
`git ls-remote` plus version ordering to analyze only the highest numeric
support branch. Set `SONAR_ENABLE_SUPPORT_BRANCH_ANALYSIS: "false"` in a
project that must analyze `develop` only. Fork merge requests never create a
SonarQube job.

### Required Variables

| Variable | Scope | Secret | Configuration |
|----------|-------|--------|---------------|
| `SONAR_HOST_URL` | Group | No | SonarQube server base URL, without a trailing slash |
| `SONAR_TOKEN` | Group | Yes | Masked token with the minimum Execute Analysis permission required by the existing projects |
| `SONAR_QUALITY_GATE_TIMEOUT` | Project, optional | No | Seconds to wait for the server gate; defaults to `300` |
| `SONAR_ENABLE_SUPPORT_BRANCH_ANALYSIS` | Project, optional | No | Defaults to `true`; set to `false` for develop-only projects |

`SONAR_TOKEN` must never be committed or interpolated into an echoed command.
For internal feature-branch MR analysis it must be available to trusted
same-project MR pipelines. Do not expose it to forks; the shared rule prevents
that. Use protected runners and restrict who can modify CI configuration. If
GitLab protected-variable policy prevents trusted MR pipelines from receiving
the token, configure the variable according to the GitLab protected-MR policy
for the group rather than weakening fork protections.

### Server Prerequisites

The CI template intentionally does not create or modify SonarQube projects,
quality profiles, or quality gates. A SonarQube administrator must:

1. Bind each existing SonarQube project to its GitLab project in Administration
  > Configuration > DevOps Platform Integrations so Developer Edition can
  decorate merge requests.
2. Assign a quality gate that evaluates **Overall Code**, not only New Code.
  In installations using classic severities, set `Blocker Issues > 0` and
  `Critical Issues > 0`. In installations using the Multi-Quality Rule mode,
  use the corresponding `Blocker` and `High` overall-issue metrics displayed
  by that server. Do not add coverage, duplication, or debt conditions unless
  they are already approved policy.
3. Associate that gate with all five existing project keys and verify that the
  assigned quality profiles are the existing language-specific profiles.
4. Configure GitLab status reporting and MR decoration with a SonarQube
  service-account token that has the minimum GitLab API permission required by
  the server integration.

This gate policy keeps all findings visible while failing CI for existing
serious findings. The exact metric names must be confirmed against the running
SonarQube server version before changing its gate.

## CI/CD Governance

### Required Approvals for Template Changes

1. Template changes require merge request approval
2. Breaking changes must bump major version
3. Security updates follow expedited process

### Release Preflight

- Shared Maven release jobs call `.maven-release-plugin-preflight` before the release script runs.
- Set `RELEASE_IMAGE_NAMES` in each project release job to the container image names that the release publishes.
- You can trigger a release pipeline from any branch.
- For a develop release, set `RELEASE_VERSION` and `SNAPSHOT_VERSION` (release runs from `develop`).
- Develop releases require an odd major version by default. Projects with a single develop release process can set `RELEASE_DEVELOP_ODD_MAJOR_ONLY: "false"` to allow both even and odd major versions.
- For a support release, set `SUP_RELEASE_VERSION` and `SUP_SNAPSHOT_VERSION`; release runs from `support-<major>.x` where `<major>` is parsed from `SUP_RELEASE_VERSION`.
- You can run develop and support releases in one pipeline by setting all 4 variables:
  - `RELEASE_VERSION`
  - `SNAPSHOT_VERSION`
  - `SUP_RELEASE_VERSION`
  - `SUP_SNAPSHOT_VERSION`
  In this mode, both release jobs run and each emits `CHECK PASS:` log lines for verification.
- After a successful release, shared logic updates `release-<RELEASE_VERSION>` and:
- `master` from `develop` HEAD for develop releases.
- `master-<SUP_RELEASE_VERSION>` from `support-<major>.x` HEAD for support releases.
- `master` updates are fast-forward only; if `master` diverged, the release job fails and requires a manual merge request.
- Rollback with `MAVEN_RELEASE_ROLLBACK=true` performs cleanup by mode:
- Develop rollback (`RELEASE_VERSION` + `SNAPSHOT_VERSION`): creates rollback revert commit(s) on `develop`/snapshot branch (and on `master` when the release commit is present), deletes `release-<RELEASE_VERSION>`, deletes git/container/package release tag `RELEASE_VERSION`, and deletes package snapshot `SNAPSHOT_VERSION` (if found).
- Support rollback (`SUP_RELEASE_VERSION` + `SUP_SNAPSHOT_VERSION`): creates rollback revert commit(s) on the support snapshot branch when release commits are present, deletes `release-<SUP_RELEASE_VERSION>`, deletes git/container/package release tag `SUP_RELEASE_VERSION`, and deletes package snapshot `SUP_SNAPSHOT_VERSION` (if found). For a minor step (release major == source major), the long-lived `master-<major>` is reverted like develop's `master`; for a major step it is deleted along with the generated `support-<major>.x` snapshot branch.
- The release job fails if the tag, Maven package, and all container image tags already exist, because that means the release is already complete.
- Projects can add `Notify Slack (Release success)` by extending `.slack-release-success-notify` with `needs: [Release with Maven Release Plugin]`.
- This notification is sent only when the release job succeeds.

### Template Testing

Templates are tested against real project configurations in the test pipeline.

## Migration Guide

### From Local CI to Shared Templates

1. Create feature branch in your project
2. Add `include:` statements for templates
3. Remove duplicated job definitions
4. Keep project-specific customizations
5. Test in merge request
6. Merge after validation

See `examples/` directory for migration examples for each project.