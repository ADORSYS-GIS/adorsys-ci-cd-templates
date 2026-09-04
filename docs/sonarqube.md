# SonarQube Scans

## Required Setup

| Platform | Configure |
|---|---|
| GitLab | Group variables: `SONAR_HOST_URL`, `SONAR_TOKEN` (masked); project variable: `SONAR_PROJECT_KEY` |
| GitHub | Repository secrets: `SONAR_HOST_URL`, `SONAR_TOKEN`; repository variable: `SONAR_PROJECT_KEY` |

The project key must already exist in SonarQube. Set `GIT_DEPTH: "0"` so the
scanner can identify branches and merge requests correctly.

## GitLab

Include the CLI and language templates, then extend the alias for the project language:

```yaml
include:
  - project: '${ADORSYS_CI_TEMPLATES_PROJECT}'
    ref: '${ADORSYS_CI_TEMPLATES_REF}'
    file:
      - 'ci/gitlab/jobs/security/sonarqube-cli.yml'
      - 'ci/gitlab/jobs/security/sonarqube-languages.yml'

SonarQube:
  extends: .sonarqube-python
```

| Language/files | Alias |
|---|---|
| Java (`.java`) | `.sonarqube-java` |
| Angular (`.ts`, `.html`, `.css`, `.scss`) | `.sonarqube-angular` |
| Rust (`.rs`) | `.sonarqube-rust` |
| Go (`.go`) | `.sonarqube-go` |
| JavaScript/TypeScript (`.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`) | `.sonarqube-javascript-typescript` |
| PowerShell (`.ps1`, `.psm1`, `.psd1`) | `.sonarqube-powershell` |
| Shell (`.sh`, `.bash`, `.zsh`) | `.sonarqube-shell` |
| Python (`.py`) | `.sonarqube-python` |
| YAML (`.yml`, `.yaml`) | `.sonarqube-yaml` |
| Terraform (`.tf`, `.tfvars`) | `.sonarqube-terraform` |

Java projects must also include `ci/gitlab/jobs/security/sonarqube.yml`.

Override defaults when required:

```yaml
SonarQube:
  extends: .sonarqube-javascript-typescript
  variables:
    SONAR_SOURCE_DIRS: "src"
    SONAR_JAVASCRIPT_LCOV_REPORT_PATHS: "coverage/lcov.info"
```

## GitHub

Add this caller workflow to `.github/workflows/sonarqube.yml`:

```yaml
name: SonarQube

on:
  pull_request:
    branches: [develop, main]
  push:
    branches: [develop]

permissions:
  contents: read

jobs:
  scan:
    uses: ADORSYS-GIS/adorsys-ci-cd-templates/.github/workflows/sonarqube.yml@main
    with:
      project-key: my-project
      exclusions: "**/node_modules/**,**/dist/**,**/build/**,**/coverage/**"
    secrets: inherit
```

Configure `SONAR_HOST_URL` and `SONAR_TOKEN` as repository secrets. The shared
workflow accepts optional `source-dirs` and `exclusions` inputs.