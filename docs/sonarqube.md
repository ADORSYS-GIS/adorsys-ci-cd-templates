# SonarQube Scans

## Required Setup

| Platform | Configure |
|---|---|
| GitLab | Group variables: `SONAR_HOST_URL`, `SONAR_TOKEN` (masked); project variable: `SONAR_PROJECT_KEY` |
| GitHub | Repository secrets: `SONAR_HOST_URL`, `SONAR_TOKEN`; repository variable: `SONAR_PROJECT_KEY` |

The project key must already exist in SonarQube. Set `GIT_DEPTH: "0"` so the
scanner can identify branches and merge requests correctly.

## GitLab

Include both templates, then extend the alias for the project language:

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
| Rust | `.sonarqube-rust` |
| Go | `.sonarqube-go` |
| JavaScript/TypeScript | `.sonarqube-javascript-typescript` |
| PowerShell | `.sonarqube-powershell` |
| Shell | `.sonarqube-shell` |
| Python | `.sonarqube-python` |
| YAML (`.yml`, `.yaml`) | `.sonarqube-yaml` |
| Terraform | `.sonarqube-terraform` |

Override defaults when required:

```yaml
SonarQube:
  extends: .sonarqube-javascript-typescript
  variables:
    SONAR_SOURCE_DIRS: "src"
    SONAR_JAVASCRIPT_LCOV_REPORT_PATHS: "coverage/lcov.info"
```

## GitHub

Add this job to `.github/workflows/sonarqube.yml` and use the same scanner for
any supported language:

```yaml
name: SonarQube

on:
  pull_request:
  push:
    branches: [develop]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: SonarSource/sonarqube-scan-action@v5
        env:
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        with:
          args: >
            -Dsonar.projectKey=${{ vars.SONAR_PROJECT_KEY }}
            -Dsonar.sources=.
```

Add optional scanner arguments to `args`, for example
`-Dsonar.exclusions=**/.terraform/**` or
`-Dsonar.javascript.lcov.reportPaths=coverage/lcov.info`.