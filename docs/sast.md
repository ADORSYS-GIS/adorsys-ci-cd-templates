# SAST Scans

Static Application Security Testing (SAST) reusable workflows / templates that scan
first-party code and publish results as **SARIF 2.1.0** artifacts. Both platforms are
covered; each scanner is **opt-in**, so existing pipelines are unaffected.

## GitLab

Include the SAST templates, then extend the alias for each language you scan:

```yaml
include:
  - project: "${ADORSYS_CI_TEMPLATES_PROJECT}"
    ref: "${ADORSYS_CI_TEMPLATES_REF}"
    file:
      - "ci/gitlab/jobs/security/sast-semgrep.yml"
      - "ci/gitlab/jobs/security/sast-bandit.yml"
      - "ci/gitlab/jobs/security/sast-gosec.yml"
      - "ci/gitlab/jobs/security/sast-shellcheck.yml"
      - "ci/gitlab/jobs/security/sast-psscriptanalyzer.yml"
      - "ci/gitlab/jobs/security/sast-checkov.yml"
```

| Language / technology                                           | Alias to extend          |
| --------------------------------------------------------------- | ------------------------ |
| Java, JavaScript/TypeScript, Rust (and other Semgrep languages) | `.sast-semgrep`          |
| Python                                                          | `.sast-bandit`           |
| Go                                                              | `.sast-gosec`            |
| Shell (`*.sh`, `*.bash`, `*.zsh`)                               | `.sast-shellcheck`       |
| PowerShell (`*.ps1`, `*.psm1`, `*.psd1`)                        | `.sast-psscriptanalyzer` |
| Terraform / Helm (IaC)                                          | `.sast-checkov`          |

Example:

```yaml
SAST (Python):
  extends: .sast-bandit

SAST (Go):
  extends: .sast-gosec
```

Each job runs in the `Security` stage and produces a SARIF artifact.

## GitHub

Add a caller workflow in `.github/workflows/sast.yml`. Pin `@main` to a release tag or
commit SHA when available.

```yaml
name: SAST

on:
  pull_request:
    branches: [develop, main]
  push:
    branches: [develop, main]

jobs:
  python:
    uses: ADORSYS-GIS/adorsys-ci-cd-templates/.github/workflows/sast-python.yml@main
    with:
      runner: ubuntu-latest
      working-directory: "."
      python-version: "3.12"
```

All GitHub SAST workflows accept `runner` and `working-directory` (repo-relative path).

| Workflow                         | Scanner                  | Additional required inputs |
| -------------------------------- | ------------------------ | -------------------------- |
| `sast-semgrep.yml`               | Semgrep (auto-detect)    | none                       |
| `sast-python.yml`                | Bandit                   | `python-version`           |
| `sast-go.yml`                    | Gosec                    | `go-version`               |
| `sast-java.yml`                  | Semgrep (Java)           | none                       |
| `sast-javascript-typescript.yml` | Semgrep (JS/TS)          | none                       |
| `sast-rust.yml`                  | Clippy + Semgrep         | `rust-version`             |
| `sast-shell.yml`                 | ShellCheck               | none                       |
| `sast-powershell.yml`            | PSScriptAnalyzer         | none                       |
| `sast-iac.yml`                   | Checkov (Terraform/Helm) | none                       |

Each GitHub workflow uploads its SARIF results to **GitHub code scanning** via
`github/codeql-action/upload-sarif`, so findings appear inline in the code and in the
**Security** tab. The workflows request `security-events: write` permission for this.
GitLab jobs publish the SARIF file as a build artifact.

## Gating

Scans run with `continue-on-error` on feature branches (GitHub) and `allow_failure`
advisory behavior on non-protected branches, so they do not block pull requests/merge
requests, and fail on protected branches (`develop`, `main`, `master`). Scans are
advisory for now; gating on severity is a follow-up.

## Optional deeper analysis

The reusable workflows favour scanners that run without per-project configuration. For
deeper analysis the following can be added at the project level:

- **Java (SpotBugs + FindSecBugs):** add `com.github.spotbugs:spotbugs-maven-plugin:4.10.4.1`
  with the `com.h3xstream.findsecbugs:findsecbugs-plugin:1.14.0` dependency and
  `sarifOutput=true`; run after `mvn compile`.
- **JavaScript/TypeScript (ESLint):** run `npx eslint . --format
@microsoft/eslint-formatter-sarif --output-file eslint-results.sarif` with
  `eslint-plugin-security`.
