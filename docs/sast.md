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
      - "ci/gitlab/jobs/security/sast-eslint.yml"
```

| Language / technology                                           | Alias to extend          |
| --------------------------------------------------------------- | ------------------------ |
| Java, JavaScript/TypeScript, Rust (and other Semgrep languages) | `.sast-semgrep`          |
| JavaScript/TypeScript (ESLint `eslint-plugin-security`)         | `.sast-eslint`           |
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

### Findings surfaced in GitLab + severity gate (Semgrep, ShellCheck, Checkov, ESLint)

The `.sast-semgrep`, `.sast-shellcheck`, `.sast-checkov`, and `.sast-eslint` jobs do
three extra things beyond emitting SARIF:

1. **Surface findings in GitLab.** Each converts its SARIF into a GitLab SAST
   report (`gl-sast-report.json`, via the shared `scripts/sast/sarif-to-gitlab.py`)
   and publishes it as `artifacts: reports: sast:`, so findings appear in the
   merge request Security widget and the project Vulnerability Report — not only
   inside the HTML/SARIF artifacts.
2. **Gate on severity.** The converter exits non-zero when any finding reaches a
   severity listed in `SAST_FAIL_SEVERITIES` (default `CRITICAL,HIGH`). Because
   these jobs are no longer `allow_failure: true`, that fails the pipeline. Set
   `SAST_FAIL_SEVERITIES: ""` on a job to make it report-only. Severity is taken
   from the SARIF `security-severity` (CVSS) when present, otherwise mapped from
   the SARIF level (`error`→High, `warning`→Medium, `note`→Low).
3. **Guard against silent no-ops.** A scanner that errors out (bad config, an
   unreachable rule registry, a crash) now fails the job instead of passing green
   with an empty result: the scanner's fatal exit codes are checked, and a
   missing/invalid SARIF makes the converter exit non-zero.

Each of these jobs ships the **same execution policy as every other security
scanner** (OWASP, Trivy, CycloneDX, Gitleaks): it **hard-fails** on protected
pushes and merge requests targeting a protected branch (and on `security-scan`
schedules), and **soft-fails** (`allow_failure: true`) on non-protected pushes and
merge requests — release/rollback runs and the duplicate push-with-open-MR
pipeline are skipped. This is built into the templates, so a consumer gets it
without overriding `rules`; projects may still override `rules:` with
`!reference [.pipeline-security-all, rules]` to stay aligned with their other
security jobs.

> Rollout note: enabling the gate on a repository with pre-existing HIGH/CRITICAL
> findings will block merge requests until they are triaged. To phase it in, start
> with `SAST_FAIL_SEVERITIES: "CRITICAL"` (or `""` for report-only) and tighten
> once a clean baseline is reached.

> ESLint note: `.sast-eslint` runs `eslint-plugin-security` over TS/JS in an
> isolated tool install (it never touches the project's own dependencies). Those
> rules are heuristic, so they are set to `warn` (→ Medium) and therefore
> **surface but do not block** under the default `CRITICAL,HIGH` gate. Add `MEDIUM`
> to `SAST_FAIL_SEVERITIES` to enforce them. It covers the security‑relevant TS/JS
> behind Angular templates; dedicated HTML template linting needs `angular-eslint`
> and is out of scope here.

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
