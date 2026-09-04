# GitHub Reusable Lint Workflows

Add a caller workflow in `.github/workflows/lint.yml`. Pin `@main` to a release
tag or commit SHA when available.

```yaml
name: Lint

on:
  pull_request:
    branches: [develop, main]

jobs:
  lint:
    uses: ADORSYS-GIS/adorsys-ci-cd-templates/.github/workflows/lint-python.yml@main
    with:
      python-version: "3.12"
      working-directory: "."
```

## Required Version Inputs

| Workflow | Required input | Example |
|---|---|---|
| `lint-java.yml` | `java-version` | `"21"` |
| `lint-angular.yml` | `node-version` | `"22"` |
| `lint-javascript-typescript.yml` | `node-version` | `"22"` |
| `lint-rust.yml` | `rust-version` | `"1.88.0"` |
| `lint-go.yml` | `go-version` | `"1.24.6"` |
| `lint-python.yml` | `python-version` | `"3.12"` |
| `lint-terraform.yml` | `terraform-version` | `"1.12.2"` |

`lint-shell.yml`, `lint-powershell.yml`, and `lint-yaml.yml` do not need a
language-version input. All workflows accept an optional `working-directory` or
`path` input as appropriate.