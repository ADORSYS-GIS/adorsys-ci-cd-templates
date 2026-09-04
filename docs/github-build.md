# GitHub Reusable Build Workflows

Add a caller workflow in `.github/workflows/build.yml`. Pin `@main` to a release
tag or commit SHA when available.

```yaml
name: Build

on:
  pull_request:
    branches: [develop, main]

jobs:
  build:
    uses: ADORSYS-GIS/adorsys-ci-cd-templates/.github/workflows/build-java.yml@main
    with:
      runner: ubuntu-latest
      working-directory: "."
      java-version: "21"
      java-distribution: temurin
      build-command: "mvn -B -ntp -DskipTests package"
```

Every workflow requires `runner`, `working-directory`, and `build-command`.

| Workflow | Additional required inputs |
|---|---|
| `build-java.yml` | `java-version`, `java-distribution` |
| `build-angular.yml`, `build-javascript-typescript.yml` | `node-version` |
| `build-rust.yml` | `rust-version` |
| `build-go.yml` | `go-version` |
| `build-python.yml` | `python-version` |
| `build-terraform.yml` | `terraform-version` |
| `build-powershell.yml`, `build-shell.yml`, `build-yaml.yml` | None |