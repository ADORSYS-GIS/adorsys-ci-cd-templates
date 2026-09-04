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
```

    Every workflow requires `runner` and `working-directory`.

| Workflow | Additional required inputs | Template operation |
|---|---|---|
| `build-java.yml` | `java-version`, `java-distribution` | `mvn -B -ntp -DskipTests package` |
| `build-angular.yml`, `build-javascript-typescript.yml` | `node-version` | `npm ci && npm run build` |
| `build-rust.yml` | `rust-version` | `cargo build --locked` |
| `build-go.yml` | `go-version` | `go build ./...` |
| `build-python.yml` | `python-version` | `python -m compileall .` |
| `build-terraform.yml` | `terraform-version` | `terraform init -backend=false && terraform validate` |
| `build-powershell.yml` | None | PowerShell syntax validation |
| `build-shell.yml` | None | Shell syntax validation |
| `build-yaml.yml` | None | No build step; use `lint-yaml.yml` |