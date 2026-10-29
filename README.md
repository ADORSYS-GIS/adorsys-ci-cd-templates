# adorsys CI/CD Templates Repository

## What this is

This repository is a shared library of ready-made CI/CD building blocks -
linting, building, testing, security scanning, packaging, deploying,
releasing, and notifications - for both **GitLab CI** and **GitHub Actions**.
Instead of every project writing and maintaining its own pipeline logic from
scratch, projects simply reference these templates and get a consistent,
battle-tested pipeline in return.

## Why it's useful

- **Write once, use everywhere** - the same pipeline logic backs both GitLab
  CI and GitHub Actions, so teams aren't locked into duplicating work per
  platform.
- **Consistency at scale** - every project that adopts these templates gets
  the same quality bar for linting, security scanning, and release safety,
  instead of each team reinventing (and re-debugging) its own version.
- **Less maintenance per project** - fixes and improvements are made once,
  here, and every consuming project benefits the next time it pulls a new
  version, instead of patching the same job in a dozen repositories.
- **Faster onboarding** - new projects can stand up a solid CI/CD pipeline in
  minutes by including a preset, rather than building one from zero.

## Node.js runtime security

The GitLab Angular UI lint and npm audit templates use
`node:22.23.4-bookworm-slim`; the ESLint SAST template uses
`node:22.23.4-alpine`. These versions include the Brotli decoder fix for
[CVE-2026-111497](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases).
The npm audit template moves from end-of-life Node.js 20 to Node.js 22.
Consumers pinned to a template tag or commit must update their template
reference to a revision containing this fix.

## Container image security gate

The GitLab `.docker-build-scan-push` template builds all configured images,
scans their local image IDs with pinned Trivy 0.76.1, and pushes only after
every scan passes. It scans OS and application packages, blocks HIGH/CRITICAL
findings including those without a fix, and fails on scanner/database errors
or missing reports. Repository ignore files are not applied.

Set `DOCKER_BUILD_TARGETS` to whitespace-separated `image-name=build-context`
pairs, plus `DOCKER_TAG`, `DOCKERHUB_NAMESPACE` and the registry credentials
required by `.docker-build-push-base`. JSON scan reports and image IDs are
retained as CI artifacts for 30 days, including on failure. The template uses
the base's pinned Docker CLI/DinD pair; it does not use the legacy DinD variant.
Filesystem and Dockerfile configuration scans do not replace this image scan.
Existing build/push templates remain unchanged for other consumers.

Run the gate regression tests with
`python3 scripts/test-docker-image-gate.py`. Consumers must select a template
revision containing `.docker-build-scan-push` before using it.

## Open source

This repository is open source. Any team or company - inside or outside
adorsys - is free to use, adapt, and build on these templates for their own
projects.

## Documentation

- [GitHub reusable build workflows](docs/github-build.md)
- [GitHub reusable lint workflows](docs/github-lint.md)
- [Reusable SAST workflows (GitHub + GitLab)](docs/sast.md)
- [SBOM generation (GitHub + GitLab)](docs/sbom.md)
- [SonarQube scan setup and usage](docs/sonarqube.md)
