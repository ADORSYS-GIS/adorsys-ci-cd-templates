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

## Open source

This repository is open source. Any team or company - inside or outside
adorsys - is free to use, adapt, and build on these templates for their own
projects.

## Documentation

- [SonarQube scan setup and usage](docs/sonarqube.md)
