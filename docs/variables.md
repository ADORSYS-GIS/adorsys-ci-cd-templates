# CI/CD Variables Setup

Variables required by the shared job templates in `ci/` and `cd/`. Set these
in GitLab under **Settings → CI/CD → Variables**, at the scope indicated.
Group scope means set once on the `adorsys/xs2a` group; Project scope means
each consuming project sets its own value.

| Variable | Definition | Scope |
|---|---|---|
| `GITLAB_API` | Base URL of the GitLab instance | Group |
| `ADORSYS_CI_TEMPLATES_PROJECT` | Path of this templates repo | Group |
| `ADORSYS_CI_TEMPLATES_REF` | Ref/tag to pull shared scripts from | Group |
| `GITLAB_TOKEN` | PAT (api + write_repository scope) for MRs, releases, rollback, and Renovate | Group |
| `GITLAB_USER_NAME` / `GITLAB_USER_EMAIL` | Bot git commit identity | Group |
| `GITLAB_PAGES_DOMAIN` | Pages domain for vuln-report links | Group |
| `NVD_API_KEY` | NVD API key for OWASP scans | Group |
| `RENOVATE_GITHUB_TOKEN` | Renovate bot GitHub PAT (public deps) | Group |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook | Group |
| `SONAR_HOST_URL` / `SONAR_TOKEN` | SonarQube server + auth token | Group |
| `SONAR_PROJECT_KEY` | SonarQube project key | Project |
| `DOCKER_REGISTRY` | Docker registry host (we only push to our own registry, no Docker Hub) | Group |
| `DOCKER_REGISTRY_USER` / `DOCKER_REGISTRY_PASSWORD` | Docker registry login | Group |
| `DOCKERHUB_NAMESPACE` | Docker image namespace | Project |
| `XS2A_VERSION` / `CONNECTOR_VERSION` / `LEDGERS_VERSION` | Versions resolved from pom.xml | Project |
| `GITHUB_DEPLOY_KEY_BASE64` / `GITHUB_TOKEN` | Auth for github-sync push | Project |
| `GITHUB_SSH_SERVER_FINGERPRINT` | github.com SSH host fingerprint | Group |
| `GITHUB_USERNAME` / `GITHUB_EMAIL` | Commit identity for github-sync | Group |

## GitHub Actions secrets (this repo's own mirror workflow)

Set in `ADORSYS-GIS/adorsys-ci-cd-templates` → **Settings → Secrets and variables → Actions**.

| Secret | Definition |
|---|---|
| `XS2A_GITLAB_SYNC_TOKEN` | GitLab PAT/project-token (write_repository) used to push the mirror |
| `XS2A_GITLAB_SYNC_URL` | Host + path of the GitLab mirror target (no scheme/credentials) |
