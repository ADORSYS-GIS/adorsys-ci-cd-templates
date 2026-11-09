# SBOM Scans

A Software Bill of Materials (SBOM) is a machine-readable inventory of the
components that make up a deliverable. These templates provide CycloneDX
generation for resolved Maven dependencies and for Trivy filesystem or
container-image scans. The generated inputs differ by ecosystem and platform.

GitHub generates its own SPDX SBOM from the dependency graph when the feature
is enabled, but only for the ecosystems it understands and only from committed
manifests. The GitLab Maven job below describes the resolved Maven project
graph. The GitHub reusable workflow continues to use Trivy for filesystem and
container-image scans; it is not changed by the Maven job.

## GitLab

The `java-backend` and `java-multi-module` presets run a dedicated job named
`sbom`, independently from OWASP Dependency-Check. To add the SBOM template to
another Java/Maven pipeline:

```yaml
include:
  - project: "${ADORSYS_CI_TEMPLATES_PROJECT}"
    ref: "${ADORSYS_CI_TEMPLATES_REF}"
    file:
      - "ci/gitlab/jobs/security/sbom.yml"

sbom:
  extends: .maven-sbom
```

The presets' OWASP job remains separate and keeps its existing CVSS threshold,
soft-failure behavior, NVD cache, and unavailable-NVD fallback. The strict
Dependency-Check variants remain pipeline-blocking; neither scanner outcome
can convert an SBOM generation or validation failure into success.

The job has `needs: []`: when its rules include it, it can start as soon as a
runner is available, without waiting for earlier stages. It consumes no
upstream job artifacts and rebuilds its own Maven reactor, so Build, lint,
test, E2E, and OWASP jobs are not prerequisites.

The job requires `JAVA_MAVEN_IMAGE`, `ADORSYS_CI_TEMPLATES_PROJECT`, and
`ADORSYS_CI_TEMPLATES_REF`. Set the template ref to the same ref as the YAML
include. It downloads its helpers and schema via `CI_API_V4_URL`, using
`GITLAB_TOKEN` when configured or `CI_JOB_TOKEN` otherwise. The token must have
read access to the templates repository (including any cross-project job-token
allowlist required by your GitLab instance).

The job rebuilds the checked-out source and runs
the exact Maven goal
`org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom`. It writes
`target/sbom.json`, validates it against the vendored, checksum-pinned
CycloneDX 1.6 JSON schema, and preserves `target/bom.json` as a compatibility
copy for remediation consumers. Both files are uploaded in the artifact named
`sbom`; the artifact is retained for 30 days, including on job failure.

The official [aggregate goal documentation](https://cyclonedx.github.io/cyclonedx-maven-plugin/makeAggregateBom-mojo.html)
describes the aggregate reactor output. The pinned
[2.9.3 release documentation](https://github.com/CycloneDX/cyclonedx-maven-plugin/blob/cyclonedx-maven-plugin-2.9.3/README.md#cyclonedx-schema-support)
maps the exact released version to CycloneDX 1.6; 1.7 is not selected because
the stable release line documented here does not support it.
The goal includes compile, provided, runtime, and system scopes (including
transitives and dependency relationships), excludes test scope, and disables
per-module BOM files so a reactor produces one aggregate BOM. Single-module
projects receive the equivalent complete project BOM. The validator rejects
missing, empty, malformed, schema-invalid, unrelated, or relationship-free
output and confirms that every reactor module is represented.

The job rebuilds from the current checkout rather than reusing Build artifacts,
and does not share the OWASP NVD cache or fallback path. It uses
`MAVEN_SETTINGS_PATH` when set and normal Maven configuration such as
`.mvn/maven.config` (which applies the same Maven CLI profiles to both build
and BOM generation). Set `MAVEN_SETTINGS_PATH` at project/group scope when the
consuming build uses a non-default settings file; ensure any profiles used by
the consuming build are also activated through the shared Maven configuration.
Do not describe the BOM as a released binary's SBOM when the release uses a
different revision or dependency configuration. The BOM metadata records the
source branch and full commit SHA.

The standard preset rules run this job in non-scheduled pipelines. A schedule
with `SCHEDULE_TYPE=security-scan` also runs the job and scans the schedule's
branch, `develop`, and the latest even-numbered `support-N.x` branch (where
present). Each branch/revision is kept separately as
`target/sbom-<branch>.json` and `target/bom-<branch>.json`, with
`target/sbom-manifest.json` mapping each branch to its full commit. The
unqualified `target/sbom.json` and compatibility `target/bom.json` represent
the schedule's target branch. Each scheduled branch/revision uses an isolated
Maven local repository so reactor artifacts from one branch cannot satisfy
another branch's dependency resolution. Sanitized branch filenames support
the existing scheduled remediation path.

These are temporary CI artifacts, not durable release publications. The
templates do not currently publish SBOMs alongside Maven release packages or
associate them with a released package digest. Projects that require durable
release SBOMs must publish through their existing configurable release/package
mechanism, attaching the SBOM to the exact release version and recording the
source commit and artifact digest. Do not rely on the 30-day job artifact as
the sole release copy. The former `cyclonedx-owasp*.yml` templates remain
scanner-only compatibility aliases; include the dedicated `sbom.yml` for
generation.

## GitHub

Add a caller workflow in `.github/workflows/sast.yml`. Pin `@main` to a release
tag or commit SHA when available.

```yaml
jobs:
  sbom:
    uses: ADORSYS-GIS/adorsys-ci-cd-templates/.github/workflows/sbom.yml@main
    with:
      runner: ubuntu-latest
      working-directory: "."
    permissions:
      contents: read
```

The workflow checks out the repository, generates a CycloneDX SBOM with Trivy,
and uploads it as the `sbom` artifact.

| Input               | Required | Default | Purpose                                                                          |
| ------------------- | -------- | ------- | -------------------------------------------------------------------------------- |
| `runner`            | yes      | -       | Runner label, for example `ubuntu-latest`                                        |
| `working-directory` | yes      | -       | Repository-relative path to scan                                                 |
| `scan-type`         | no       | `fs`    | `fs`, `image`, or `all` (fs plus image)                                          |
| `image-ref`         | no       | empty   | Image reference, required when `scan-type` is `image` or `all`                   |
| `platforms`         | no       | empty   | Comma-separated platforms for image scans, for example `linux/amd64,linux/arm64` |
| `artifact-name`     | no       | `sbom`  | Base name of the uploaded artifact                                               |
| `retention-days`    | no       | `7`     | Days to keep the uploaded artifact                                               |

The workflow builds a scan matrix from these inputs. Every scan in the matrix
uploads a distinct artifact, so a single caller job covers any combination of
filesystem, image, and platform scans with no name collisions:

- Filesystem scan: `artifact-name`, for example `sbom`
- Image scan: `artifact-name-image`, for example `sbom-image`
- Image scan for one platform: `artifact-name-image-{platform}`, for example
  `sbom-image-linux-amd64`

For a container image, point `scan-type` at `image` and pass the image
reference:

```yaml
jobs:
  sbom-image:
    uses: ADORSYS-GIS/adorsys-ci-cd-templates/.github/workflows/sbom.yml@main
    with:
      runner: ubuntu-latest
      working-directory: "."
      scan-type: image
      image-ref: ghcr.io/adorsys-gis/my-image:latest
    permissions:
      contents: read
```

The image must be reachable from the runner. Most projects use the default
filesystem scan, which reads the committed lockfiles (`Cargo.lock`,
`package-lock.json`, `poetry.lock`, `.terraform.lock.hcl`) plus anything else
Trivy detects.

To produce the filesystem SBOM and the image SBOMs in one job, use
`scan-type: all` and pass one or more `platforms` when the image is built for
several architectures:

```yaml
jobs:
  sbom:
    uses: ADORSYS-GIS/adorsys-ci-cd-templates/.github/workflows/sbom.yml@main
    with:
      runner: ubuntu-latest
      working-directory: "."
      scan-type: all
      image-ref: ghcr.io/adorsys-gis/my-image:latest
      platforms: linux/amd64,linux/arm64
      artifact-name: sbom
      retention-days: 7
    permissions:
      contents: read
```

This uploads `sbom` (filesystem), `sbom-image-linux-amd64`, and
`sbom-image-linux-arm64` (image scans). Each platform scan runs
`trivy image --platform` so the SBOM reflects the packages of that
architecture.

For images that are shipped as multi-platform manifests, the recommended
source of the SBOM is the build itself: `docker/build-push-action` with
`provenance: true` and `sbom: true` attaches a per-platform SBOM attestation
to the image index. That is a single build step and requires no additional
workflow on the caller side. The workflow above is the CI-artifact path, used
when the SBOM must be downloadable from the workflow run, for example for
import into DefectDojo.
