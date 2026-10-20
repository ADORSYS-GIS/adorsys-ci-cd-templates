# SBOM Scans

A Software Bill of Materials (SBOM) is a machine-readable inventory of the
components that make up a deliverable. This set of templates generates a
CycloneDX SBOM from the repository contents (or from a container image) so it
can be published, audited, or compared against the GitHub Dependency Graph
baseline.

GitHub generates its own SPDX SBOM from the dependency graph when the feature
is enabled, but only for the ecosystems it understands and only from committed
manifests. The generated SBOM below is the source of truth: it scans the actual
repository contents, covers ecosystems the dependency graph does not parse
(Helm, container images, shell), and can be attached to releases or gated in CI.

## GitLab

Java / Maven projects include the existing CycloneDX job:

```yaml
include:
  - project: "${ADORSYS_CI_TEMPLATES_PROJECT}"
    ref: "${ADORSYS_CI_TEMPLATES_REF}"
    file:
      - "ci/gitlab/jobs/security/cyclonedx-owasp.yml"
```

This requires the `JAVA_MAVEN_IMAGE` variable and produces `target/bom.json` in
CycloneDX format using the CycloneDX Maven plugin, alongside the OWASP
Dependency-Check gate.

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
