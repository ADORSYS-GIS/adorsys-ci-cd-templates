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

| Input               | Required | Default | Purpose                                                   |
| ------------------- | -------- | ------- | --------------------------------------------------------- |
| `runner`            | yes      | -       | Runner label, for example `ubuntu-latest`                 |
| `working-directory` | yes      | -       | Repository-relative path to scan                          |
| `scan-type`         | no       | `fs`    | `fs` for a filesystem scan, `image` for a container image |
| `image-ref`         | no       | empty   | Image reference, required when `scan-type` is `image`     |

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
Trivy detects. Projects that build container images get an additional SBOM for
the built image via the Docker BuildKit `sbom: true` option on the
`docker/build-push-action` step.
