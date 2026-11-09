#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA="${SCRIPT_DIR}/../schemas/cyclonedx-bom-1.6.schema.json"
VALIDATOR="${SCRIPT_DIR}/validate-maven-sbom.py"
STAGING_DIR=".sbom-artifacts"
MAVEN_PLUGIN="org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom"
MAVEN_SETTINGS_ARGS=()
SCHEMA_SHA256="18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d"

if [[ -n "${MAVEN_SETTINGS_PATH:-}" ]]; then
  [[ -f "$MAVEN_SETTINGS_PATH" ]] || {
    echo "ERROR: MAVEN_SETTINGS_PATH does not exist: $MAVEN_SETTINGS_PATH" >&2
    exit 1
  }
  MAVEN_SETTINGS_ARGS=(--settings "$MAVEN_SETTINGS_PATH")
fi

[[ -s "$SCHEMA" ]] || {
  echo "ERROR: CycloneDX 1.6 schema is missing or empty: $SCHEMA" >&2
  exit 1
}
printf '%s  %s\n' "$SCHEMA_SHA256" "$SCHEMA" | sha256sum --check --status || {
  echo "ERROR: CycloneDX 1.6 schema checksum mismatch." >&2
  exit 1
}

mkdir -p target "$STAGING_DIR"
rm -f "$STAGING_DIR"/*.json target/sbom.json target/bom.json \
  target/sbom-*.json target/bom-*.json target/sbom-manifest.json

TARGET_BRANCH="${CI_COMMIT_BRANCH:-$(git branch --show-current)}"
[[ -n "$TARGET_BRANCH" ]] || {
  echo "ERROR: Could not determine the source branch for this SBOM." >&2
  exit 1
}
TARGET_COMMIT="$(git rev-parse HEAD)"
TARGET_LABEL="${TARGET_BRANCH//\//-}"
TARGET_LABEL="$(printf '%s' "$TARGET_LABEL" | sed 's/[^A-Za-z0-9._-]/-/g')"
BRANCHES=("$TARGET_BRANCH")

if [[ "${CI_PIPELINE_SOURCE:-}" == "schedule" && "${SCHEDULE_TYPE:-}" == "security-scan" ]]; then
  if [[ "$TARGET_BRANCH" != "develop" ]]; then
    BRANCHES+=("develop")
  fi
  LATEST_SUPPORT="$(
    git ls-remote --heads origin 'support-*.x' \
      | sed -n 's#.*refs/heads/support-\([0-9][0-9]*\)\.x#\1#p' \
      | awk '$1 % 2 == 0' | sort -n | tail -1
  )"
  if [[ -n "$LATEST_SUPPORT" ]]; then
    SUPPORT_BRANCH="support-${LATEST_SUPPORT}.x"
    if [[ "$TARGET_BRANCH" != "$SUPPORT_BRANCH" && "$SUPPORT_BRANCH" != "develop" ]]; then
      BRANCHES+=("$SUPPORT_BRANCH")
    fi
  fi
fi

run_branch() {
  local branch="$1"
  local label="${branch//\//-}"
  label="$(printf '%s' "$label" | sed 's/[^A-Za-z0-9._-]/-/g')"
  local commit

  if [[ "$branch" == "$TARGET_BRANCH" ]]; then
    git checkout -f "$TARGET_COMMIT" || return 1
  else
    echo "=== Fetching SBOM source branch: $branch ==="
    git fetch origin "$branch" || return 1
    git checkout -f FETCH_HEAD || return 1
  fi
  commit="$(git rev-parse HEAD)" || return 1
  echo "=== Generating SBOM for $branch at $commit ==="
  local maven_repo="${MAVEN_REPO_PATH:-.m2/repository}"
  if [[ "${CI_PIPELINE_SOURCE:-}" == "schedule" && "${SCHEDULE_TYPE:-}" == "security-scan" ]]; then
    maven_repo="${PWD}/.sbom-m2/${label}-${commit}"
    mkdir -p "$maven_repo" || return 1
  fi

  rm -f target/sbom.json target/bom.json || return 1
  if ! mvn -B -ntp -nsu \
    "-Dmaven.repo.local=${maven_repo}" \
    "${MAVEN_SETTINGS_ARGS[@]}" \
    -DskipITs -DskipTests -Dci.build.number="Build:${CI_PIPELINE_ID:-local}" clean install; then
    echo "ERROR: Maven build failed for branch $branch ($commit)." >&2
    return 1
  fi

  if ! mvn -B -ntp -nsu \
    "-Dmaven.repo.local=${maven_repo}" \
    "${MAVEN_SETTINGS_ARGS[@]}" \
    -DschemaVersion=1.6 \
    -DoutputFormat=json \
    -DoutputName=sbom \
    -DoutputDirectory="${PWD}/target" \
    -DoutputReactorProjects=false \
    -DincludeCompileScope=true \
    -DincludeProvidedScope=true \
    -DincludeRuntimeScope=true \
    -DincludeSystemScope=true \
    -DincludeTestScope=false \
    "$MAVEN_PLUGIN"; then
    echo "ERROR: CycloneDX aggregate generation failed for branch $branch ($commit)." >&2
    return 1
  fi

  if ! python3 "$VALIDATOR" target/sbom.json "$SCHEMA" pom.xml "$branch" "$commit"; then
    echo "ERROR: CycloneDX output validation failed for branch $branch ($commit)." >&2
    return 1
  fi

  cp target/sbom.json "$STAGING_DIR/sbom-${label}.json" || return 1
  cp target/sbom.json "$STAGING_DIR/bom-${label}.json" || return 1
  if ! python3 - "$STAGING_DIR/manifest.json" "$branch" "$commit" "$label" <<'PY'
import json
import sys
from pathlib import Path

manifest = Path(sys.argv[1])
entries = json.loads(manifest.read_text()) if manifest.exists() else []
entries.append({"branch": sys.argv[2], "commit": sys.argv[3], "label": sys.argv[4]})
manifest.write_text(json.dumps(entries, indent=2) + "\n")
PY
  then
    echo "ERROR: Could not record SBOM source metadata for $branch ($commit)." >&2
    return 1
  fi
}

OVERALL_EXIT=0
for branch in "${BRANCHES[@]}"; do
  run_branch "$branch" || OVERALL_EXIT=1
done

git checkout -f "$TARGET_COMMIT" || OVERALL_EXIT=1
mkdir -p target
rm -f target/sbom.json target/bom.json target/sbom-manifest.json
for artifact in "$STAGING_DIR"/*.json; do
  [[ -f "$artifact" ]] || continue
  cp "$artifact" "target/$(basename "$artifact")"
done
if [[ -f "$STAGING_DIR/sbom-${TARGET_LABEL}.json" ]]; then
  cp "$STAGING_DIR/sbom-${TARGET_LABEL}.json" target/sbom.json
  cp "$STAGING_DIR/bom-${TARGET_LABEL}.json" target/bom.json
fi
if [[ -f "$STAGING_DIR/manifest.json" ]]; then
  cp "$STAGING_DIR/manifest.json" target/sbom-manifest.json
fi

exit "$OVERALL_EXIT"
