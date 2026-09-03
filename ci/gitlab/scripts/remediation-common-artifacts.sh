#!/bin/bash
# Remediation: CI artifact link resolution helpers.
# Sourced by remediation-common.sh — do not source this file directly.

resolve_artifact_links() {
    local GITLAB_API="$1" TOKEN="$2" PROJECT_ID="$3" PIPELINE_ID="$4" BASE_BRANCH="${5:-develop}"
    OWASP_JOB_ID="" TRIVY_FS_JOB_ID="" TRIVY_DF_JOB_ID="" CYCLONEDX_JOB_ID=""
    TRIVY_FS_JOB_NAME="" TRIVY_DF_JOB_NAME=""
    [[ -z "$PROJECT_ID" || -z "$PIPELINE_ID" || -z "$TOKEN" ]] && return 0
    local JOBS_JSON
    JOBS_JSON=$(curl -s --header "PRIVATE-TOKEN: $TOKEN" \
        "${GITLAB_API}/projects/${PROJECT_ID}/pipelines/${PIPELINE_ID}/jobs?per_page=100" 2>/dev/null || echo "[]")
    # For each tool, prefer the scheduled job for the target branch, then any scheduled job,
    # then fall back to any matching job (gate / on-push variants).
    OWASP_JOB_ID=$(echo "$JOBS_JSON" | jq -r --arg b "$BASE_BRANCH" '
        (([.[] | select(.name | test("owasp.*scheduled|scheduled.*owasp"; "i"))
                | select(.name | ascii_downcase | contains($b))] | .[0])
         // ([.[] | select(.name | test("owasp.*scheduled|scheduled.*owasp"; "i"))] | .[0])
         // ([.[] | select(.name | test("owasp|dep-check|dependency-check"; "i"))] | .[0])
        ).id // empty' 2>/dev/null || true)
    TRIVY_FS_JOB_ID=$(echo "$JOBS_JSON" | jq -r --arg b "$BASE_BRANCH" '
        (([.[] | select(.name | test("trivy.*fs.*scheduled|trivy-fs-scheduled"; "i"))
                | select(.name | ascii_downcase | contains($b))] | .[0])
         // ([.[] | select(.name | test("trivy.*fs.*scheduled|trivy-fs-scheduled"; "i"))] | .[0])
         // ([.[] | select(.name | test("trivy.*fs|trivy.*filesystem"; "i"))] | .[0])
        ).id // empty' 2>/dev/null || true)
    TRIVY_FS_JOB_NAME=$(echo "$JOBS_JSON" | jq -r --arg b "$BASE_BRANCH" '
        (([.[] | select(.name | test("trivy.*fs.*scheduled|trivy-fs-scheduled"; "i"))
                | select(.name | ascii_downcase | contains($b))] | .[0])
         // ([.[] | select(.name | test("trivy.*fs.*scheduled|trivy-fs-scheduled"; "i"))] | .[0])
         // ([.[] | select(.name | test("trivy.*fs|trivy.*filesystem"; "i"))] | .[0])
        ).name // empty' 2>/dev/null || true)
    TRIVY_DF_JOB_ID=$(echo "$JOBS_JSON" | jq -r --arg b "$BASE_BRANCH" '
        (([.[] | select(.name | test("trivy.*dockerfile.*scheduled|trivy-dockerfile-scheduled"; "i"))
                | select(.name | ascii_downcase | contains($b))] | .[0])
         // ([.[] | select(.name | test("trivy.*dockerfile.*scheduled|trivy-dockerfile-scheduled"; "i"))] | .[0])
         // ([.[] | select(.name | test("trivy.*dockerfile|trivy.*config|trivy.*docker"; "i"))] | .[0])
        ).id // empty' 2>/dev/null || true)
    TRIVY_DF_JOB_NAME=$(echo "$JOBS_JSON" | jq -r --arg b "$BASE_BRANCH" '
        (([.[] | select(.name | test("trivy.*dockerfile.*scheduled|trivy-dockerfile-scheduled"; "i"))
                | select(.name | ascii_downcase | contains($b))] | .[0])
         // ([.[] | select(.name | test("trivy.*dockerfile.*scheduled|trivy-dockerfile-scheduled"; "i"))] | .[0])
         // ([.[] | select(.name | test("trivy.*dockerfile|trivy.*config|trivy.*docker"; "i"))] | .[0])
        ).name // empty' 2>/dev/null || true)
    CYCLONEDX_JOB_ID=$(echo "$JOBS_JSON" | jq -r --arg b "$BASE_BRANCH" '
        (([.[] | select(.name | test("cyclonedx.*scheduled|scheduled.*cyclonedx"; "i"))
                | select(.name | ascii_downcase | contains($b))] | .[0])
         // ([.[] | select(.name | test("cyclonedx.*scheduled|scheduled.*cyclonedx"; "i"))] | .[0])
         // ([.[] | select(.name | test("cyclonedx|cyclone"; "i"))] | .[0])
        ).id // empty' 2>/dev/null || true)
}

build_artifact_links() {
    local PROJECT_URL="$1" OWASP_JOB_ID="$2" TRIVY_FS_JOB_ID="$3" TRIVY_DF_JOB_ID="$4" CYCLONEDX_JOB_ID="$5" PIPELINE_ID="$6"
    local TRIVY_FS_JOB_NAME="${7:-}" TRIVY_DF_JOB_NAME="${8:-}"
    # Compute GitLab Pages artifact base URL:
    #   https://git.adorsys.de/adorsys/xs2a/foo  ->  https://adorsys.pages.adorsys.de/-/xs2a/foo/-/jobs
    local _HOST _DOMAIN _PROJ_PATH _NS _SUBPATH _PAGES_BASE
    _HOST=$(echo "$PROJECT_URL" | sed 's|https://||' | cut -d'/' -f1)
    _DOMAIN="${_HOST#*.}"
    _PROJ_PATH=$(echo "$PROJECT_URL" | sed "s|https://${_HOST}/||")
    _NS=$(echo "$_PROJ_PATH" | cut -d'/' -f1)
    _SUBPATH=$(echo "$_PROJ_PATH" | cut -d'/' -f2-)
    _PAGES_BASE="https://${_NS}.pages.${_DOMAIN}/-/${_SUBPATH}/-/jobs"
    # Determine trivy artifact filenames from job names (scheduled jobs use branch-suffixed names)
    local _FS_FILE="trivy-fs-report.json" _DF_FILE="trivy-dockerfile-report.json"
    [[ "$TRIVY_FS_JOB_NAME" == *develop* ]] && _FS_FILE="trivy-fs-report-develop.json"
    [[ "$TRIVY_FS_JOB_NAME" == *support* ]] && _FS_FILE="trivy-fs-report-support.json"
    [[ "$TRIVY_DF_JOB_NAME" == *develop* ]] && _DF_FILE="trivy-dockerfile-report-develop.json"
    [[ "$TRIVY_DF_JOB_NAME" == *support* ]] && _DF_FILE="trivy-dockerfile-report-support.json"
    local LINKS="| Report | Link |\n|---|---|\n"
    if [[ -n "$OWASP_JOB_ID" ]]; then
        LINKS+="| OWASP Dependency-Check (HTML) | [Download](${_PAGES_BASE}/${OWASP_JOB_ID}/artifacts/target/dependency-check-report.html) |\n"
        LINKS+="| OWASP Dependency-Check (JSON) | [Download](${_PAGES_BASE}/${OWASP_JOB_ID}/artifacts/target/dependency-check-report.json) |\n"
    fi
    if [[ -n "$TRIVY_FS_JOB_ID" ]]; then
        LINKS+="| Trivy Filesystem (JSON) | [Download](${_PAGES_BASE}/${TRIVY_FS_JOB_ID}/artifacts/${_FS_FILE}) |\n"
    fi
    if [[ -n "$TRIVY_DF_JOB_ID" ]]; then
        LINKS+="| Trivy Dockerfile (JSON) | [Download](${_PAGES_BASE}/${TRIVY_DF_JOB_ID}/artifacts/${_DF_FILE}) |\n"
    fi
    if [[ -n "$CYCLONEDX_JOB_ID" ]]; then
        LINKS+="| CycloneDX BOM (JSON) | [Download](${_PAGES_BASE}/${CYCLONEDX_JOB_ID}/artifacts/target/bom.json) |\n"
    fi
    LINKS+="| Pipeline Overview | [View](${PROJECT_URL}/-/pipelines/${PIPELINE_ID}) |\n"
    echo "$LINKS"
}
