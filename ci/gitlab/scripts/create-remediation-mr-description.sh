#!/bin/bash
# MR description builder and MR creation for create-remediation-mr.sh.
# Sourced by create-remediation-mr.sh — do not run directly.
# Uses script-level variables set by the caller: CVE_COUNT, CRITICAL_COUNT,
# HIGH_COUNT, ACTIONABLE_COUNT, NO_FIX_COUNT, NOT_AFFECTED_COUNT, FIXES_APPLIED,
# REMEDIATION_FILE, FINDINGS_FILE, BRANCH_NAME, TARGET_BRANCH, GITLAB_HOST,
# GITLAB_API, GITLAB_TOKEN, CI_PROJECT_ID, CI_PIPELINE_ID, CI_PROJECT_URL,
# CI_PROJECT_PATH.

build_and_submit_mr() {
# Generate MR description
FIXES_NOTE=$([[ "$FIXES_APPLIED" == "true" ]] && echo "This MR includes **automated version updates**. Please review before merging." || echo "No automated fixes could be applied. **Manual remediation required**.")

# ── Counts from remediation-plan.json (has per-status breakdown) ────────────
ACTIONABLE_COUNT=0; NO_FIX_COUNT=0; NOT_AFFECTED_COUNT=0
if [[ -n "$REMEDIATION_FILE" && -f "$REMEDIATION_FILE" ]]; then
    ACTIONABLE_COUNT=$(jq '[.remediations[] | select(.status == "actionable")] | length' "$REMEDIATION_FILE" 2>/dev/null || echo "0")
    NO_FIX_COUNT=$(jq '.no_fix_count // 0' "$REMEDIATION_FILE" 2>/dev/null || echo "0")
    NOT_AFFECTED_COUNT=$(jq '.not_affected_count // 0' "$REMEDIATION_FILE" 2>/dev/null || echo "0")
fi

MR_DESCRIPTION="## Security Updates\n\n"
MR_DESCRIPTION+="| | Count |\n|---|---|\n"
MR_DESCRIPTION+="| Total CVEs detected | **${CVE_COUNT}** |\n"
MR_DESCRIPTION+="| Critical | ${CRITICAL_COUNT} |\n"
MR_DESCRIPTION+="| High | ${HIGH_COUNT} |\n"
MR_DESCRIPTION+="| **Fixes applied** | **${ACTIONABLE_COUNT}** |\n"
MR_DESCRIPTION+="| No fix available in Maven Central | ${NO_FIX_COUNT} |\n"
MR_DESCRIPTION+="| Not affected per NVD | ${NOT_AFFECTED_COUNT} |\n\n"
MR_DESCRIPTION+="${FIXES_NOTE}\n\n"

# ── Section 1: Applied fixes ─────────────────────────────────────────────────
if [[ -n "$REMEDIATION_FILE" && -f "$REMEDIATION_FILE" ]]; then
    ACTIONABLE_ROWS=$(jq -r '
        .remediations[]
        | select(.status == "actionable")
        | (if .is_transitive == true then "🔄" else "" end) as $badge
        | (if .parent_dependency != null and .parent_dependency != "" then "via \(.parent_dependency)" else "" end) as $parent
        | (if .fix_guidance != null and .fix_guidance != "" then "\n  💡 \(.fix_guidance)" else "" end) as $guidance
        | "| \($badge) \(.package) | \(.current_version // "—") | **\(.fixed_version)** | \(.risk_level) | \(.cve_ids | join(", ")) | \($parent)\($guidance) |"
    ' "$REMEDIATION_FILE" 2>/dev/null || true)

    if [[ -n "$ACTIONABLE_ROWS" ]]; then
        MR_DESCRIPTION+="### ✅ Fixes Applied\n\n"
        MR_DESCRIPTION+="| Package | Installed | Fix Version | Risk | CVEs | Note |\n"
        MR_DESCRIPTION+="|---|---|---|---|---|---|\n"
        MR_DESCRIPTION+="${ACTIONABLE_ROWS}\n\n"
        # Transitive dependency explanation
        HAS_TRANSITIVE=$(jq '[.remediations[] | select(.status == "actionable" and .is_transitive == true)] | length' "$REMEDIATION_FILE" 2>/dev/null || echo "0")
        if [[ "$HAS_TRANSITIVE" -gt 0 ]]; then
            MR_DESCRIPTION+="> 🔄 = **Transitive dependency** — not declared directly in your pom.xml. Applied via `<dependencyManagement>` version pin. Review the parent dependency for a version that includes the patched transitive.\n\n"
        fi
    fi

    # ── Section 2: No fix available ──────────────────────────────────────────
    NO_FIX_ROWS=$(jq -r '
        .remediations[]
        | select(.status == "no-fix")
        | (if .is_transitive == true then "🔄" else "" end) as $badge
        | (if .parent_dependency != null and .parent_dependency != "" then "via \(.parent_dependency)" else "" end) as $parent
        | (if .fix_guidance != null and .fix_guidance != "" then "\n  💡 \(.fix_guidance)" else "" end) as $guidance
        | "| \($badge) \(.package) | \(.current_version // "—") | \(.cve_ids | join(", ")) | \($parent)\($guidance) |"
    ' "$REMEDIATION_FILE" 2>/dev/null || true)

    if [[ -n "$NO_FIX_ROWS" ]]; then
        MR_DESCRIPTION+="### ⚠️ No Fix Available\n\n"
        MR_DESCRIPTION+="These CVEs were detected but Maven Central has no newer release that satisfies the NVD fix boundary. Manual remediation required.\n\n"
        MR_DESCRIPTION+="| Package | Installed | CVEs | Note |\n"
        MR_DESCRIPTION+="|---|---|---|---|\n"
        MR_DESCRIPTION+="${NO_FIX_ROWS}\n\n"
    fi

    # ── Section 3: Not affected ───────────────────────────────────────────────
    NOT_AFFECTED_ROWS=$(jq -r '
        .remediations[]
        | select(.status == "not-affected")
        | (if .is_transitive == true then "🔄" else "" end) as $badge
        | "| \($badge) \(.package) | \(.current_version // "—") | \(.cve_ids | join(", ")) |"
    ' "$REMEDIATION_FILE" 2>/dev/null || true)

    if [[ -n "$NOT_AFFECTED_ROWS" ]]; then
        MR_DESCRIPTION+="### ℹ️ Not Affected (NVD)\n\n"
        MR_DESCRIPTION+="NVD confirms the installed version is outside the vulnerable range for these CVEs. No action required.\n\n"
        MR_DESCRIPTION+="| Package | Installed | CVEs |\n"
        MR_DESCRIPTION+="|---|---|---|\n"
        MR_DESCRIPTION+="${NOT_AFFECTED_ROWS}\n\n"
    fi
fi

# ── All detected vulnerabilities ──────────────────────────────────────────────
if [[ -n "$FINDINGS_FILE" && -f "$FINDINGS_FILE" ]]; then
    FINDINGS_ROWS=$(jq -r '
        .findings[]
        | (if .is_transitive == true then "🔄" else "" end) as $badge
        | (if .parent_dependency != null and .parent_dependency != "" then .parent_dependency else "—" end) as $parent
        | "| \($badge) \(.package) | \(.installed_version // "—") | \(.severity) | \(.cve_id) | \(.fixed_version // "—") | \(.source) | \($parent) |"
    ' "$FINDINGS_FILE" 2>/dev/null || true)

    if [[ -n "$FINDINGS_ROWS" ]]; then
        MR_DESCRIPTION+="### All Detected Vulnerabilities\n\n"
        MR_DESCRIPTION+="| Package | Installed | Severity | CVE | Fix Version | Source | Parent Dep |\n"
        MR_DESCRIPTION+="|---|---|---|---|---|---|---|\n"
        MR_DESCRIPTION+="${FINDINGS_ROWS}\n\n"
        HAS_TRANSITIVE_FINDINGS=$(jq '[.findings[] | select(.is_transitive == true)] | length' "$FINDINGS_FILE" 2>/dev/null || echo "0")
        if [[ "$HAS_TRANSITIVE_FINDINGS" -gt 0 ]]; then
            MR_DESCRIPTION+="> 🔄 = Transitive dependency. Check the \"Parent Dep\" column to see which direct dependency brings it in.\n\n"
        fi
    fi
fi

# ── Artifact links ────────────────────────────────────────────────────────────
PIPELINE_URL="${CI_PROJECT_URL}/-/pipelines/${CI_PIPELINE_ID}"
# Compute GitLab Pages artifact base URL:
#   https://git.example.com/group/subgroup/foo  ->  https://group.pages.example.com/-/subgroup/foo/-/jobs
_DOMAIN="${GITLAB_HOST#*.}"
_NS=$(echo "$CI_PROJECT_PATH" | cut -d'/' -f1)
_SUBPATH=$(echo "$CI_PROJECT_PATH" | cut -d'/' -f2-)
PAGES_JOBS_BASE="https://${_NS}.pages.${_DOMAIN}/-/${_SUBPATH}/-/jobs"

# Resolve job-specific artifact links via GitLab API
OWASP_JOB_ID=""
TRIVY_FS_JOB_ID="" TRIVY_FS_JOB_NAME=""
TRIVY_DF_JOB_ID="" TRIVY_DF_JOB_NAME=""
CYCLONEDX_JOB_ID=""
if [[ -n "$CI_PROJECT_ID" && -n "$CI_PIPELINE_ID" && -n "$GITLAB_TOKEN" ]]; then
    JOBS_JSON=$(curl -s --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
        "${GITLAB_API}/projects/${CI_PROJECT_ID}/pipelines/${CI_PIPELINE_ID}/jobs?per_page=100" 2>/dev/null || echo "[]")
    _B=$(echo "$TARGET_BRANCH" | tr '[:upper:]' '[:lower:]')
    OWASP_JOB_ID=$(echo "$JOBS_JSON" | jq -r --arg b "$_B" '
        (([.[] | select(.name | test("owasp.*scheduled|scheduled.*owasp"; "i"))
                | select(.name | ascii_downcase | contains($b))] | .[0])
         // ([.[] | select(.name | test("owasp.*scheduled|scheduled.*owasp"; "i"))] | .[0])
         // ([.[] | select(.name | test("owasp|dep-check|dependency-check"; "i"))] | .[0])
        ).id // empty' 2>/dev/null || true)
    TRIVY_FS_JOB_ID=$(echo "$JOBS_JSON" | jq -r --arg b "$_B" '
        (([.[] | select(.name | test("trivy.*fs.*scheduled|trivy-fs-scheduled"; "i"))
                | select(.name | ascii_downcase | contains($b))] | .[0])
         // ([.[] | select(.name | test("trivy.*fs.*scheduled|trivy-fs-scheduled"; "i"))] | .[0])
         // ([.[] | select(.name | test("trivy.*fs|trivy.*filesystem"; "i"))] | .[0])
        ).id // empty' 2>/dev/null || true)
    TRIVY_FS_JOB_NAME=$(echo "$JOBS_JSON" | jq -r --arg b "$_B" '
        (([.[] | select(.name | test("trivy.*fs.*scheduled|trivy-fs-scheduled"; "i"))
                | select(.name | ascii_downcase | contains($b))] | .[0])
         // ([.[] | select(.name | test("trivy.*fs.*scheduled|trivy-fs-scheduled"; "i"))] | .[0])
         // ([.[] | select(.name | test("trivy.*fs|trivy.*filesystem"; "i"))] | .[0])
        ).name // empty' 2>/dev/null || true)
    TRIVY_DF_JOB_ID=$(echo "$JOBS_JSON" | jq -r --arg b "$_B" '
        (([.[] | select(.name | test("trivy.*dockerfile.*scheduled|trivy-dockerfile-scheduled"; "i"))
                | select(.name | ascii_downcase | contains($b))] | .[0])
         // ([.[] | select(.name | test("trivy.*dockerfile.*scheduled|trivy-dockerfile-scheduled"; "i"))] | .[0])
         // ([.[] | select(.name | test("trivy.*dockerfile|trivy.*config|trivy.*docker"; "i"))] | .[0])
        ).id // empty' 2>/dev/null || true)
    TRIVY_DF_JOB_NAME=$(echo "$JOBS_JSON" | jq -r --arg b "$_B" '
        (([.[] | select(.name | test("trivy.*dockerfile.*scheduled|trivy-dockerfile-scheduled"; "i"))
                | select(.name | ascii_downcase | contains($b))] | .[0])
         // ([.[] | select(.name | test("trivy.*dockerfile.*scheduled|trivy-dockerfile-scheduled"; "i"))] | .[0])
         // ([.[] | select(.name | test("trivy.*dockerfile|trivy.*config|trivy.*docker"; "i"))] | .[0])
        ).name // empty' 2>/dev/null || true)
    CYCLONEDX_JOB_ID=$(echo "$JOBS_JSON" | jq -r --arg b "$_B" '
        (([.[] | select(.name | test("cyclonedx.*scheduled|scheduled.*cyclonedx"; "i"))
                | select(.name | ascii_downcase | contains($b))] | .[0])
         // ([.[] | select(.name | test("cyclonedx.*scheduled|scheduled.*cyclonedx"; "i"))] | .[0])
         // ([.[] | select(.name | test("cyclonedx|cyclone"; "i"))] | .[0])
        ).id // empty' 2>/dev/null || true)
fi

# Determine trivy artifact filenames from job names
_FS_FILE="trivy-fs-report.json"
_DF_FILE="trivy-dockerfile-report.json"
[[ "$TRIVY_FS_JOB_NAME" == *develop* ]] && _FS_FILE="trivy-fs-report-develop.json"
[[ "$TRIVY_FS_JOB_NAME" == *support* ]] && _FS_FILE="trivy-fs-report-support.json"
[[ "$TRIVY_DF_JOB_NAME" == *develop* ]] && _DF_FILE="trivy-dockerfile-report-develop.json"
[[ "$TRIVY_DF_JOB_NAME" == *support* ]] && _DF_FILE="trivy-dockerfile-report-support.json"

MR_DESCRIPTION+="### Scan Artifacts\n\n"
MR_DESCRIPTION+="Detailed scan reports are available as CI artifacts:\n\n"
MR_DESCRIPTION+="| Report | Link |\n"
MR_DESCRIPTION+="|---|---|\n"
if [[ -n "$OWASP_JOB_ID" ]]; then
    MR_DESCRIPTION+="| OWASP Dependency-Check (HTML) | [Download](${PAGES_JOBS_BASE}/${OWASP_JOB_ID}/artifacts/target/dependency-check-report.html) |\n"
    MR_DESCRIPTION+="| OWASP Dependency-Check (JSON) | [Download](${PAGES_JOBS_BASE}/${OWASP_JOB_ID}/artifacts/target/dependency-check-report.json) |\n"
fi
if [[ -n "$TRIVY_FS_JOB_ID" ]]; then
    MR_DESCRIPTION+="| Trivy Filesystem (JSON) | [Download](${PAGES_JOBS_BASE}/${TRIVY_FS_JOB_ID}/artifacts/${_FS_FILE}) |\n"
fi
if [[ -n "$TRIVY_DF_JOB_ID" ]]; then
    MR_DESCRIPTION+="| Trivy Dockerfile (JSON) | [Download](${PAGES_JOBS_BASE}/${TRIVY_DF_JOB_ID}/artifacts/${_DF_FILE}) |\n"
fi
if [[ -n "$CYCLONEDX_JOB_ID" ]]; then
    MR_DESCRIPTION+="| CycloneDX BOM (JSON) | [Download](${PAGES_JOBS_BASE}/${CYCLONEDX_JOB_ID}/artifacts/target/bom.json) |\n"
fi
MR_DESCRIPTION+="| Pipeline Overview | [View](${PIPELINE_URL}) |\n\n"

MR_DESCRIPTION+="---\n\n_Generated by Security Remediation Bot — sources: OWASP Dependency-Check, Trivy, CycloneDX. Fix resolution: NVD API v2.0 + Maven Central._"

MR_RESPONSE=$(curl -s --request POST --header "PRIVATE-TOKEN: $GITLAB_TOKEN" --header "Content-Type: application/json" \
    --data "$(jq -n --arg title "fix(deps): Security updates for ${CVE_COUNT} CVE(s) (${CRITICAL_COUNT} critical, ${HIGH_COUNT} high)" \
        --arg description "$(printf '%b' "$MR_DESCRIPTION")" --arg source_branch "$BRANCH_NAME" --arg target_branch "$TARGET_BRANCH" \
        '{title:$title,description:$description,source_branch:$source_branch,target_branch:$target_branch,labels:"dependencies,security,renovate",remove_source_branch:true,squash:true}')" \
    "${GITLAB_API}/projects/${CI_PROJECT_ID}/merge_requests")

MR_ID=$(echo "$MR_RESPONSE" | jq -r '.iid // empty')
MR_URL=$(echo "$MR_RESPONSE" | jq -r '.web_url // empty')
if [[ -n "$MR_ID" ]]; then
    echo "MR created: IID=$MR_ID URL=$MR_URL"
    echo "::set-output name=mr_iid::$MR_ID"
    echo "::set-output name=mr_url::$MR_URL"
else
    echo "Error: Failed to create MR"; echo "$MR_RESPONSE" | jq .; exit 1
fi
}
