#!/bin/bash
# Remediation: MR description building and MR augmentation helpers.
# Sourced by remediation-common.sh — do not source this file directly.

build_findings_table() {
    local FINDINGS_FILE="$1"
    [[ ! -f "$FINDINGS_FILE" ]] && return 0
    local FINDINGS_ROWS
    FINDINGS_ROWS=$(jq -r '
        .findings[]
        | (if .is_transitive == true then "🔄" else "" end) as $badge
        | (if .parent_dependency != null and .parent_dependency != "" then .parent_dependency else "—" end) as $parent
        | "| \($badge) \(.package) | \(.installed_version // "—") | \(.severity) | \(.cve_id) | \(.fixed_version // "—") | \(.source) | \($parent) |"
    ' "$FINDINGS_FILE" 2>/dev/null || true)
    if [[ -n "$FINDINGS_ROWS" ]]; then
        local HEADER="### All Detected Vulnerabilities\n\n"
        HEADER+="| Package | Installed | Severity | CVE | Fix Version | Source | Parent Dep |"
        HEADER+="\n|---|---|---|---|---|---|---|"
        echo -e "$HEADER"
        echo "$FINDINGS_ROWS"
        echo ""
        local HAS_TRANSITIVE_FINDINGS
        HAS_TRANSITIVE_FINDINGS=$(jq '[.findings[] | select(.is_transitive == true)] | length' "$FINDINGS_FILE" 2>/dev/null || echo "0")
        if [[ "$HAS_TRANSITIVE_FINDINGS" -gt 0 ]]; then
            echo "> 🔄 = Transitive dependency. Check the \"Parent Dep\" column to see which direct dependency brings it in."
            echo ""
        fi
    fi
}

build_remediation_sections() {
    local REMEDIATION_FILE="$1"
    [[ ! -f "$REMEDIATION_FILE" ]] && return 0
    local RESULT=""
    local ACTIONABLE_ROWS NO_FIX_ROWS NOT_AFFECTED_ROWS
    ACTIONABLE_ROWS=$(jq -r '.remediations[] | select(.status == "actionable") |
        (if .is_transitive == true then "🔄" else "" end) as $badge
        | (if .parent_dependency != null and .parent_dependency != "" then "via \(.parent_dependency)" else "" end) as $parent
        | (if .fix_guidance != null and .fix_guidance != "" then "\n  💡 \(.fix_guidance)" else "" end) as $guidance
        | "| \($badge) \(.package) | \(.current_version // "—") | **\(.fixed_version)** | \(.risk_level) | \(.cve_ids | join(", ")) | \($parent)\($guidance) |"
    ' "$REMEDIATION_FILE" 2>/dev/null || true)
    NO_FIX_ROWS=$(jq -r '.remediations[] | select(.status == "no-fix") |
        (if .is_transitive == true then "🔄" else "" end) as $badge
        | (if .parent_dependency != null and .parent_dependency != "" then "via \(.parent_dependency)" else "" end) as $parent
        | (if .fix_guidance != null and .fix_guidance != "" then "\n  💡 \(.fix_guidance)" else "" end) as $guidance
        | "| \($badge) \(.package) | \(.current_version // "—") | \(.cve_ids | join(", ")) | \($parent)\($guidance) |"
    ' "$REMEDIATION_FILE" 2>/dev/null || true)
    NOT_AFFECTED_ROWS=$(jq -r '.remediations[] | select(.status == "not-affected") |
        (if .is_transitive == true then "🔄" else "" end) as $badge
        | "| \($badge) \(.package) | \(.current_version // "—") | \(.cve_ids | join(", ")) |"
    ' "$REMEDIATION_FILE" 2>/dev/null || true)

    if [[ -n "$ACTIONABLE_ROWS" ]]; then
        RESULT+="### ✅ Fixes Applied\n\n"
        RESULT+="| Package | Installed | Fix Version | Risk | CVEs | Note |\n|---|---|---|---|---|---|\n"
        RESULT+="${ACTIONABLE_ROWS}\n\n"
        local HAS_TRANSITIVE
        HAS_TRANSITIVE=$(jq '[.remediations[] | select(.status == "actionable" and .is_transitive == true)] | length' "$REMEDIATION_FILE" 2>/dev/null || echo "0")
        if [[ "$HAS_TRANSITIVE" -gt 0 ]]; then
            RESULT+="> 🔄 = **Transitive dependency** — not declared directly in pom.xml. Applied via \`<dependencyManagement>\` version pin.\n\n"
        fi
    fi
    if [[ -n "$NO_FIX_ROWS" ]]; then
        RESULT+="### ⚠️ No Fix Available\n\n"
        RESULT+="Maven Central has no newer release satisfying the NVD fix boundary. Manual remediation required.\n\n"
        RESULT+="| Package | Installed | CVEs | Note |\n|---|---|---|---|\n"
        RESULT+="${NO_FIX_ROWS}\n\n"
    fi
    if [[ -n "$NOT_AFFECTED_ROWS" ]]; then
        RESULT+="### ℹ️ Not Affected (NVD)\n\n"
        RESULT+="Installed version is outside the NVD vulnerable range. No action required.\n\n"
        RESULT+="| Package | Installed | CVEs |\n|---|---|---|\n"
        RESULT+="${NOT_AFFECTED_ROWS}\n\n"
    fi
    echo "$RESULT"
}

augment_existing_mr() {
    local MR_IID="$1" API_URL="$2" TOKEN="$3" PROJECT_ID="$4" FIXES_APPLIED="$5"
    local FINDINGS_FILE="security-reports/unified-findings.json"
    local REMEDIATION_FILE="security-reports/remediation-plan.json"
    [[ -f "$FINDINGS_FILE" ]] || return 0

    local CVE_COUNT CRITICAL_COUNT HIGH_COUNT ACTIONABLE_COUNT NO_FIX_COUNT NOT_AFFECTED_COUNT
    CVE_COUNT=$(jq '.total_findings // 0' "$FINDINGS_FILE" 2>/dev/null || echo "0")
    CRITICAL_COUNT=$(jq '[.findings[] | select(.severity == "CRITICAL")] | length' "$FINDINGS_FILE" 2>/dev/null || echo "0")
    HIGH_COUNT=$(jq '[.findings[] | select(.severity == "HIGH")] | length' "$FINDINGS_FILE" 2>/dev/null || echo "0")
    ACTIONABLE_COUNT=0; NO_FIX_COUNT=0; NOT_AFFECTED_COUNT=0
    if [[ -f "$REMEDIATION_FILE" ]]; then
        ACTIONABLE_COUNT=$(jq '[.remediations[] | select(.status == "actionable")] | length' "$REMEDIATION_FILE" 2>/dev/null || echo "0")
        NO_FIX_COUNT=$(jq '.no_fix_count // 0' "$REMEDIATION_FILE" 2>/dev/null || echo "0")
        NOT_AFFECTED_COUNT=$(jq '.not_affected_count // 0' "$REMEDIATION_FILE" 2>/dev/null || echo "0")
    fi
    local FIXES_NOTE
    [[ "$FIXES_APPLIED" = "true" ]] && FIXES_NOTE="This MR includes **automated version updates**. Please review before merging." \
                                     || FIXES_NOTE="No automated fixes could be applied. **Manual remediation required**."

    local DESC="## Security Updates\n\n"
    DESC+="| | Count |\n|---|---|\n"
    DESC+="| Total CVEs detected | **${CVE_COUNT}** |\n"
    DESC+="| Critical | ${CRITICAL_COUNT} |\n"
    DESC+="| High | ${HIGH_COUNT} |\n"
    DESC+="| **Fixes applied** | **${ACTIONABLE_COUNT}** |\n"
    DESC+="| No fix available in Maven Central | ${NO_FIX_COUNT} |\n"
    DESC+="| Not affected per NVD | ${NOT_AFFECTED_COUNT} |\n\n"
    DESC+="${FIXES_NOTE}\n\n"

    if [[ -f "$REMEDIATION_FILE" ]]; then
        DESC+="$(build_remediation_sections "$REMEDIATION_FILE")"
    fi

    DESC+="$(build_findings_table "$FINDINGS_FILE")"

    local OWASP_JOB_ID="" TRIVY_FS_JOB_ID="" TRIVY_DF_JOB_ID="" CYCLONEDX_JOB_ID=""
    resolve_artifact_links "$API_URL" "$TOKEN" "$PROJECT_ID" "${CI_PIPELINE_ID:-}" "${SECURITY_BASE_BRANCH:-develop}"
    DESC+="### Scan Artifacts\n\n"
    DESC+="Detailed scan reports are available as CI artifacts:\n\n"
    DESC+="$(build_artifact_links "${CI_PROJECT_URL}" "$OWASP_JOB_ID" "$TRIVY_FS_JOB_ID" "$TRIVY_DF_JOB_ID" "$CYCLONEDX_JOB_ID" "${CI_PIPELINE_ID:-0}" "$TRIVY_FS_JOB_NAME" "$TRIVY_DF_JOB_NAME")\n\n"

    DESC+="---\n\n_Generated by Security Remediation Bot — sources: OWASP Dependency-Check, Trivy, CycloneDX. Fix resolution: NVD API v2.0 + Maven Central._"

    curl -s --request PUT --header "PRIVATE-TOKEN: $TOKEN" --header "Content-Type: application/json" \
        --data "$(jq -n --arg d "$(printf '%b' "$DESC")" '{description: $d}')" \
        "${API_URL}/projects/${PROJECT_ID}/merge_requests/${MR_IID}" > /dev/null
    echo "MR $MR_IID description augmented (${ACTIONABLE_COUNT} fixes, ${NO_FIX_COUNT} no-fix, ${NOT_AFFECTED_COUNT} not-affected)"
}
