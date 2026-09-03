#!/bin/bash
# Remediation: git operations and security report collection helpers.
# Sourced by remediation-common.sh — do not source this file directly.

validate_base_branch() {
    local target_branch="$1"
    local VALID_BASE_BRANCHES=("develop" "main" "master")
    local IS_VALID_BASE=false
    for valid_branch in "${VALID_BASE_BRANCHES[@]}"; do
        [[ "$target_branch" == "$valid_branch" ]] && IS_VALID_BASE=true && break
    done
    [[ "$target_branch" =~ ^support-[0-9]+\.(x|[0-9]+)$ ]] && IS_VALID_BASE=true
    if [[ "$IS_VALID_BASE" == "false" ]]; then
        echo "Error: '$target_branch' is not a valid base branch. Must be develop, main, master, or support-*.x"
        exit 1
    fi
}

collect_reports() {
    REPORTS_FOUND=0
    [ -f "target/dependency-check-report.json" ] && { echo "Found OWASP report"; REPORTS_FOUND=$((REPORTS_FOUND + 1)); } || echo "OWASP report not found"
    if [ -f "trivy-fs-report.json" ]; then echo "Found Trivy FS report"; REPORTS_FOUND=$((REPORTS_FOUND + 1))
    elif [ -f "trivy-fs-report-develop.json" ]; then echo "Found Trivy FS report (develop)"; cp trivy-fs-report-develop.json trivy-fs-report.json; REPORTS_FOUND=$((REPORTS_FOUND + 1))
    elif [ -f "trivy-fs-report-support.json" ]; then echo "Found Trivy FS report (support)"; cp trivy-fs-report-support.json trivy-fs-report.json; REPORTS_FOUND=$((REPORTS_FOUND + 1))
    else echo "Trivy FS report not found"; fi
    if [ -f "trivy-dockerfile-report.json" ]; then echo "Found Trivy Dockerfile report"; REPORTS_FOUND=$((REPORTS_FOUND + 1))
    elif [ -f "trivy-dockerfile-report-develop.json" ]; then echo "Found Trivy Dockerfile report (develop)"; cp trivy-dockerfile-report-develop.json trivy-dockerfile-report.json; REPORTS_FOUND=$((REPORTS_FOUND + 1))
    elif [ -f "trivy-dockerfile-report-support.json" ]; then echo "Found Trivy Dockerfile report (support)"; cp trivy-dockerfile-report-support.json trivy-dockerfile-report.json; REPORTS_FOUND=$((REPORTS_FOUND + 1))
    else echo "Trivy Dockerfile report not found"; fi
    [ -f "target/bom.json" ] && { echo "Found CycloneDX BOM"; REPORTS_FOUND=$((REPORTS_FOUND + 1)); } || echo "CycloneDX BOM not found"
    echo "Total reports found: $REPORTS_FOUND"
    [ "$REPORTS_FOUND" -eq 0 ] && { echo "No security reports found. Exiting."; exit 0; }
}

push_fixes_to_branch() {
    local BRANCH_NAME="$1" REMEDIATION_FILE="$2" GITLAB_HOST="$3" GITLAB_TOKEN="$4" CI_PROJECT_PATH="$5"
    [[ -z "$GITLAB_HOST" ]] && { echo "Error: GITLAB_HOST not set (define it as a project/group CI/CD variable)"; exit 1; }
    echo "Pushing fixes to branch: $BRANCH_NAME"

    # Check for local modifications before switching branches
    local CHANGED_POM CHANGED_DOCKER CHANGED_PKG LOCAL_CHANGED_FILES
    CHANGED_POM=$(git diff --name-only HEAD -- '*/pom.xml' 'pom.xml' 2>/dev/null || true)
    CHANGED_DOCKER=$(git diff --name-only HEAD -- '*/Dockerfile' 'Dockerfile' 2>/dev/null || true)
    CHANGED_PKG=$(git diff --name-only HEAD -- '*/package.json' 'package.json' '*/package-lock.json' 'package-lock.json' 2>/dev/null || true)
    LOCAL_CHANGED_FILES=""
    [[ -n "$CHANGED_POM" ]] && LOCAL_CHANGED_FILES="${LOCAL_CHANGED_FILES} ${CHANGED_POM}"
    [[ -n "$CHANGED_DOCKER" ]] && LOCAL_CHANGED_FILES="${LOCAL_CHANGED_FILES} ${CHANGED_DOCKER}"
    [[ -n "$CHANGED_PKG" ]] && LOCAL_CHANGED_FILES="${LOCAL_CHANGED_FILES} ${CHANGED_PKG}"
    LOCAL_CHANGED_FILES=$(echo "$LOCAL_CHANGED_FILES" | xargs 2>/dev/null || true)

    if [[ -z "$LOCAL_CHANGED_FILES" ]]; then
        echo "No local source code changes to push"
        return 1
    fi

    echo "Local file changes to push:"
    echo "$LOCAL_CHANGED_FILES"

    # Stash local changes before switching branches
    git stash push -m "security-remediation-fixes" -- '*/pom.xml' 'pom.xml' '*/Dockerfile' 'Dockerfile' '*/package.json' 'package.json' '*/package-lock.json' 'package-lock.json' 2>/dev/null || git stash push -m "security-remediation-fixes" 2>/dev/null || true

    # Switch to the target branch
    git fetch origin "$BRANCH_NAME" 2>/dev/null || true
    git checkout "$BRANCH_NAME" 2>/dev/null || git checkout -b "$BRANCH_NAME" "origin/$BRANCH_NAME" 2>/dev/null || {
        echo "Error: Could not checkout branch $BRANCH_NAME"
        git stash pop 2>/dev/null || true
        return 1
    }

    # Apply stashed changes
    git stash pop 2>/dev/null || {
        echo "Warning: Could not apply stashed changes cleanly — attempting manual merge"
        git stash pop --index 2>/dev/null || true
    }

    # Stage only dependency files (not artifact files)
    for pattern in '*/pom.xml' 'pom.xml' '*/Dockerfile' 'Dockerfile' '*/package.json' 'package.json' '*/package-lock.json' 'package-lock.json'; do
        git add "$pattern" 2>/dev/null || true
    done
    git reset HEAD -- 'security-reports/' '.fixes-applied' 'trivy-*.json' 'trivy-*.sarif' 'dependency-check-report.*' 'target/' 2>/dev/null || true

    local CHANGED_STAGED; CHANGED_STAGED=$(git diff --cached --name-only 2>/dev/null || true)
    [[ -z "$CHANGED_STAGED" ]] && { echo "No source code changes staged for commit after checkout."; return 1; }

    local CVE_LIST TOTAL_CVES REMAINDER
    CVE_LIST=$(jq -r '.remediations[].cve_ids[]' "$REMEDIATION_FILE" 2>/dev/null | sort -u | head -20 | tr '\n' ',' | sed 's/,$//')
    TOTAL_CVES=$(jq -r '.remediations[].cve_ids[]' "$REMEDIATION_FILE" 2>/dev/null | sort -u | wc -l)
    [[ "$TOTAL_CVES" -gt 20 ]] && REMAINDER=$((TOTAL_CVES - 20)) && CVE_LIST="${CVE_LIST}... and ${REMAINDER} more"

    if [[ -n "$CVE_LIST" ]]; then
        git commit -m "fix(deps): update vulnerable dependencies [${CVE_LIST}]"
    else
        git commit -m "fix(deps): update vulnerable dependencies"
    fi

    git push "https://oauth2:${GITLAB_TOKEN}@${GITLAB_HOST}/${CI_PROJECT_PATH}.git" "$BRANCH_NAME" 2>/dev/null || \
        git push origin "$BRANCH_NAME" 2>/dev/null || echo "Warning: Could not push changes"
    echo "Fixes pushed to branch $BRANCH_NAME"
    return 0
}
