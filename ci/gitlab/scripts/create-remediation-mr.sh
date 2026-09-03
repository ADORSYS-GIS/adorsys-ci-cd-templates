#!/bin/bash
# Creates a merge request with security fixes aggregated from all security tools.
# Sources shared functions from remediation-common.sh.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/remediation-common.sh"
source "${SCRIPT_DIR}/create-remediation-mr-description.sh"

BRANCH_PREFIX="" TARGET_BRANCH="" FINDINGS_FILE="" REMEDIATION_FILE="" DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --branch-prefix) BRANCH_PREFIX="$2"; shift 2 ;;
        --target-branch) TARGET_BRANCH="$2"; shift 2 ;;
        --findings-file) FINDINGS_FILE="$2"; shift 2 ;;
        --remediation-file) REMEDIATION_FILE="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

[[ -z "$BRANCH_PREFIX" || -z "$TARGET_BRANCH" ]] && { echo "Error: --branch-prefix and --target-branch are required"; exit 1; }
validate_base_branch "$TARGET_BRANCH"

[[ -z "${GITLAB_HOST:-}" ]] && { echo "Error: GITLAB_HOST not set (define it as a project/group CI/CD variable)"; exit 1; }
GITLAB_API="https://${GITLAB_HOST}/api/v4"
[[ -z "$GITLAB_TOKEN" ]] && { echo "Error: GITLAB_TOKEN not set"; exit 1; }
[[ -z "$CI_PROJECT_ID" ]] && { echo "Error: CI_PROJECT_ID not set"; exit 1; }

DATE_SUFFIX=$(date +%d-%m-%y)
BRANCH_NAME="${BRANCH_PREFIX}-${TARGET_BRANCH}-${DATE_SUFFIX}"

CVE_COUNT=0; CRITICAL_COUNT=0; HIGH_COUNT=0; FIXABLE_COUNT=0
[[ -n "$FINDINGS_FILE" && -f "$FINDINGS_FILE" ]] && {
    CVE_COUNT=$(jq '.total_findings // 0' "$FINDINGS_FILE" 2>/dev/null || echo "0")
    CRITICAL_COUNT=$(jq '[.findings[] | select(.severity == "CRITICAL")] | length' "$FINDINGS_FILE" 2>/dev/null || echo "0")
    HIGH_COUNT=$(jq '[.findings[] | select(.severity == "HIGH")] | length' "$FINDINGS_FILE" 2>/dev/null || echo "0")
}
[[ -n "$REMEDIATION_FILE" && -f "$REMEDIATION_FILE" ]] && FIXABLE_COUNT=$(jq '.total_remediations // 0' "$REMEDIATION_FILE" 2>/dev/null || echo "0")

echo "Branch: $BRANCH_NAME | Target: $TARGET_BRANCH | CVEs: $CVE_COUNT | Fixable: $FIXABLE_COUNT"
[[ "$CVE_COUNT" -eq 0 ]] && { echo "No CVEs found. No MR needed."; exit 0; }
[[ "$DRY_RUN" == "true" ]] && { echo "[DRY RUN] Would create MR: fix(deps): Security updates for $CVE_COUNT CVE(s)"; exit 0; }

[[ -z "${GITLAB_USER_EMAIL:-}" ]] && { echo "Error: GITLAB_USER_EMAIL not set (define it as a project/group CI/CD variable)"; exit 1; }
git config --global user.email "$GITLAB_USER_EMAIL"
git config --global user.name "${GITLAB_USER_NAME:-Security Bot}"

# Detect locally modified files from the aggregator's --apply-fixes step
CHANGED_POM=$(git diff --name-only HEAD -- '*/pom.xml' 'pom.xml' 2>/dev/null || true)
CHANGED_DOCKER=$(git diff --name-only HEAD -- '*/Dockerfile' 'Dockerfile' 2>/dev/null || true)
CHANGED_PKG=$(git diff --name-only HEAD -- '*/package.json' 'package.json' '*/package-lock.json' 'package-lock.json' 2>/dev/null || true)
CHANGED_FILES=""
[[ -n "$CHANGED_POM" ]] && CHANGED_FILES="${CHANGED_FILES} ${CHANGED_POM}"
[[ -n "$CHANGED_DOCKER" ]] && CHANGED_FILES="${CHANGED_FILES} ${CHANGED_DOCKER}"
[[ -n "$CHANGED_PKG" ]] && CHANGED_FILES="${CHANGED_FILES} ${CHANGED_PKG}"
CHANGED_FILES=$(echo "$CHANGED_FILES" | xargs 2>/dev/null || true)

echo "Locally modified files detected by git diff:"
echo "  pom.xml files: ${CHANGED_POM:-none}"
echo "  Dockerfiles: ${CHANGED_DOCKER:-none}"
echo "  package.json: ${CHANGED_PKG:-none}"

# Check if branch already exists on remote
BRANCH_EXISTS=false
if git ls-remote --heads origin "$BRANCH_NAME" 2>/dev/null | grep -q "$BRANCH_NAME"; then
    BRANCH_EXISTS=true
    echo "Branch $BRANCH_NAME already exists on remote"
fi

# Also check for an existing MR with the security label and our prefix
EXISTING_MR_IID=""
EXISTING_MR_BRANCH=""
BRANCH_PREFIX_SEARCH="${BRANCH_PREFIX}-${TARGET_BRANCH}"
search_existing_mr "$BRANCH_PREFIX_SEARCH" "$BRANCH_NAME" "$TARGET_BRANCH" "$GITLAB_API" "$GITLAB_TOKEN" "$CI_PROJECT_ID"
if [[ -n "$EXISTING_MR" && "$EXISTING_BRANCH_NAME" == "$BRANCH_NAME" ]]; then
    echo "Found existing MR $EXISTING_MR on today's branch $EXISTING_BRANCH_NAME — will augment instead of creating new MR"
    if [[ -n "$CHANGED_FILES" ]]; then
        push_fixes_to_branch "$EXISTING_BRANCH_NAME" "$REMEDIATION_FILE" "$GITLAB_HOST" "$GITLAB_TOKEN" "$CI_PROJECT_PATH" || true
    else
        echo "No local file changes to push to existing MR"
    fi
    if [[ -f "security-reports/unified-findings.json" ]]; then
        local_fixes_applied=false
        [[ -n "$CHANGED_FILES" ]] && local_fixes_applied=true
        augment_existing_mr "$EXISTING_MR" "$GITLAB_API" "$GITLAB_TOKEN" "$CI_PROJECT_ID" "$local_fixes_applied"
    fi
    exit 0
elif [[ -n "$EXISTING_MR" ]]; then
    echo "Existing MR $EXISTING_MR is on a different branch ($EXISTING_BRANCH_NAME) — creating new MR for today's scan"
fi

FIXES_APPLIED=false

# Create branch and commit local changes
if [[ "$BRANCH_EXISTS" == "true" ]]; then
    echo "Reusing existing remote branch $BRANCH_NAME"
    git fetch origin "$BRANCH_NAME"
    # Stash local changes, checkout branch, then apply
    if [[ -n "$CHANGED_FILES" ]]; then
        git stash
        git checkout "$BRANCH_NAME"
        git stash pop || { echo "Warning: Could not apply stashed changes cleanly"; git stash drop 2>/dev/null || true; }
    else
        git checkout "$BRANCH_NAME"
    fi
else
    echo "Creating new local branch $BRANCH_NAME from current HEAD"
    git checkout -b "$BRANCH_NAME"
fi

# Stage and commit changed files
if [[ -z "$CHANGED_FILES" ]]; then
    echo "No local file changes detected — creating empty commit so branch can be pushed with findings report."
    git commit --allow-empty -m "chore(security): scan report $(date +%Y-%m-%d) — ${CVE_COUNT} CVE(s) found, manual review required"
elif [[ -n "$CHANGED_FILES" ]]; then
    echo "Staging modified files..."
    # Stage all modified dependency files
    for pattern in '*/pom.xml' 'pom.xml' '*/Dockerfile' 'Dockerfile' '*/package.json' 'package.json' '*/package-lock.json' 'package-lock.json'; do
        git add "$pattern" 2>/dev/null || true
    done
    # Unstage artifact and report files (these are not source code)
    git reset HEAD -- 'security-reports/' '.fixes-applied' 'trivy-*.json' 'trivy-*.sarif' 'dependency-check-report.*' 'target/' 2>/dev/null || true

    STAGED_FILES=$(git diff --cached --name-only 2>/dev/null || true)
    if [[ -n "$STAGED_FILES" ]]; then
        echo "Committing staged files:"
        echo "$STAGED_FILES"
        CVE_LIST=""
        TOTAL_CVES=0
        if [[ -n "$REMEDIATION_FILE" && -f "$REMEDIATION_FILE" ]]; then
            CVE_LIST=$(jq -r '.remediations[].cve_ids[]' "$REMEDIATION_FILE" 2>/dev/null | sort -u | head -20 | tr '\n' ',' | sed 's/,$//')
            TOTAL_CVES=$(jq -r '.remediations[].cve_ids[]' "$REMEDIATION_FILE" 2>/dev/null | sort -u | wc -l)
        fi
        if [[ "$TOTAL_CVES" -gt 20 ]]; then
            REMAINDER=$((TOTAL_CVES - 20))
            CVE_LIST="${CVE_LIST}... and ${REMAINDER} more"
        fi
        if [[ -n "$CVE_LIST" ]]; then
            git commit -m "fix(deps): update vulnerable dependencies [${CVE_LIST}]"
        else
            git commit -m "fix(deps): update vulnerable dependencies"
        fi
        FIXES_APPLIED=true
    else
        echo "No source code changes staged for commit after filtering."
    fi
fi

# Push the branch
echo "Pushing branch $BRANCH_NAME to remote..."
git push "https://oauth2:${GITLAB_TOKEN}@${GITLAB_HOST}/${CI_PROJECT_PATH}.git" "$BRANCH_NAME" 2>/dev/null || \
    git push origin "$BRANCH_NAME" 2>/dev/null || { echo "Warning: Could not push branch $BRANCH_NAME"; }

# Generate MR description and submit the MR
build_and_submit_mr