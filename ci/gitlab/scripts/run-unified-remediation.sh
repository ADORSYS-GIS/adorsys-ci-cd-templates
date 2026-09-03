#!/bin/bash
# Collect security reports, aggregate findings, and create/augment a remediation MR.
# Called by the unified-remediation CI job templates.
# Sources shared functions from remediation-common.sh.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/remediation-common.sh"

echo "=== Step 1: Collect Security Reports ==="
collect_reports

echo "=== Step 2: Aggregate Findings ==="
AGGREGATOR_ARGS="--project-dir $CI_PROJECT_DIR --output-dir security-reports --severity $SEVERITY_FILTER"
[ "$OFFLINE_MODE" = "true" ] && AGGREGATOR_ARGS="$AGGREGATOR_ARGS --offline"

mkdir -p security-reports

AGGREGATOR_EXIT_CODE=0
python3 /scripts/unified-security-aggregator.py $AGGREGATOR_ARGS --apply-fixes || {
    AGGREGATOR_EXIT_CODE=$?
    echo "WARNING: Aggregator exited with code $AGGREGATOR_EXIT_CODE — continuing with partial results"
}

if [ ! -f "security-reports/unified-findings.json" ]; then
    echo '{"total_findings": 0, "findings": [], "generated_at": "unknown"}' > security-reports/unified-findings.json
fi
if [ ! -f "security-reports/remediation-plan.json" ]; then
    echo '{"total_remediations": 0, "remediations": [], "generated_at": "unknown"}' > security-reports/remediation-plan.json
fi
if [ ! -f "security-reports/summary.json" ]; then
    echo '{"summary": {"total_cves": 0, "high_count": 0, "critical_count": 0, "actionable_count": 0, "unique_packages": 0}, "by_source": {}, "top_packages": []}' > security-reports/summary.json
fi

echo "=== Step 3: Generate Summary ==="
[ -f "security-reports/summary.json" ] && echo "Summary:" && jq . security-reports/summary.json

echo "=== Step 4: Report locally modified files ==="
# Clean up per-branch trivy report copies (they were already copied to canonical names)
rm -f trivy-dockerfile-report-develop.json trivy-dockerfile-report-support.json 2>/dev/null || true
rm -f trivy-fs-report-develop.json trivy-fs-report-support.json 2>/dev/null || true
rm -f trivy-fs-report-develop.sarif trivy-fs-report-support.sarif 2>/dev/null || true
rm -f trivy-fs-report.sarif 2>/dev/null || true
# Remove canonical trivy reports — they are CI artifacts, not source code
rm -f trivy-fs-report.json trivy-dockerfile-report.json 2>/dev/null || true
rm -f trivy-fs-report.json trivy-dockerfile-report.json 2>/dev/null || true
CHANGED_POM=$(git diff --name-only HEAD -- '*/pom.xml' 'pom.xml' 2>/dev/null || true)
CHANGED_DOCKER=$(git diff --name-only HEAD -- '*/Dockerfile' 'Dockerfile' 2>/dev/null || true)
CHANGED_PKG=$(git diff --name-only HEAD -- '*/package.json' 'package.json' '*/package-lock.json' 'package-lock.json' 2>/dev/null || true)
echo "Modified pom.xml files: ${CHANGED_POM:-none}"
echo "Modified Dockerfiles: ${CHANGED_DOCKER:-none}"
echo "Modified package.json files: ${CHANGED_PKG:-none}"

echo "=== Step 5: Validate and Create MR ==="
[ -f /tmp/security_base_branch.env ] && source /tmp/security_base_branch.env

if [ -z "$SECURITY_BASE_BRANCH" ]; then
    echo "Error: SECURITY_BASE_BRANCH is not set. Refusing to create remediation branch."
    exit 1
fi

validate_base_branch "$SECURITY_BASE_BRANCH"

BRANCH_NAME="bugFix/issue-0001-security-updates-${SECURITY_BASE_BRANCH}-$(date +%d-%m-%y)"
echo "Base branch: ${SECURITY_BASE_BRANCH}"
echo "Remediation branch: ${BRANCH_NAME}"

ACTIONABLE_COUNT=0
[ -f "security-reports/remediation-plan.json" ] && ACTIONABLE_COUNT=$(jq '.total_remediations' security-reports/remediation-plan.json 2>/dev/null || echo "0")
echo "Actionable remediations: ${ACTIONABLE_COUNT}"

FIXES_APPLIED=false
if [ -f "security-reports/.fixes-applied" ]; then
    FIXES_APPLIED=true
    echo "Fixes applied locally: $(cat security-reports/.fixes-applied)"
fi

[ -z "${GITLAB_USER_EMAIL:-}" ] && { echo "Error: GITLAB_USER_EMAIL not set (define it as a project/group CI/CD variable)"; exit 1; }
git config --global user.email "$GITLAB_USER_EMAIL"
git config --global user.name "${GITLAB_USER_NAME:-Security Bot}"

# Delegate to create-remediation-mr.sh which handles:
#   - Detecting existing MRs (including Renovate branches)
#   - Creating local branch, committing changes, pushing
#   - Creating or augmenting the MR via API
if [ -f "security-reports/unified-findings.json" ]; then
    CVE_COUNT=$(jq '.total_findings' security-reports/unified-findings.json 2>/dev/null || echo "0")
    if [ "$CVE_COUNT" -gt 0 ]; then
        echo "Found $CVE_COUNT HIGH/CRITICAL CVEs. Creating or augmenting remediation MR"
        /scripts/create-remediation-mr.sh \
            --branch-prefix "bugFix/issue-0001-security-updates" \
            --target-branch "$SECURITY_BASE_BRANCH" \
            --findings-file "security-reports/unified-findings.json" \
            --remediation-file "security-reports/remediation-plan.json" \
            || echo "MR creation/augmentation completed with warnings"
    else
        echo "No HIGH/CRITICAL CVEs found. No MR needed."
    fi
else
    echo "No findings file found. Skipping MR creation."
fi

echo "=== Remediation job completed ==="
if [ "$AGGREGATOR_EXIT_CODE" -ne 0 ]; then
    echo "NOTE: Aggregator had errors (exit code $AGGREGATOR_EXIT_CODE) but remediation continued with partial results"
fi