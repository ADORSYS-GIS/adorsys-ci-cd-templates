#!/usr/bin/env bash
# Slack Remediation Notification Script
# Reports remediation MR results to Slack: CVE counts, MR link, fix status.
# Called by the .slack_notify_remediation CI job template.
set -euo pipefail

log() { echo "[notify-remediation] $1"; }

if [ -z "${SLACK_WEBHOOK_URL:-}" ]; then
    log "SLACK_WEBHOOK_URL not set; skipping notification"
    exit 0
fi

PROJECT="${CI_PROJECT_PATH:-${CI_PROJECT_NAME:-unknown}}"
BRANCH="${SECURITY_BASE_BRANCH:-develop}"
TS=$(date -u +"%Y-%m-%d %H:%M UTC")
if [ -z "${GITLAB_API:-}" ]; then
    log "GITLAB_API not set (define it as a project/group CI/CD variable); skipping notification"
    exit 0
fi
API_URL="${GITLAB_API}/api/v4"

TOTAL_CVES="0"; HIGH_COUNT="0"; CRITICAL_COUNT="0"; ACTIONABLE="0"; FIXES_APPLIED="0"

if [ -f "security-reports/summary.json" ]; then
    TOTAL_CVES=$(jq '.summary.total_cves // 0' security-reports/summary.json 2>/dev/null || echo "0")
    HIGH_COUNT=$(jq '.summary.high_count // 0' security-reports/summary.json 2>/dev/null || echo "0")
    CRITICAL_COUNT=$(jq '.summary.critical_count // 0' security-reports/summary.json 2>/dev/null || echo "0")
    ACTIONABLE=$(jq '.summary.actionable_count // 0' security-reports/summary.json 2>/dev/null || echo "0")
fi

if [ -f "security-reports/.fixes-applied" ]; then
    FIXES_APPLIED=$(cat security-reports/.fixes-applied 2>/dev/null || echo "0")
fi

MR_TITLE="_No MR created_"
MR_URL=""
DATE_SUFFIX=$(date +%d-%m-%y 2>/dev/null || echo "")
BRANCH_NAME="${REMEDIATION_BRANCH_PREFIX:-bugFix/issue-0001-security-updates}-${BRANCH}-${DATE_SUFFIX}"
BRANCH_PREFIX="${REMEDIATION_BRANCH_PREFIX:-bugFix/issue-0001-security-updates}-${BRANCH}"

if [ -n "${GITLAB_TOKEN:-}" ] && [ -n "${CI_PROJECT_ID:-}" ]; then
    MR_IID=$(curl -s --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
        "${API_URL}/projects/${CI_PROJECT_ID}/merge_requests?state=opened&source_branch=${BRANCH_NAME}&target_branch=${BRANCH}" \
        | jq -r '.[0].iid // empty' 2>/dev/null || true)
    if [ -z "$MR_IID" ]; then
        MR_IID=$(curl -s --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
            "${API_URL}/projects/${CI_PROJECT_ID}/merge_requests?state=opened&source_branch=${BRANCH_PREFIX}&target_branch=${BRANCH}" \
            | jq -r '.[0].iid // empty' 2>/dev/null || true)
    fi
    if [ -z "$MR_IID" ]; then
        MR_IID=$(curl -s --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
            "${API_URL}/projects/${CI_PROJECT_ID}/merge_requests?state=opened&target_branch=${BRANCH}&labels=security" \
            | jq -r "[.[] | select(.source_branch | startswith(\"${BRANCH_PREFIX}\"))] | .[0].iid // empty" 2>/dev/null || true)
    fi
    if [ -n "$MR_IID" ]; then
        MR_DATA=$(curl -s --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
            "${API_URL}/projects/${CI_PROJECT_ID}/merge_requests/${MR_IID}")
        MR_TITLE=$(echo "$MR_DATA" | jq -r '.title // "Security Remediation MR"' 2>/dev/null)
        MR_URL=$(echo "$MR_DATA" | jq -r '.web_url // empty' 2>/dev/null)
    fi
fi

if [ "$TOTAL_CVES" -eq 0 ]; then
    COLOR="good"; ICON=":white_check_mark:"; HEADER="[REMEDIATION] No HIGH/CRITICAL Vulnerabilities"
    STATUS_TEXT="No HIGH/CRITICAL CVEs detected"
elif [ "$FIXES_APPLIED" -gt 0 ]; then
    COLOR="warning"; ICON=":shield:"; HEADER="[REMEDIATION] ${TOTAL_CVES} CVE(s) — ${FIXES_APPLIED} Fix(es) Applied"
    STATUS_TEXT="${ACTIONABLE} actionable · ${FIXES_APPLIED} fixes applied to source files"
elif [ "$ACTIONABLE" -gt 0 ]; then
    COLOR="warning"; ICON=":shield:"; HEADER="[REMEDIATION] ${TOTAL_CVES} CVE(s) — ${ACTIONABLE} Fixable"
    STATUS_TEXT="${ACTIONABLE} have known fixes · manual review required"
else
    COLOR="danger"; ICON=":bangbang:"; HEADER="[REMEDIATION] ${TOTAL_CVES} CVE(s) — No Known Fixes"
    STATUS_TEXT="No automated fixes available · manual remediation needed"
fi

MR_LINE="_No MR created_"
if [ -n "$MR_URL" ]; then MR_LINE="<${MR_URL}|${MR_TITLE}>"
elif [ "$TOTAL_CVES" -gt 0 ]; then MR_LINE="MR creation attempted — see pipeline log"; fi

PAYLOAD=$(cat <<EOF
{"text":"${ICON} ${HEADER} — ${PROJECT}","attachments":[{"color":"${COLOR}","blocks":[{"type":"header","text":{"type":"plain_text","text":"${ICON} ${HEADER}","emoji":true}},{"type":"section","fields":[{"type":"mrkdwn","text":"*Project:*\n${PROJECT}"},{"type":"mrkdwn","text":"*Branch:*\n${BRANCH}"},{"type":"mrkdwn","text":"*Total CVEs:*\n${TOTAL_CVES} (${CRITICAL_COUNT} critical, ${HIGH_COUNT} high)"},{"type":"mrkdwn","text":"*Fixes Applied:*\n${FIXES_APPLIED}"}]},{"type":"section","text":{"type":"mrkdwn","text":"*Status:*\n${STATUS_TEXT}"}},{"type":"section","text":{"type":"mrkdwn","text":"*Security MR:*\n${MR_LINE}"}},{"type":"context","elements":[{"type":"mrkdwn","text":":clock1: ${TS}"},{"type":"mrkdwn","text":"| Triggered by security-scan schedule"}]},{"type":"actions","elements":[{"type":"button","text":{"type":"plain_text","text":"View Pipeline"},"url":"${CI_PIPELINE_URL}"},{"type":"button","text":{"type":"plain_text","text":":shield: Security MRs"},"url":"${CI_PROJECT_URL}/-/merge_requests?label_name=security&state=opened"}]}]}]}
EOF
)

curl -s -X POST "${SLACK_WEBHOOK_URL}" -H 'Content-Type: application/json' -d "$PAYLOAD" >/dev/null || true
log "Notification sent"