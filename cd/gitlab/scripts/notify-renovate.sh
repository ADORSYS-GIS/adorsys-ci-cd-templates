#!/usr/bin/env bash
# Slack Renovate Notification Script
# Reports Renovate update status and grouped security MR to Slack.
# Called by the .slack_notify_renovate CI job template.
set -euo pipefail

log() { echo "[notify-renovate] $1"; }

if [ -z "${SLACK_WEBHOOK_URL:-}" ]; then
    log "SLACK_WEBHOOK_URL not set; skipping"
    exit 0
fi

validate_env() {
    local missing=()
    for var in CI_PROJECT_URL CI_PIPELINE_URL CI_JOB_TOKEN CI_API_V4_URL CI_PROJECT_ID CI_PIPELINE_ID CI_COMMIT_BRANCH; do
        [ -z "${!var:-}" ] && missing+=("$var")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        log "Missing vars: ${missing[*]}; skipping"
        exit 0
    fi
}

fetch_jobs() {
    local resp
    resp=$(curl -s -w "\n%{http_code}" \
        -H "JOB-TOKEN: ${CI_JOB_TOKEN}" \
        "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/pipelines/${CI_PIPELINE_ID}/jobs")
    local code; code=$(echo "$resp" | tail -1)
    local body; body=$(echo "$resp" | sed '$d')
    [ "$code" = "200" ] && echo "$body" || echo "[]"
}

get_renovate_job_status() {
    echo "$1" | jq -r \
        '[.[] | select(.name | ascii_downcase | contains("renovate"))] | first | .status // "unknown"' \
        2>/dev/null
}

fetch_recent_renovate_mrs() {
    local since
    since=$(date -u -d '25 hours ago' +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null \
        || date -u -v-25H +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")
    local url="${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/merge_requests?state=opened&per_page=50"
    [ -n "$since" ] && url="${url}&created_after=${since}"
    local resp
    resp=$(curl -s -w "\n%{http_code}" -H "JOB-TOKEN: ${CI_JOB_TOKEN}" "$url")
    local code; code=$(echo "$resp" | tail -1)
    local body; body=$(echo "$resp" | sed '$d')
    if [ "$code" = "200" ]; then
        echo "$body" | jq \
            --arg prefix "${RENOVATE_BRANCH_PREFIX:-renovate/}" \
            '[.[] | select(.source_branch | startswith($prefix))]' \
            2>/dev/null || echo "[]"
    else
        log "GitLab API returned HTTP $code when fetching MRs"
        echo "[]"
    fi
}

format_mr_list() {
    local count; count=$(echo "$1" | jq 'length' 2>/dev/null || echo "0")
    [ "$count" -eq 0 ] && { echo "_None_"; return; }
    echo "$1" | jq -r '.[] | "• <\(.web_url)|\(.title)>"' 2>/dev/null | head -10
}

send() {
    local color="$1" icon="$2" header="$3" status="$4" mr_list="$5" mr_count="$6"
    local ts; ts=$(date -u +"%Y-%m-%d %H:%M UTC")
    local project="${CI_PROJECT_PATH:-${CI_PROJECT_NAME:-unknown}}"

    local payload
    payload=$(cat << 'PAYLOAD'
{"text":"ICON HEADER — PROJECT","attachments":[{"color":"COLOR","blocks":[{"type":"header","text":{"type":"plain_text","text":"ICON HEADER","emoji":true}},{"type":"section","fields":[{"type":"mrkdwn","text":"*Project:*\nPROJECT"},{"type":"mrkdwn","text":"*Branch:*\nBRANCH"},{"type":"mrkdwn","text":"*Job Status:*\n`STATUS`"},{"type":"mrkdwn","text":"*Security MRs Opened:*\nMR_COUNT"}]},{"type":"section","text":{"type":"mrkdwn","text":"*HIGH / CRITICAL Security Update MR:*\nMR_LIST"}},{"type":"context","elements":[{"type":"mrkdwn","text":":clock1: TS"},{"type":"mrkdwn","text":"| Triggered by Renovate Bot schedule (HIGH + CRITICAL only)"}]},{"type":"actions","elements":[{"type":"button","text":{"type":"plain_text","text":"View Pipeline"},"url":"PIPELINE_URL"},{"type":"button","text":{"type":"plain_text","text":":shield: Open Security MRs"},"url":"PROJECT_URL/-/merge_requests?label_name=security&state=opened"}]}]}]}
PAYLOAD
    )

    local mr_list_escaped; mr_list_escaped=$(echo "$mr_list" | sed 's/&/\&amp;/g')

    payload="${payload//ICON/$icon}"
    payload="${payload//HEADER/$header}"
    payload="${payload//COLOR/$color}"
    payload="${payload//PROJECT/$project}"
    payload="${payload//BRANCH/$CI_COMMIT_BRANCH}"
    payload="${payload//STATUS/$status}"
    payload="${payload//MR_COUNT/$mr_count}"
    payload="${payload//MR_LIST/$mr_list_escaped}"
    payload="${payload//TS/$ts}"
    payload="${payload//PIPELINE_URL/$CI_PIPELINE_URL}"
    payload="${payload//PROJECT_URL/$CI_PROJECT_URL}"

    curl -s -X POST "${SLACK_WEBHOOK_URL}" -H 'Content-Type: application/json' -d "$payload" >/dev/null || true
}

main() {
    validate_env
    local jobs; jobs=$(fetch_jobs)
    local job_status; job_status=$(get_renovate_job_status "$jobs")
    local mrs; mrs=$(fetch_recent_renovate_mrs)
    local mr_count; mr_count=$(echo "$mrs" | jq 'length' 2>/dev/null || echo "0")
    local mr_list; mr_list=$(format_mr_list "$mrs")

    if [ "$job_status" = "failed" ]; then
        send "danger" ":bangbang:" "[RENOVATE] Security Scan Failed" "$job_status" "$mr_list" "$mr_count"
    elif [ "$mr_count" -gt 0 ]; then
        send "warning" ":shield:" "[RENOVATE] ${mr_count} HIGH/CRITICAL Security MR(s) Opened" "$job_status" "$mr_list" "$mr_count"
    else
        send "good" ":white_check_mark:" "[RENOVATE] No HIGH/CRITICAL Vulnerabilities Found" "$job_status" "_No vulnerable dependencies detected_" "0"
    fi
}

main "$@"