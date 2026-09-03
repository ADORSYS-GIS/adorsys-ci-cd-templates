#!/usr/bin/env bash
# Slack Pipeline Notification Script
# Called by the .slack_notify CI job template.
# Optional: GITLAB_PAGES_DOMAIN (e.g. group.pages.example.com) - set at
# project/group CI/CD variable level to enable the vulnerability-report link.
set -euo pipefail

log() { echo "[notify-slack] $1"; }

if [ -z "${SLACK_WEBHOOK_URL:-}" ]; then
    log "SLACK_WEBHOOK_URL is not set; skipping notification"; exit 0
fi

validate_env() {
    local missing=()
    for var in CI_COMMIT_BRANCH CI_COMMIT_SHA CI_PROJECT_URL CI_PIPELINE_URL CI_JOB_TOKEN CI_API_V4_URL CI_PROJECT_ID CI_PIPELINE_ID; do
        if [ -z "${!var:-}" ]; then missing+=("$var"); fi
    done
    if [ ${#missing[@]} -gt 0 ]; then log "Missing: ${missing[*]}"; exit 0; fi
}

fetch_pipeline_jobs() {
    local resp; resp=$(curl -s -w "\n%{http_code}" -H "JOB-TOKEN: ${CI_JOB_TOKEN}" \
        "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/pipelines/${CI_PIPELINE_ID}/jobs")
    local code; code=$(echo "$resp" | tail -1)
    local body; body=$(echo "$resp" | sed '$d')
    [ "$code" = "200" ] && echo "$body" || { echo "{}"; return 1; }
}

get_failed_jobs() { echo "$1" | jq -r '.[] | select(.status == "failed") | .name' 2>/dev/null || true; }

get_owasp_info() { echo "$1" | jq -r ".[] | select(.name | ascii_downcase | contains(\"owasp\")) | .$2" 2>/dev/null | head -1 || true; }

format_jobs_list() {
    local count; count=$(echo "$1" | grep -c . 2>/dev/null || echo "0")
    [ "$count" -eq 0 ] && { echo "None"; return; }
    echo "$1" | while read -r job; do [ -n "$job" ] && echo "- $job"; done | tr '\n' ',' | sed 's/,$//'
}

get_pages_path() {
    local fp="${CI_PROJECT_PATH:-${CI_PROJECT_NAME:-unknown}}"
    echo "${fp#*/}"
}

send_notification() {
    local color="$1" icon="$2" header="$3" sl="$4" sv="$5" has_vuln="$6" owasp_id="$7"
    local ts; ts=$(date -u +"%Y-%m-%d %H:%M UTC")
    local cs="${CI_COMMIT_SHA:0:8}"
    local cm; cm=$(echo "${CI_COMMIT_MESSAGE:-No message}" | head -c 100)
    local author="${GITLAB_USER_LOGIN:-${CI_COMMIT_AUTHOR:-Unknown}}"
    local pp="${CI_PROJECT_PATH:-${CI_PROJECT_NAME:-unknown}}"
    local pages_path; pages_path=$(get_pages_path)
    local curl="$CI_PROJECT_URL/-/commit/$CI_COMMIT_SHA"

    local vuln_btn=""
    if [ "$has_vuln" = "true" ] && [ -n "$owasp_id" ] && [ -n "${GITLAB_PAGES_DOMAIN:-}" ]; then
        vuln_btn=$(jq -nc --arg url "https://${GITLAB_PAGES_DOMAIN}/-/${pages_path}/-/jobs/${owasp_id}/artifacts/target/dependency-check-report.html" \
            '{type:"button",text:{type:"plain_text",text:":warning: Vulnerability Report",emoji:true},url:$url}')
    fi

    local actions='[{"type":"button","text":{"type":"plain_text","text":"View Pipeline"},"url":"'"$CI_PIPELINE_URL"'"},{"type":"button","text":{"type":"plain_text","text":"View Commit"},"url":"'"$curl"'"}]'
    [ -n "$vuln_btn" ] && actions=$(echo "$actions" | jq --argjson vb "$vuln_btn" '. + [$vb]')

    local payload
    payload=$(jq -nc \
        --arg text "$icon $header in $pp" \
        --arg color "$color" \
        --arg header_text "$icon $header" \
        --arg pp "$pp" --arg branch "$CI_COMMIT_BRANCH" \
        --arg curl "$curl" --arg cs "$cs" --arg author "$author" \
        --arg sl "$sl" --arg sv "$sv" --arg cm "_${cm}_" \
        --arg ts "$ts" --arg purl "$CI_PIPELINE_URL" \
        --argjson actions "$actions" \
        '{text:$text,attachments:[{color:$color,blocks:[
        {type:"header",text:{type:"plain_text",text:$header_text,emoji:true}},
        {type:"section",fields:[
          {type:"mrkdwn",text:("*Project:*\\n"+$pp)},
          {type:"mrkdwn",text:("*Branch:*\\n"+$branch)},
          {type:"mrkdwn",text:("*Commit:*\\n<"+$curl+"|"+$cs+">")},
          {type:"mrkdwn",text:("*Author:*\\n"+$author)}]},
        {type:"section",text:{type:"mrkdwn",text:("*"+$sl+":*\\n`"+$sv+"`")}},
        {type:"section",text:{type:"mrkdwn",text:("*Commit Message:*\\n"+$cm)}},
        {type:"context",elements:[
          {type:"mrkdwn",text:":clock1: "+$ts},
          {type:"mrkdwn",text:"|"},
          {type:"mrkdwn",text:"Triggered by GitLab CI"}]},
        {type:"actions",elements:$actions}]}]}')

    curl -s -X POST "${SLACK_WEBHOOK_URL}" -H 'Content-Type: application/json' -d "$payload" >/dev/null || true
}

main() {
    validate_env
    local jobs; jobs=$(fetch_pipeline_jobs)
    [ -z "$jobs" ] || [ "$jobs" = "{}" ] && { log "No job data received"; exit 0; }
    local fj; fj=$(get_failed_jobs "$jobs")
    local fc; fc=$(echo "$fj" | grep -c . 2>/dev/null || echo "0")
    local ows; ows=$(get_owasp_info "$jobs" "status")
    local owid; owid=$(get_owasp_info "$jobs" "id")
    local vuln="false"
    [ "$ows" = "failed" ] && [ -n "$owid" ] && vuln="true"

    if [ "$vuln" = "true" ]; then
        local st="OWASP Dependency Check found vulnerabilities"
        [ "$fc" -gt 0 ] && st="OWASP vulnerabilities found. Also failed: $(format_jobs_list "$fj")"
        send_notification "danger" ":bangbang:" "[HIGH PRIORITY] VULNERABILITIES FOUND" "Security Scan" "$st" "true" "$owid"
    elif [ "$fc" -gt 0 ]; then
        send_notification "danger" ":red_circle:" "Pipeline Failed" "Failed Jobs" "$(format_jobs_list "$fj")" "false" ""
    else
        log "Pipeline passed successfully - no notification sent"
    fi
}

main "$@"