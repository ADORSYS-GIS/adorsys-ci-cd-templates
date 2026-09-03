#!/bin/bash
# Remediation: GitLab MR search helpers.
# Sourced by remediation-common.sh — do not source this file directly.

search_existing_mr() {
    local BRANCH_PREFIX_SEARCH="$1" BRANCH_NAME="$2" TARGET_BRANCH="$3" GITLAB_API="$4" GITLAB_TOKEN="$5" CI_PROJECT_ID="$6"
    EXISTING_MR=""; EXISTING_BRANCH_NAME=""

    echo "Searching for existing MR: branch_name=$BRANCH_NAME, prefix=$BRANCH_PREFIX_SEARCH, target=$TARGET_BRANCH"

    local EXISTING_BRANCH; EXISTING_BRANCH=$(git ls-remote --heads origin "$BRANCH_NAME" 2>/dev/null | head -1 || true)
    if [[ -n "$EXISTING_BRANCH" ]]; then
        echo "Found exact branch match: $BRANCH_NAME"
        EXISTING_MR=$(curl -s --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
            "${GITLAB_API}/projects/${CI_PROJECT_ID}/merge_requests?state=opened&source_branch=${BRANCH_NAME}&target_branch=${TARGET_BRANCH}" \
            | jq -r '.[0].iid // empty' 2>/dev/null || true)
        [[ -n "$EXISTING_MR" ]] && EXISTING_BRANCH_NAME="$BRANCH_NAME"
    fi

    if [[ -z "$EXISTING_MR" ]]; then
        local RENOVATE_BRANCH="${BRANCH_PREFIX_SEARCH}"
        local RENOVATE_REMOTE; RENOVATE_REMOTE=$(git ls-remote --heads origin "$RENOVATE_BRANCH" 2>/dev/null | head -1 || true)
        if [[ -n "$RENOVATE_REMOTE" ]]; then
            echo "Found prefix branch match: $RENOVATE_BRANCH"
            local RENOVATE_MR; RENOVATE_MR=$(curl -s --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
                "${GITLAB_API}/projects/${CI_PROJECT_ID}/merge_requests?state=opened&source_branch=${RENOVATE_BRANCH}&target_branch=${TARGET_BRANCH}" \
                | jq -r '.[0].iid // empty' 2>/dev/null || true)
            [[ -n "$RENOVATE_MR" ]] && EXISTING_MR="$RENOVATE_MR" && EXISTING_BRANCH_NAME="$RENOVATE_BRANCH"
        fi
    fi

    if [[ -z "$EXISTING_MR" ]]; then
        echo "Searching for Renovate branches (renovate/*) targeting $TARGET_BRANCH..."
        local RENOVATE_BRANCHES; RENOVATE_BRANCHES=$(git ls-remote --heads origin 'renovate/*' 2>/dev/null | head -5 || true)
        if [[ -n "$RENOVATE_BRANCHES" ]]; then
            while IFS= read -r remote_line; do
                local branch_ref; branch_ref=$(echo "$remote_line" | awk '{print $2}' | sed 's|refs/heads/||')
                [[ -z "$branch_ref" ]] && continue
                echo "Checking Renovate branch: $branch_ref"
                local MR_FOR_BRANCH; MR_FOR_BRANCH=$(curl -s --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
                    "${GITLAB_API}/projects/${CI_PROJECT_ID}/merge_requests?state=opened&source_branch=${branch_ref}&target_branch=${TARGET_BRANCH}" \
                    | jq -r '.[0].iid // empty' 2>/dev/null || true)
                if [[ -n "$MR_FOR_BRANCH" ]]; then
                    echo "Found MR $MR_FOR_BRANCH for Renovate branch: $branch_ref"
                    EXISTING_MR="$MR_FOR_BRANCH"
                    EXISTING_BRANCH_NAME="$branch_ref"
                    break
                fi
            done <<< "$RENOVATE_BRANCHES"
        fi
    fi

    if [[ -z "$EXISTING_MR" ]]; then
        local PREFIX_MATCH_MR; PREFIX_MATCH_MR=$(curl -s --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
            "${GITLAB_API}/projects/${CI_PROJECT_ID}/merge_requests?state=opened&target_branch=${TARGET_BRANCH}&labels=security" \
            | jq -r "[.[] | select(.source_branch | startswith(\"${BRANCH_PREFIX_SEARCH}\"))] | .[0].iid // empty" 2>/dev/null || true)
        if [[ -n "$PREFIX_MATCH_MR" ]]; then
            echo "Found MR $PREFIX_MATCH_MR by prefix search on security label"
            EXISTING_MR="$PREFIX_MATCH_MR"
            EXISTING_BRANCH_NAME=$(curl -s --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
                "${GITLAB_API}/projects/${CI_PROJECT_ID}/merge_requests/${PREFIX_MATCH_MR}" \
                | jq -r '.source_branch // empty' 2>/dev/null || true)
        fi
    fi

    if [[ -z "$EXISTING_MR" ]]; then
        local GROUP_MATCH_MR; GROUP_MATCH_MR=$(curl -s --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
            "${GITLAB_API}/projects/${CI_PROJECT_ID}/merge_requests?state=opened&target_branch=${TARGET_BRANCH}&labels=security" \
            | jq -r "[.[] | select(.source_branch | startswith(\"bugFix/issue-0001-\"))] | .[0].iid // empty" 2>/dev/null || true)
        if [[ -n "$GROUP_MATCH_MR" ]]; then
            echo "Found MR $GROUP_MATCH_MR by bugFix prefix search on security label"
            EXISTING_MR="$GROUP_MATCH_MR"
            EXISTING_BRANCH_NAME=$(curl -s --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
                "${GITLAB_API}/projects/${CI_PROJECT_ID}/merge_requests/${GROUP_MATCH_MR}" \
                | jq -r '.source_branch // empty' 2>/dev/null || true)
        fi
    fi

    if [[ -n "$EXISTING_MR" ]]; then
        echo "Found existing MR: $EXISTING_MR on branch: $EXISTING_BRANCH_NAME"
    else
        echo "No existing MR found for target branch: $TARGET_BRANCH"
    fi
}
