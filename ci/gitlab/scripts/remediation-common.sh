#!/bin/bash
# Remediation MR Helper Functions
# Source this file: source /scripts/remediation-common.sh
# All helper functions are defined in the sub-files sourced below.

_REMCOMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${_REMCOMMON_DIR}/remediation-common-git.sh"
source "${_REMCOMMON_DIR}/remediation-common-mr-search.sh"
source "${_REMCOMMON_DIR}/remediation-common-artifacts.sh"
source "${_REMCOMMON_DIR}/remediation-common-report.sh"