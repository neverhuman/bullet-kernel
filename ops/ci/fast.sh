#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "fast lane: standalone component tests only"
deny_sibling_gitd
run_partition_tests fast fast "$EXPECTED_STANDALONE_TESTS" "$STANDALONE_FILTER"
log "fast lane passed"
