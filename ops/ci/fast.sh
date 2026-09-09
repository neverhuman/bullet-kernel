#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "fast lane: standalone component tests only"
deny_sibling_gitd
run_partition_tests fast fast "$EXPECTED_STANDALONE_TESTS" "$STANDALONE_FILTER"
fast_junit="$REPO_ROOT/.ci-artifacts/junit/fast.xml"
if ! awk -v expected="$EXPECTED_STANDALONE_TESTS" '
  NR == 2 && /^<testsuites / {
    if (match($0, / tests="[0-9]+"/)) {
      result_count = substr($0, RSTART + 8, RLENGTH - 9) + 0
      root_seen = 1
    }
  }
  index($0, "<skipped") != 0 || $0 ~ / disabled="[1-9][0-9]*"/ { skipped = 1 }
  END { exit !(root_seen && result_count == expected && !skipped) }
' "$fast_junit"; then
  refuse FAST_JUNIT_RESULT_DRIFT "expected exactly $EXPECTED_STANDALONE_TESTS results and zero skipped tests"
  exit 1
fi
log "fast lane passed"
