#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

require_tool cargo-nextest || exit 1
require_tool cargo-llvm-cov || exit 1
require_tool jq || exit 1
require_exact_output "cargo-llvm-cov 0.8.7" cargo llvm-cov --version
deny_sibling_gitd
selected="$(partition_count "$STANDALONE_FILTER")"
if [[ "$selected" -ne "$EXPECTED_STANDALONE_TESTS" || "$selected" -eq 0 ]]; then
  refuse TEST_PARTITION_DRIFT "coverage selected $selected tests; expected $EXPECTED_STANDALONE_TESTS"
  exit 1
fi
raw="$REPO_ROOT/target/coverage-summary.raw.json"
output="$REPO_ROOT/.ci-artifacts/coverage/summary.json"
mkdir -p "$(dirname "$output")"
cargo llvm-cov nextest --locked --workspace "${NEXTEST_FEATURES[@]}" --profile coverage -E "$STANDALONE_FILTER" \
  --json --summary-only --output-path "$raw"
jq -e '{schema_version: "bullet.coverage-summary.v1", totals: .data[0].totals}' "$raw" >"$output"
rm -f "$raw"
log "standalone coverage summary written to .ci-artifacts/coverage/summary.json"
bash ops/ci/assert-coverage.sh
