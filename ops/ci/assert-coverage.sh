#!/usr/bin/env bash
# Standalone line-coverage floor for the kernel coverage lane.
#
# Reads the summary that ops/ci/coverage.sh writes
# (.ci-artifacts/coverage/summary.json, schema bullet.coverage-summary.v1) and
# refuses when measured line coverage is below COVERAGE_LINE_FLOOR. The floor
# is a ratchet: it may only rise. It was introduced at measured-1 (74.06 % lines
# on 2026-08-26 -> 73). A missing, symlinked, empty, malformed, or internally
# inconsistent summary is a refusal, never a pass.
#
# The optional argument names another summary file and exists only so hostile
# fixtures can be proven; the coverage lane always calls this with no argument.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

COVERAGE_LINE_FLOOR=73
summary="${1:-.ci-artifacts/coverage/summary.json}"

require_tool jq || exit 1
require_tool awk || exit 1
[[ "$COVERAGE_LINE_FLOOR" =~ ^[0-9]+$ && "$COVERAGE_LINE_FLOOR" -le 100 ]] \
  || { refuse COVERAGE_FLOOR_INVALID "$COVERAGE_LINE_FLOOR"; exit 1; }
[[ -f "$summary" && ! -L "$summary" && -s "$summary" ]] \
  || { refuse COVERAGE_ARTIFACT_MISSING "$summary"; exit 1; }

# Exact shape admission: the schema tag, integer counters, and a numeric
# percent must all be present; anything else is a malformed artifact.
totals="$(jq -er '
  select(type == "object")
  | select(.schema_version == "bullet.coverage-summary.v1")
  | .totals.lines
  | select(type == "object")
  | select((.count | type) == "number" and .count == (.count | floor) and .count > 0)
  | select((.covered | type) == "number" and .covered == (.covered | floor) and .covered >= 0)
  | select(.covered <= .count)
  | select((.percent | type) == "number" and .percent >= 0 and .percent <= 100)
  | "\(.count) \(.covered) \(.percent)"
' "$summary" 2>/dev/null)" \
  || { refuse COVERAGE_ARTIFACT_INVALID "$summary is not a bullet.coverage-summary.v1 with line totals"; exit 1; }
read -r line_count line_covered reported_percent <<<"$totals"

# Recompute the percent from the counters and require the artifact to agree
# with itself, so a hand-edited percent cannot outrun its own counters.
measured="$(awk -v count="$line_count" -v covered="$line_covered" \
  'BEGIN { printf "%.2f", (covered * 100) / count }')"
awk -v measured="$measured" -v reported="$reported_percent" 'BEGIN {
  delta = measured - reported
  if (delta < 0) delta = -delta
  exit (delta <= 0.01) ? 0 : 1
}' || { refuse COVERAGE_ARTIFACT_INVALID "percent $reported_percent disagrees with $line_covered/$line_count"; exit 1; }

log "standalone line coverage measured=${measured}% (${line_covered}/${line_count} lines) floor=${COVERAGE_LINE_FLOOR}%"
awk -v measured="$measured" -v floor="$COVERAGE_LINE_FLOOR" \
  'BEGIN { exit (measured + 0 >= floor + 0) ? 0 : 1 }' \
  || { refuse COVERAGE_BELOW_FLOOR "measured ${measured}% < floor ${COVERAGE_LINE_FLOOR}% lines"; exit 1; }
log "coverage floor passed"
