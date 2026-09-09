#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

require_tool jq || exit 1
mkdir -p .ci-artifacts/test
printf 'sanitized\n' >.ci-artifacts/test/artifact.txt
bash scripts/ci-observation.sh observation-test 0 \
  'bash ops/ci/observation-test.sh' .ci-artifacts/test/artifact.txt >/dev/null
observation=.ci-artifacts/observations/observation-test.json
jq -e '
  .schema_version == "bullet.ci-observation.v1" and
  .repository == "bullet-kernel" and
  (.commit_oid | test("^[0-9a-f]{40}$")) and
  (.tree_oid | test("^[0-9a-f]{40}$")) and
  (.clean | type == "boolean") and
  .commands == ["bash ops/ci/observation-test.sh"] and
  (.tool_versions | type == "object") and
  .outcomes == [{"lane":"observation-test","status":"PASS","exit_code":0}] and
  (.artifact_hashes | length == 1) and
  (.artifact_hashes[0].path == ".ci-artifacts/test/artifact.txt") and
  (.artifact_hashes[0].sha256 | test("^[0-9a-f]{64}$")) and
  .signed == false and
  .evidence_class == "DIAGNOSTIC_ONLY" and
  (keys | sort) == (["artifact_hashes","clean","commands","commit_oid","evidence_class","outcomes","repository","schema_version","signed","tool_versions","tree_oid"] | sort)
' "$observation" >/dev/null

if bash scripts/ci-observation.sh observation-test 0 valid ../escape >/dev/null 2>&1; then
  refuse OBSERVATION_PATH_GUARD_FAILED "parent traversal was accepted"
  exit 1
fi
if bash scripts/ci-observation.sh observation-test 0 '' >/dev/null 2>&1; then
  refuse OBSERVATION_COMMAND_GUARD_FAILED "empty command was accepted"
  exit 1
fi
if bash scripts/ci-observation.sh observation-test 256 valid >/dev/null 2>&1; then
  refuse OBSERVATION_EXIT_BOUND_GUARD_FAILED "exit code above schema maximum was accepted"
  exit 1
fi
if bash scripts/ci-observation.sh ../escape 1 valid >/dev/null 2>&1; then
  refuse OBSERVATION_LANE_GUARD_FAILED "path-shaped lane was accepted"
  exit 1
fi
rm -rf .ci-artifacts/test
rm -f "$observation"
log "CI observation schema and path guards passed"
