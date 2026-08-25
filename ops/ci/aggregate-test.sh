#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

require_tool jq || exit 1
test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT
expected_commit="$(git rev-parse HEAD)"
expected_tree="$(git rev-parse "$expected_commit^{tree}")"
lanes=(preflight fast lint contract security docs)
green=(success success success success success success)

make_fixtures() {
  local lane relative path digest artifacts
  rm -rf -- "$test_root"
  mkdir -p "$test_root/observations" "$test_root/junit"
  printf '%s\n' '<testsuites tests="1" failures="0" errors="0" skipped="0"/>' \
    >"$test_root/junit/fast.xml"
  printf '%s\n' '<testsuites tests="1" failures="0" errors="0" skipped="0"/>' \
    >"$test_root/junit/contract.xml"
  for lane in "${lanes[@]}"; do
    artifacts='[]'
    case "$lane" in
      fast|contract)
        relative=".ci-artifacts/junit/$lane.xml"
        path="$test_root/${relative#.ci-artifacts/}"
        digest="$(sha256_file "$path")"
        artifacts="$(jq -cn --arg path "$relative" --arg sha256 "$digest" \
          '[{path:$path,sha256:$sha256}]')"
        ;;
    esac
    jq -n --arg lane "$lane" --arg commit "$expected_commit" --arg tree "$expected_tree" \
      --arg command "bash scripts/ci-local.sh $lane" --argjson artifacts "$artifacts" '
      {schema_version:"bullet.ci-observation.v1",repository:"bullet-kernel",
       commit_oid:$commit,tree_oid:$tree,clean:true,commands:[$command],tool_versions:{},
       outcomes:[{lane:$lane,status:"PASS",exit_code:0}],artifact_hashes:$artifacts,
       signed:false,evidence_class:"DIAGNOSTIC_ONLY"}' \
      >"$test_root/observations/$lane.json"
  done
}

expect_failure() {
  local reason="$1" output code
  shift
  set +e
  output="$(bash ops/ci/aggregate.sh "$@" 2>&1)"
  code=$?
  set -e
  [[ "$code" -eq 1 && "$output" == *"$reason"* ]] \
    || { refuse AGGREGATOR_NEGATIVE_FAILED "$reason code=$code output=$output"; exit 1; }
}

args=("$test_root" "$expected_commit")
make_fixtures
bash ops/ci/aggregate.sh "${args[@]}" "${green[@]}" >/dev/null
for bad in failure skipped cancelled ''; do
  candidate=("${green[@]}")
  candidate[2]="$bad"
  expect_failure CI_JOB_NOT_SUCCESSFUL "${args[@]}" "${candidate[@]}"
done
expect_failure CI_JOB_MISSING "${args[@]}" "${green[@]:0:5}"

make_fixtures
jq '.tree_oid="2222222222222222222222222222222222222222"' \
  "$test_root/observations/security.json" >"$test_root/x"
mv "$test_root/x" "$test_root/observations/security.json"
expect_failure CI_OBSERVATION_INVALID "${args[@]}" "${green[@]}"

make_fixtures
jq '.commit_oid="2222222222222222222222222222222222222222"' \
  "$test_root/observations/security.json" >"$test_root/x"
mv "$test_root/x" "$test_root/observations/security.json"
expect_failure CI_OBSERVATION_INVALID "${args[@]}" "${green[@]}"

make_fixtures
jq '.commands=["true"]' \
  "$test_root/observations/security.json" >"$test_root/x"
mv "$test_root/x" "$test_root/observations/security.json"
expect_failure CI_OBSERVATION_INVALID "${args[@]}" "${green[@]}"

make_fixtures
rm "$test_root/observations/lint.json"
expect_failure CI_OBSERVATION_MISSING "${args[@]}" "${green[@]}"

make_fixtures
printf 'tampered\n' >>"$test_root/junit/fast.xml"
expect_failure CI_ARTIFACT_HASH_MISMATCH "${args[@]}" "${green[@]}"

make_fixtures
printf 'unexpected\n' >"$test_root/unexpected.txt"
expect_failure CI_ARTIFACT_INVENTORY_INVALID "${args[@]}" "${green[@]}"

log "aggregator rejects wrong trees and every non-exact predecessor fixture"
