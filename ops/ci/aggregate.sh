#!/usr/bin/env bash
# Converge hosted predecessor outcomes against clean observations for the exact
# commit tree checked out by the protected required job.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

lanes=(preflight fast lint contract security docs)
[[ "$#" -eq 8 ]] \
  || { refuse CI_JOB_MISSING "expected artifact root, commit, and six results"; exit 1; }
artifact_root="$1"
EXPECTED_COMMIT="$2"
shift 2
[[ -d "$artifact_root" && ! -L "$artifact_root" ]] \
  || { refuse CI_ARTIFACT_ROOT_MISSING "$artifact_root"; exit 1; }
[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
  || { refuse CI_COMMIT_INVALID "$EXPECTED_COMMIT"; exit 1; }
if ! EXPECTED_TREE="$(git rev-parse "$EXPECTED_COMMIT^{tree}" 2>/dev/null)"; then
  refuse CI_COMMIT_UNAVAILABLE "$EXPECTED_COMMIT"
  exit 1
fi
[[ "$EXPECTED_TREE" =~ ^[0-9a-f]{40}$ ]] \
  || { refuse CI_TREE_INVALID "$EXPECTED_TREE"; exit 1; }

status=0
for lane in "${lanes[@]}"; do
  result="$1"
  shift
  if [[ "$result" != success ]]; then
    refuse CI_JOB_NOT_SUCCESSFUL "$lane=${result:-missing}" || true
    status=1
  fi

  observation="$artifact_root/observations/$lane.json"
  if [[ ! -f "$observation" || -L "$observation" ]]; then
    refuse CI_OBSERVATION_MISSING "$lane" || true
    status=1
    continue
  fi
  if ! jq -e --arg lane "$lane" --arg command "bash scripts/ci-local.sh $lane" \
    --arg commit "$EXPECTED_COMMIT" --arg tree "$EXPECTED_TREE" '
    .schema_version == "bullet.ci-observation.v1" and
    .repository == "bullet-kernel" and
    .commit_oid == $commit and
    .tree_oid == $tree and
    .clean == true and
    .commands == [$command] and
    (.tool_versions | type == "object") and
    .outcomes == [{"lane": $lane, "status": "PASS", "exit_code": 0}] and
    (.artifact_hashes | type == "array") and
    (all(.artifact_hashes[];
      (.path | type == "string") and
      (.sha256 | type == "string" and test("^[0-9a-f]{64}$")))) and
    .signed == false and
    .evidence_class == "DIAGNOSTIC_ONLY" and
    (keys | sort) == ([
      "artifact_hashes", "clean", "commands", "commit_oid",
      "evidence_class", "outcomes", "repository", "schema_version",
      "signed", "tool_versions", "tree_oid"
    ] | sort)
  ' "$observation" >/dev/null; then
    refuse CI_OBSERVATION_INVALID "$lane" || true
    status=1
    continue
  fi

  expected_artifact=''
  case "$lane" in
    fast) expected_artifact='.ci-artifacts/junit/fast.xml' ;;
    contract) expected_artifact='.ci-artifacts/junit/contract.xml' ;;
  esac
  actual_hashes="$(jq -r '.artifact_hashes | length' "$observation")"
  expected_hashes=0
  [[ -z "$expected_artifact" ]] || expected_hashes=1
  if [[ "$actual_hashes" -ne "$expected_hashes" ]]; then
    refuse CI_ARTIFACT_COUNT_INVALID "$lane=$actual_hashes expected=$expected_hashes" || true
    status=1
    continue
  fi
  if [[ -n "$expected_artifact" ]] &&
     [[ "$(jq -r '.artifact_hashes[0].path' "$observation")" != "$expected_artifact" ]]; then
    refuse CI_ARTIFACT_PATH_INVALID "$lane" || true
    status=1
    continue
  fi

  while IFS=$'\t' read -r relative expected_hash; do
    [[ -n "$relative" ]] || continue
    artifact="$artifact_root/${relative#.ci-artifacts/}"
    if [[ ! -f "$artifact" || -L "$artifact" ]]; then
      refuse CI_ARTIFACT_MISSING "$relative" || true
      status=1
      continue
    fi
    actual_hash="$(sha256_file "$artifact")"
    if [[ "$actual_hash" != "$expected_hash" ]]; then
      refuse CI_ARTIFACT_HASH_MISMATCH "$relative" || true
      status=1
    fi
  done < <(jq -r '.artifact_hashes[] | [.path, .sha256] | @tsv' "$observation")
done

expected_files="$(mktemp)"
actual_files="$(mktemp)"
trap 'rm -f -- "$expected_files" "$actual_files"' EXIT
printf '%s\n' \
  junit/contract.xml \
  junit/fast.xml \
  observations/contract.json \
  observations/docs.json \
  observations/fast.json \
  observations/lint.json \
  observations/preflight.json \
  observations/security.json \
  >"$expected_files"
find "$artifact_root" -mindepth 1 \( -type f -o -type l \) -printf '%P\n' | sort -u >"$actual_files"
if ! cmp -s "$expected_files" "$actual_files"; then
  diff -u "$expected_files" "$actual_files" >&2 || true
  refuse CI_ARTIFACT_INVENTORY_INVALID "$artifact_root" || true
  status=1
fi

[[ "$status" -eq 0 ]] || exit 1
log "CI / required: six jobs bind clean observations to $EXPECTED_COMMIT^{tree}"
