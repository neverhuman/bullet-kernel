#!/usr/bin/env bash
# Hostile/static guardrails for the boundary-addressability chaos wrapper.
set -euo pipefail

# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

release_refusal_only() {
  local release_bin="${BULLET_TRANSACTION_OFFLINE_RELEASE_BIN:-}"
  local release_sha="${BULLET_TRANSACTION_OFFLINE_RELEASE_SHA256:-}"
  local test_root cleanup code expected selector selector_env selector_value case_name stdout stderr
  [[ "$release_bin" == /* && -f "$release_bin" && -x "$release_bin" \
    && "$(realpath -e -- "$release_bin")" == "$release_bin" ]] \
    || { refuse OFFLINE_CHAOS_RELEASE_SUBJECT_INVALID "$release_bin"; return 1; }
  [[ "$release_sha" =~ ^[0-9a-f]{64}$ && "$(sha256_file "$release_bin")" == "$release_sha" ]] \
    || { refuse OFFLINE_CHAOS_RELEASE_DIGEST_MISMATCH "$release_bin"; return 1; }
  test_root="$(mktemp -d)"
  printf -v cleanup 'rm -rf -- %q' "$test_root"
  # shellcheck disable=SC2064 # Freeze the quoted private path while the local exists.
  trap "$cleanup" EXIT
  mkdir -m 0700 -- "$test_root/bin"
  # shellcheck disable=SC2016 # The generated cargo stub must expand this at its own runtime, not here.
  printf '%s\n' '#!/usr/bin/env bash' ': >"${OFFLINE_CHAOS_TEST_CARGO_MARKER:?}"' 'exit 97' \
    >"$test_root/bin/cargo"
  chmod 0700 "$test_root/bin/cargo"
  expected='bullet-transaction-offline: CHAOS_DEBUG_ONLY_REFUSED: boundary addressability is debug-component-only'
  for selector in \
    boundary:provider-completion \
    fault:runner-startup:death \
    fault:verifier-handoff:timeout; do
    selector_env=BULLET_TRANSACTION_OFFLINE_CHAOS
    selector_value="${selector#boundary:}"
    if [[ "$selector" == fault:* ]]; then
      selector_env=BULLET_TRANSACTION_OFFLINE_FAULT_CELL
      selector_value="${selector#fault:}"
    fi
    case_name="${selector//:/-}"
    stdout="$test_root/$case_name.stdout"
    stderr="$test_root/$case_name.stderr"
    set +e
    env -i \
      PATH="$test_root/bin:/usr/bin:/bin" \
      LC_ALL=C TZ=UTC \
      "$selector_env=$selector_value" \
      BULLET_DATA_DIR="$test_root/data" \
      TRANSACTION_OFFLINE_RECEIPT="$test_root/receipt.json" \
      TRANSACTION_OFFLINE_ARTIFACT_ROOT="$test_root/artifacts" \
      OFFLINE_CHAOS_TEST_CARGO_MARKER="$test_root/cargo-called" \
      "$release_bin" >"$stdout" 2>"$stderr"
    code=$?
    set -e
    [[ "$code" -eq 1 ]] \
      || { refuse OFFLINE_CHAOS_RELEASE_EXIT_INVALID "$selector returned $code"; return 1; }
    [[ ! -s "$stdout" && "$(cat "$stderr")" == "$expected" \
      && "$(wc -l <"$stderr")" -eq 1 ]] \
      || { refuse OFFLINE_CHAOS_RELEASE_REASON_INVALID "$stderr"; return 1; }
    for absent in data artifacts receipt.json cargo-called; do
      [[ ! -e "$test_root/$absent" && ! -L "$test_root/$absent" ]] \
        || { refuse OFFLINE_CHAOS_RELEASE_SIDE_EFFECT "$selector:$absent"; return 1; }
    done
    [[ "$(sha256_file "$release_bin")" == "$release_sha" ]] \
      || { refuse OFFLINE_CHAOS_RELEASE_SUBJECT_DRIFT "$release_bin"; return 1; }
  done
  log "TEST_ONLY release boundary and process-fault selections refused before mutation"
}

debug_selection_refusal_only() {
  local debug_bin="${BULLET_TRANSACTION_OFFLINE_DEBUG_BIN:-}"
  local debug_sha="${BULLET_TRANSACTION_OFFLINE_DEBUG_SHA256:-}"
  local test_root cleanup case_name expected code stdout stderr
  local -a selection_env=()
  [[ "$debug_bin" == /* && -f "$debug_bin" && -x "$debug_bin" \
    && "$(realpath -e -- "$debug_bin")" == "$debug_bin" ]] \
    || { refuse OFFLINE_CHAOS_DEBUG_SUBJECT_INVALID "$debug_bin"; return 1; }
  [[ "$debug_sha" =~ ^[0-9a-f]{64}$ && "$(sha256_file "$debug_bin")" == "$debug_sha" ]] \
    || { refuse OFFLINE_CHAOS_DEBUG_DIGEST_MISMATCH "$debug_bin"; return 1; }
  test_root="$(mktemp -d)"
  printf -v cleanup 'rm -rf -- %q' "$test_root"
  # shellcheck disable=SC2064 # Freeze the quoted private path while the local exists.
  trap "$cleanup" EXIT
  mkdir -m 0700 -- "$test_root/bin"
  # shellcheck disable=SC2016 # The generated cargo stub must expand this at its own runtime, not here.
  printf '%s\n' '#!/usr/bin/env bash' ': >"${OFFLINE_CHAOS_TEST_CARGO_MARKER:?}"' 'exit 97' \
    >"$test_root/bin/cargo"
  chmod 0700 "$test_root/bin/cargo"
  for case_name in invalid-fault dual-selection; do
    if [[ "$case_name" == invalid-fault ]]; then
      selection_env=(BULLET_TRANSACTION_OFFLINE_FAULT_CELL=runner-startup:process-death)
      expected='bullet-transaction-offline: CHAOS_FAULT_CELL_INVALID: expected exactly one of runner-startup:death,runner-startup:timeout,verifier-handoff:death,verifier-handoff:timeout'
    else
      selection_env=(
        BULLET_TRANSACTION_OFFLINE_CHAOS=grant-persistence
        BULLET_TRANSACTION_OFFLINE_FAULT_CELL=runner-startup:death
      )
      expected='bullet-transaction-offline: CHAOS_SELECTION_CONFLICT: boundary addressability and process fault selectors are mutually exclusive'
    fi
    stdout="$test_root/$case_name.stdout"
    stderr="$test_root/$case_name.stderr"
    set +e
    env -i \
      PATH="$test_root/bin:/usr/bin:/bin" LC_ALL=C TZ=UTC \
      "${selection_env[@]}" \
      BULLET_DATA_DIR="$test_root/data" \
      TRANSACTION_OFFLINE_RECEIPT="$test_root/receipt.json" \
      TRANSACTION_OFFLINE_ARTIFACT_ROOT="$test_root/artifacts" \
      OFFLINE_CHAOS_TEST_CARGO_MARKER="$test_root/cargo-called" \
      "$debug_bin" >"$stdout" 2>"$stderr"
    code=$?
    set -e
    [[ "$code" -eq 1 && ! -s "$stdout" && "$(cat "$stderr")" == "$expected" \
      && "$(wc -l <"$stderr")" -eq 1 ]] \
      || { refuse OFFLINE_CHAOS_DEBUG_SELECTION_INVALID "$case_name code=$code"; return 1; }
    for absent in data artifacts receipt.json cargo-called; do
      [[ ! -e "$test_root/$absent" && ! -L "$test_root/$absent" ]] \
        || { refuse OFFLINE_CHAOS_DEBUG_SELECTION_SIDE_EFFECT "$case_name:$absent"; return 1; }
    done
    [[ "$(sha256_file "$debug_bin")" == "$debug_sha" ]] \
      || { refuse OFFLINE_CHAOS_DEBUG_SUBJECT_DRIFT "$debug_bin"; return 1; }
  done
  log "TEST_ONLY debug malformed and dual process-fault selections refused before mutation"
}

if [[ "${1:-}" == --release-refusal-only ]]; then
  release_refusal_only
  exit
fi
if [[ "${1:-}" == --debug-selection-refusal-only ]]; then
  debug_selection_refusal_only
  exit
fi

test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT
mkdir -m 0700 -- "$test_root/bin"

# The generated shim expands the marker when it runs, not while it is written.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  ': >"${OFFLINE_CHAOS_TEST_CARGO_MARKER:?}"' \
  'exit 97' \
  >"$test_root/bin/cargo"
chmod 0700 "$test_root/bin/cargo"

set +e
env -u CARGO_TARGET_DIR -u BULLET_CI_CARGO_TARGET_DIR -u BULLET_CI_CARGO_TARGET_ID \
  -u BULLET_GITD_BIN -u BULLET_GITD_SHA256 \
  PATH="$test_root/bin:/usr/bin:/bin" \
  OFFLINE_CHAOS_TEST_CARGO_MARKER="$test_root/cargo-called" \
  /usr/bin/bash ops/ci/proof-transaction-offline-chaos.sh \
  >"$test_root/missing-gitd.stdout" 2>"$test_root/missing-gitd.stderr"
code=$?
set -e
[[ "$code" -eq 1 ]] \
  || { refuse OFFLINE_CHAOS_HOSTILE_EXIT "missing gitd returned $code"; exit 1; }
rg -Fq '[ci] BULLET_GITD_BIN_REQUIRED:' "$test_root/missing-gitd.stderr" \
  || { cat "$test_root/missing-gitd.stderr" >&2; refuse OFFLINE_CHAOS_HOSTILE_REASON missing-gitd; exit 1; }
[[ ! -e "$test_root/cargo-called" ]] \
  || { refuse OFFLINE_CHAOS_PREBUILD_GUARD_FAILED "missing Gitd invoked Cargo"; exit 1; }

wrapper=ops/ci/proof-transaction-offline-chaos.sh
chaos=apps/bullet/src/bin/transaction_offline/chaos.rs
provider=apps/bullet/src/bin/transaction_offline/sim_provider.rs
supervisor=apps/bullet/src/bin/transaction_offline/verifier_process.rs
runner=apps/bullet/src/bin/transaction_offline/runner_probe.rs
observation=apps/bullet/src/bin/transaction_offline/process_observation.rs
child=apps/bullet-runner/src/bin/bullet-command-worker/child.rs
app=apps/bullet/src/bin/transaction_offline/single_candidate_app.rs
readonly expected=(
  grant-persistence
  runner-startup
  workspace-open
  provider-completion
  patch-apply
  checkpoint
  candidate-preparation
  verifier-handoff
  candidate-delivery
  check-publication
  integration
  observation-cleanup
)
readonly expected_faults=(
  runner-startup:death
  runner-startup:timeout
  verifier-handoff:death
  verifier-handoff:timeout
)
for label in "${expected[@]}"; do
  rg -Fq "$label" "$wrapper" \
    || { refuse OFFLINE_CHAOS_LABEL_MISSING "$wrapper:$label"; exit 1; }
  rg -Fq "\"$label\"" "$chaos" \
    || { refuse OFFLINE_CHAOS_LABEL_MISSING "$chaos:$label"; exit 1; }
done
[[ "${#expected[@]}" -eq 12 ]] \
  || { refuse OFFLINE_CHAOS_LABEL_COUNT_DRIFT expected-array; exit 1; }
wrapper_count="$(awk '
  /^readonly CHAOS_BOUNDARIES=\($/ { inside = 1; next }
  inside && /^\)$/ { inside = 0 }
  inside && /^[[:space:]]+[a-z-]+$/ { count++ }
  END { print count + 0 }
' "$wrapper")"
[[ "$wrapper_count" -eq 12 ]] \
  || { refuse OFFLINE_CHAOS_LABEL_COUNT_DRIFT "$wrapper"; exit 1; }
for cell in "${expected_faults[@]}"; do
  rg -Fq "$cell" "$wrapper" "$chaos" \
    || { refuse OFFLINE_CHAOS_FAULT_CELL_MISSING "$cell"; exit 1; }
done
fault_count="$(awk '
  /^readonly FAULT_CELLS=\($/ { inside = 1; next }
  inside && /^\)$/ { inside = 0 }
  inside && /^[[:space:]]+[a-z-]+:(death|timeout)$/ { count++ }
  END { print count + 0 }
' "$wrapper")"
[[ "$fault_count" -eq 4 ]] \
  || { refuse OFFLINE_CHAOS_FAULT_CELL_COUNT_DRIFT "$wrapper"; exit 1; }
rg -Fq 'CHAOS_DEBUG_ONLY_REFUSED' "$chaos" \
  || { refuse OFFLINE_CHAOS_RELEASE_REFUSAL_MISSING "$chaos"; exit 1; }
rg -Fq '#[cfg(not(debug_assertions))]' "$chaos" \
  || { refuse OFFLINE_CHAOS_RELEASE_CFG_MISSING "$chaos"; exit 1; }
for lifecycle in \
  'admit_product_runner_transcript' \
  'read_protected_transcript' \
  'decode_terminal_proposal' \
  'Some("turn.completed")' \
  'PatchProposal::from_value' \
  'write_all(&raw)' \
  'sync_all()'; do
  rg -Fq "$lifecycle" "$provider" \
    || { refuse OFFLINE_CHAOS_PROVIDER_LIFECYCLE_MISSING "$provider:$lifecycle"; exit 1; }
done
for binding in \
  'proposal.producing_attempt_id != expected_attempt_id' \
  'proposal.gate_ids != [bullet_domain::REPOSITORY_GATE_ID]' \
  'decode_strict_json' \
  'SIM_PROVIDER_SUBJECT_MISMATCH' \
  'SIM_PROVIDER_RAW_ARTIFACT_INVALID'; do
  rg -Fq "$binding" "$provider" \
    || { refuse OFFLINE_CHAOS_PROVIDER_BINDING_MISSING "$provider:$binding"; exit 1; }
done
admission_line="$(rg -n -m 1 'chaos::admit_debug_selection' "$app" | awk -F: '{ print $1 }')"
for mutation_start in 'ArtifactCustody::create' 'SqliteLedger::open' 'spawn_durable_farmd'; do
  mutation_line="$(rg -n -m 1 "$mutation_start" "$app" | awk -F: '{ print $1 }')"
  [[ "$admission_line" =~ ^[0-9]+$ && "$mutation_line" =~ ^[0-9]+$ \
    && "$admission_line" -lt "$mutation_line" ]] \
    || { refuse OFFLINE_CHAOS_RELEASE_ORDER_INVALID "$mutation_start"; exit 1; }
done
rg -Fq '.env_clear()' "$child" \
  || { refuse OFFLINE_CHAOS_PUBLIC_ENV_CLEAR_MISSING "$child"; exit 1; }
! rg -Fq 'BULLET_TRANSACTION_OFFLINE_CHAOS' "$child" \
  || { refuse OFFLINE_CHAOS_PUBLIC_ENV_ADMITTED "$child"; exit 1; }
! rg -Fq 'BULLET_TRANSACTION_OFFLINE_FAULT_CELL' "$child" \
  || { refuse OFFLINE_CHAOS_PUBLIC_ENV_ADMITTED "$child"; exit 1; }
# shellcheck disable=SC2016 # These are literal source substrings searched for in the app, not expansions.
for predicate in \
  'CHAOS_BOUNDARY_INJECTED' \
  'OFFLINE_CHAOS_RECEIPT_CREATED' \
  'OFFLINE_CHAOS_ELIGIBILITY_PROMOTION' \
  'OFFLINE_CHAOS_PROCESS_SURVIVED' \
  'subject_processes' \
  '/proc/$pid/exe' \
  'bullet-gitd-admitted' \
  'bullet-verifier-fixture-admitted' \
  'CHAOS_FAULT_INJECTED' \
  'CHAOS_SELECTION_CONFLICT' \
  'BULLET_TRANSACTION_OFFLINE_FAULT_CELL' \
  'Signal::KILL' \
  'Signal::STOP' \
  'wait_with_output_for' \
  'assert_fault_process_groups_reaped' \
  'assert_authority_cleanup'; do
  rg -Fq "$predicate" "$wrapper" "$chaos" "$supervisor" "$runner" "$observation" \
    || { refuse OFFLINE_CHAOS_GUARD_MISSING "$predicate"; exit 1; }
done

log "offline boundary-addressability chaos guardrails passed"
