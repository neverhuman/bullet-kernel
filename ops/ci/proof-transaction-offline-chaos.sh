#!/usr/bin/env bash
# Boundary-addressability diagnostics for the offline component bridge. This is
# not a fault-complete campaign and emits no receipt.
set -euo pipefail
umask 077

# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

readonly CHAOS_ENV=BULLET_TRANSACTION_OFFLINE_CHAOS
readonly FAULT_CELL_ENV=BULLET_TRANSACTION_OFFLINE_FAULT_CELL
readonly CHAOS_CLASSIFICATION='COMPONENT_PROOF signing_trust=UNSIGNED_FIXTURE transaction=false release=false'
readonly CHAOS_BOUNDARIES=(
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
readonly FAULT_CELLS=(
  runner-startup:death
  runner-startup:timeout
  verifier-handoff:death
  verifier-handoff:timeout
)

for tool in awk cargo jq mktemp pgrep readlink realpath rg sha256sum sqlite3 stat uname; do
  require_tool "$tool" || exit 1
done
if [[ "$(uname -s)" != Linux ]]; then
  refuse OFFLINE_CHAOS_REQUIRES_LINUX \
    "sealed verifier execution and process cleanup checks require Linux"
  exit 1
fi
if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  refuse CARGO_TARGET_DIR_UNSUPPORTED \
    "unset CARGO_TARGET_DIR so every spawned local binary has one exact target path"
  exit 1
fi
if [[ -z "${BULLET_GITD_BIN:-}" ]]; then
  refuse BULLET_GITD_BIN_REQUIRED \
    "set BULLET_GITD_BIN to the exact absolute production daemon path"
  exit 1
fi
if [[ "$BULLET_GITD_BIN" != /* ]]; then
  refuse BULLET_GITD_BIN_NOT_ABSOLUTE "$BULLET_GITD_BIN"
  exit 1
fi
if [[ ! -f "$BULLET_GITD_BIN" || ! -x "$BULLET_GITD_BIN" ]]; then
  refuse BULLET_GITD_BIN_NOT_EXECUTABLE "$BULLET_GITD_BIN"
  exit 1
fi
gitd_resolved="$(realpath -e -- "$BULLET_GITD_BIN")" || {
  refuse BULLET_GITD_BIN_UNRESOLVED "$BULLET_GITD_BIN"
  exit 1
}
if [[ "$gitd_resolved" != "$BULLET_GITD_BIN" ]]; then
  refuse BULLET_GITD_BIN_NOT_CANONICAL "expected $gitd_resolved"
  exit 1
fi
if [[ ! "${BULLET_GITD_SHA256:-}" =~ ^[0-9a-f]{64}$ ]]; then
  refuse BULLET_GITD_SHA256_REQUIRED \
    "set BULLET_GITD_SHA256 to the exact lowercase production daemon digest"
  exit 1
fi
if [[ "$(sha256_file "$BULLET_GITD_BIN")" != "$BULLET_GITD_SHA256" ]]; then
  refuse BULLET_GITD_DIGEST_MISMATCH before-build
  exit 1
fi

log "building exact offline component subjects for boundary addressability"
cargo build --offline --locked -p bullet-farmd --bin bullet-farmd
cargo build --offline --locked -p bullet-runner --bin bullet-runner
cargo build --offline --locked -p bullet --bin transaction_offline
cargo build --offline --locked -p bullet-verifier --bin bullet-verifier-fixture \
  --features fixture-executor
cargo build --offline --locked --release -p bullet --bin transaction_offline

farmd_bin="$(realpath -e -- target/debug/bullet-farmd)"
runner_bin="$(realpath -e -- target/debug/bullet-runner)"
offline_bin="$(realpath -e -- target/debug/transaction_offline)"
verifier_bin="$(realpath -e -- target/debug/bullet-verifier-fixture)"
release_offline_bin="$(realpath -e -- target/release/transaction_offline)"
declare -A subject_sha=(
  ["$farmd_bin"]="$(sha256_file "$farmd_bin")"
  ["$runner_bin"]="$(sha256_file "$runner_bin")"
  ["$offline_bin"]="$(sha256_file "$offline_bin")"
  ["$verifier_bin"]="$(sha256_file "$verifier_bin")"
  ["$BULLET_GITD_BIN"]="$BULLET_GITD_SHA256"
)

env \
  BULLET_TRANSACTION_OFFLINE_RELEASE_BIN="$release_offline_bin" \
  BULLET_TRANSACTION_OFFLINE_RELEASE_SHA256="$(sha256_file "$release_offline_bin")" \
  bash ops/ci/proof-transaction-offline-chaos-test.sh --release-refusal-only
env \
  BULLET_TRANSACTION_OFFLINE_DEBUG_BIN="$offline_bin" \
  BULLET_TRANSACTION_OFFLINE_DEBUG_SHA256="$(sha256_file "$offline_bin")" \
  bash ops/ci/proof-transaction-offline-chaos-test.sh --debug-selection-refusal-only

assert_subjects_unchanged() {
  local subject
  for subject in "${!subject_sha[@]}"; do
    [[ -f "$subject" && -x "$subject" && "$(sha256_file "$subject")" == "${subject_sha[$subject]}" ]] \
      || { refuse OFFLINE_CHAOS_SUBJECT_DRIFT "$subject"; return 1; }
  done
}

assert_no_promotion() {
  local root="$1"
  if rg -n \
    'TRANSACTION_PROOF|"transaction_gate_eligible"[[:space:]]*:[[:space:]]*true|"independent_evidence_eligible"[[:space:]]*:[[:space:]]*true|"release_gate_eligible"[[:space:]]*:[[:space:]]*true' \
    "$root" >/dev/null; then
    rg -n \
      'TRANSACTION_PROOF|"transaction_gate_eligible"[[:space:]]*:[[:space:]]*true|"independent_evidence_eligible"[[:space:]]*:[[:space:]]*true|"release_gate_eligible"[[:space:]]*:[[:space:]]*true' \
      "$root" >&2 || true
    refuse OFFLINE_CHAOS_ELIGIBILITY_PROMOTION "$root"
    return 1
  fi
}

assert_custody() {
  local root="$1"
  local artifact_root="$root/artifacts"
  local data_root="$root/data"
  local ledger="$data_root/ledger.sqlite"
  [[ ! -L "$root" && "$(stat -Lc '%u:%a:%F' -- "$root")" == "$(id -u):700:directory" ]] \
    || { refuse OFFLINE_CHAOS_ROOT_CUSTODY "$root"; return 1; }
  if [[ -e "$artifact_root" || -L "$artifact_root" ]]; then
    [[ ! -L "$artifact_root" && "$(stat -Lc '%u:%a:%F' -- "$artifact_root")" == "$(id -u):700:directory" ]] \
      || { refuse OFFLINE_CHAOS_ARTIFACT_CUSTODY "$artifact_root"; return 1; }
  fi
  if [[ -e "$data_root" || -L "$data_root" ]]; then
    [[ ! -L "$data_root" && "$(stat -Lc '%u:%a:%F' -- "$data_root")" == "$(id -u):700:directory" ]] \
      || { refuse OFFLINE_CHAOS_DATA_CUSTODY "$data_root"; return 1; }
  fi
  if [[ -e "$ledger" || -L "$ledger" ]]; then
    [[ ! -L "$ledger" && "$(stat -Lc '%u:%a:%F' -- "$ledger")" == "$(id -u):600:regular file" ]] \
      || { refuse OFFLINE_CHAOS_LEDGER_CUSTODY "$ledger"; return 1; }
  fi
}

subject_digest_is_admitted() {
  local expected
  for expected in "${subject_sha[@]}"; do
    [[ "$1" == "$expected" ]] && return 0
  done
  return 1
}

subject_name_for_digest() {
  local subject
  for subject in "${!subject_sha[@]}"; do
    [[ "${subject_sha[$subject]}" == "$1" ]] && { printf '%s\n' "$subject"; return 0; }
  done
  return 1
}

subject_processes() {
  local run_pid="$1"
  local ledger="$2"
  local exe link pid process_uid stat_fields parent process_group start_time digest subject children existing
  local cursor=0
  local -a pending=("$run_pid") child_pids=()
  declare -A visited=()
  while [[ "$cursor" -lt "${#pending[@]}" ]]; do
    pid="${pending[$cursor]}"
    cursor=$((cursor + 1))
    [[ "$pid" =~ ^[0-9]+$ && -z "${visited[$pid]:-}" ]] || continue
    visited["$pid"]=1
    children="/proc/$pid/task/$pid/children"
    if [[ -r "$children" ]]; then
      child_pids=()
      read -r -a child_pids 2>/dev/null <"$children" || true
      pending+=("${child_pids[@]}")
    fi
    [[ -r "/proc/$pid/status" ]] || continue
    process_uid="$(awk '/^Uid:/ { print $2; exit }' "/proc/$pid/status" 2>/dev/null)" || continue
    [[ "$process_uid" == "$(id -u)" ]] || continue
    exe="/proc/$pid/exe"
    link="$(readlink -- "$exe" 2>/dev/null)" || continue
    case "$link" in
      "$farmd_bin"|"$runner_bin"|"$offline_bin"|"$verifier_bin"|"$BULLET_GITD_BIN"|\
        *bullet-gitd-admitted*|*bullet-verifier-fixture-admitted*) ;;
      *) continue ;;
    esac
    stat_fields="$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null)" || continue
    parent="$(awk '{ print $2 }' <<<"$stat_fields")"
    process_group="$(awk '{ print $3 }' <<<"$stat_fields")"
    start_time="$(awk '{ print $20 }' <<<"$stat_fields")"
    [[ "$parent" =~ ^[0-9]+$ && "$process_group" =~ ^[0-9]+$ \
      && "$start_time" =~ ^[0-9]+$ ]] || continue
    existing="$(awk -F '\t' -v pid="$pid" -v start="$start_time" \
      '$1 == pid && $2 == start { print; exit }' "$ledger")"
    if [[ -n "$existing" ]]; then
      printf '%s\n' "$existing"
      continue
    fi
    digest="${subject_sha[$link]:-}"
    if [[ -z "$digest" ]]; then
      digest="$(sha256_file "$exe" 2>/dev/null)" || continue
    fi
    subject_digest_is_admitted "$digest" || continue
    subject="$(subject_name_for_digest "$digest")" || continue
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$pid" "$start_time" "$parent" "$process_group" "$subject" "$digest" "$link"
  done
}

monitor_subject_processes() {
  local run_pid="$1"
  local ledger="$2"
  local stop_file="$3"
  local ready_file="$4"
  local record key
  declare -A seen=()
  : >"$ready_file"
  while [[ ! -e "$stop_file" ]]; do
    while IFS= read -r record; do
      [[ -n "$record" ]] || continue
      key="${record%%$'\t'*}:$(awk -F '\t' '{ print $2 ":" $6 }' <<<"$record")"
      [[ -n "${seen[$key]:-}" ]] && continue
      seen["$key"]=1
      printf '%s\n' "$record" >>"$ledger"
    done < <(subject_processes "$run_pid" "$ledger")
    sleep 0.001
  done
}

assert_recorded_subjects_reaped() {
  local root="$1"
  local ledger="$2"
  local boundary="$3"
  local cell="$4"
  local pid start_time parent process_group subject digest link current_start
  [[ ! -L "$ledger" && -f "$ledger" \
    && "$(stat -Lc '%u:%a' -- "$ledger")" == "$(id -u):600" ]] \
    || { refuse OFFLINE_CHAOS_PROCESS_LEDGER_CUSTODY "$ledger"; return 1; }
  awk -F '\t' -v digest="${subject_sha[$offline_bin]}" '$6 == digest { found = 1 } END { exit !found }' "$ledger" \
    || { refuse OFFLINE_CHAOS_BRIDGE_NOT_OBSERVED "$ledger"; return 1; }
  awk -F '\t' -v digest="${subject_sha[$farmd_bin]}" '$6 == digest { found = 1 } END { exit !found }' "$ledger" \
    || { refuse OFFLINE_CHAOS_FARMD_NOT_OBSERVED "$ledger"; return 1; }
  case "$cell" in
    grant-persistence|runner-startup|runner-startup:*) ;;
    *)
    awk -F '\t' -v digest="$BULLET_GITD_SHA256" '$6 == digest { found = 1 } END { exit !found }' "$ledger" \
      || { refuse OFFLINE_CHAOS_GITD_NOT_OBSERVED "$ledger"; return 1; }
      ;;
  esac
  case "$cell" in
    candidate-delivery|check-publication|integration|observation-cleanup|verifier-handoff:*)
      awk -F '\t' -v digest="${subject_sha[$verifier_bin]}" \
        '$6 == digest { found = 1 } END { exit !found }' "$ledger" \
        || { refuse OFFLINE_CHAOS_VERIFIER_NOT_OBSERVED "$ledger"; return 1; }
      ;;
  esac
  case "$cell" in
    runner-startup:*)
      awk -F '\t' -v digest="${subject_sha[$runner_bin]}" \
        '$5 == "bullet-runner-admitted" && $6 == digest { found = 1 } END { exit !found }' "$ledger" \
        || { refuse OFFLINE_CHAOS_RUNNER_NOT_OBSERVED "$ledger"; return 1; }
      ;;
    verifier-handoff:*)
      awk -F '\t' -v digest="${subject_sha[$verifier_bin]}" \
        '$5 == "sealed-verifier-fixture" && $6 == digest { found = 1 } END { exit !found }' "$ledger" \
        || { refuse OFFLINE_CHAOS_VERIFIER_NOT_OBSERVED "$ledger"; return 1; }
      ;;
  esac
  while IFS=$'\t' read -r pid start_time parent process_group subject digest link; do
    [[ -n "$pid" ]] || continue
    if [[ -r "/proc/$pid/stat" ]]; then
      current_start="$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | awk '{ print $20 }')" || true
      if [[ "$current_start" == "$start_time" ]]; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
          "$pid" "$start_time" "$parent" "$process_group" "$subject" "$digest" "$link" \
          >"$root/surviving-processes.txt"
        cat "$root/surviving-processes.txt" >&2
        refuse OFFLINE_CHAOS_PROCESS_SURVIVED "$subject"
        return 1
      fi
    fi
  done <"$ledger"
}

assert_fault_process_groups_reaped() {
  local root="$1"
  local ledger="$2"
  local pid start_time parent process_group subject digest link candidate stat_fields candidate_group candidate_uid
  while IFS=$'\t' read -r pid start_time parent process_group subject digest link; do
    case "$subject" in
      bullet-runner-admitted|sealed-verifier-fixture) ;;
      *) continue ;;
    esac
    [[ "$pid" == "$process_group" ]] \
      || { refuse OFFLINE_CHAOS_PROCESS_GROUP_INVALID "$subject pid=$pid pgid=$process_group"; return 1; }
    for stat_path in /proc/[0-9]*/stat; do
      [[ -r "$stat_path" ]] || continue
      candidate="${stat_path#/proc/}"
      candidate="${candidate%/stat}"
      candidate_uid="$(awk '/^Uid:/ { print $2; exit }' "/proc/$candidate/status" 2>/dev/null)" || continue
      [[ "$candidate_uid" == "$(id -u)" ]] || continue
      stat_fields="$(sed 's/.*) //' "$stat_path" 2>/dev/null)" || continue
      candidate_group="$(awk '{ print $3 }' <<<"$stat_fields")"
      if [[ "$candidate_group" == "$process_group" ]]; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
          "$pid" "$start_time" "$parent" "$process_group" "$subject" "$digest" "$link" \
          >"$root/surviving-process-groups.txt"
        refuse OFFLINE_CHAOS_PROCESS_GROUP_SURVIVED "$subject pgid=$process_group member=$candidate"
        return 1
      fi
    done
  done <"$ledger"
}

assert_authority_cleanup() {
  local root="$1"
  local ledger="$root/data/ledger.sqlite"
  local active cancelled
  active="$(sqlite3 "$ledger" 'SELECT count(*) FROM active_leases')" \
    || { refuse OFFLINE_CHAOS_RUNNER_LEASE_READBACK_FAILED "$ledger"; return 1; }
  cancelled="$(sqlite3 "$ledger" "SELECT count(*) FROM attempts WHERE state = 'cancelled'")" \
    || { refuse OFFLINE_CHAOS_RUNNER_ATTEMPT_READBACK_FAILED "$ledger"; return 1; }
  [[ "$active" == 0 && "$cancelled" == 1 ]] \
    || { refuse OFFLINE_CHAOS_RUNNER_AUTHORITY_CLEANUP_INVALID \
      "active_leases=$active cancelled_attempts=$cancelled"; return 1; }
}

assert_no_survivors() {
  local root="$1"
  local candidate ancestor
  declare -A ancestor_pids=()
  ancestor=$$
  while [[ "$ancestor" =~ ^[0-9]+$ && "$ancestor" -gt 1 && -r "/proc/$ancestor/status" ]]; do
    ancestor_pids["$ancestor"]=1
    ancestor="$(awk '/^PPid:/ { print $2 }' "/proc/$ancestor/status")"
  done
  while read -r candidate; do
    [[ -z "$candidate" || -n "${ancestor_pids[$candidate]:-}" ]] && continue
    pgrep -a -u "$(id -u)" -f "$root" >"$root/surviving-processes.txt" || true
    cat "$root/surviving-processes.txt" >&2
    refuse OFFLINE_CHAOS_PROCESS_SURVIVED "$root"
    return 1
  done < <(pgrep -u "$(id -u)" -f "$root" || true)
}

assert_subjects_unchanged
for cell in "${CHAOS_BOUNDARIES[@]}" "${FAULT_CELLS[@]}"; do
  boundary="$cell"
  selection_env="$CHAOS_ENV"
  expected_reason="CHAOS_BOUNDARY_INJECTED: $boundary"
  root_label="$boundary"
  if [[ "$cell" == *:* ]]; then
    boundary="${cell%%:*}"
    mode="${cell##*:}"
    selection_env="$FAULT_CELL_ENV"
    expected_reason="CHAOS_FAULT_INJECTED: boundary=$boundary mode=$mode"
    root_label="${cell//:/-}"
  fi
  proof_root="$(mktemp -d "/tmp/bullet-offline-chaos-${root_label}.XXXXXXXX")"
  chmod 0700 "$proof_root"
  receipt="$proof_root/COMPONENT_PROOF.receipt.json"
  artifact_root="$proof_root/artifacts"
  stdout="$proof_root/stdout.txt"
  stderr="$proof_root/stderr.txt"
  process_ledger="$proof_root/process-subjects.tsv"
  monitor_stop="$proof_root/process-monitor.stop"
  monitor_ready="$proof_root/process-monitor.ready"
  : >"$process_ledger"

  set +e
  exec 9<"$verifier_bin"
  exec 8>>"$process_ledger"
  env -u CARGO_TARGET_DIR -u BULLET_OFFLINE_PROOF_DIR \
    -u "$CHAOS_ENV" -u "$FAULT_CELL_ENV" \
    PATH=/usr/bin:/bin \
    "$selection_env=$cell" \
    BULLET_FARMD_BIN="$farmd_bin" \
    BULLET_RUNNER_BIN="$runner_bin" \
    BULLET_RUNNER_SHA256="${subject_sha[$runner_bin]}" \
    BULLET_GITD_BIN="$BULLET_GITD_BIN" \
    BULLET_GITD_SHA256="$BULLET_GITD_SHA256" \
    BULLET_KERNEL_AUTHORITY_SERVER_UID="$(id -u)" \
    BULLET_KERNEL_AUTHORITY_SOCKET_GID="$(id -g)" \
    BULLET_DATA_DIR="$proof_root/data" \
    TRANSACTION_OFFLINE_RECEIPT="$receipt" \
    TRANSACTION_OFFLINE_ARTIFACT_ROOT="$artifact_root" \
    BULLET_VERIFIER_FIXTURE_FD=9 \
    BULLET_VERIFIER_FIXTURE_SHA256="${subject_sha[$verifier_bin]}" \
    BULLET_TRANSACTION_OFFLINE_PROCESS_LEDGER_FD=8 \
    /bin/sh -c 'kill -STOP "$$"; exec "$@"' bullet-chaos-start \
      "$offline_bin" >"$stdout" 2>"$stderr" &
  offline_pid=$!
  stopped=false
  for _ in {1..200}; do
    if awk '/^State:/ { exit $2 !~ /^T/ }' "/proc/$offline_pid/status" 2>/dev/null; then
      stopped=true
      break
    fi
    sleep 0.01
  done
  if ! $stopped; then
    kill -KILL "$offline_pid" 2>/dev/null || true
    wait "$offline_pid" 2>/dev/null || true
    exec 8>&-
    exec 9<&-
    set -e
    refuse OFFLINE_CHAOS_START_BARRIER_FAILED "$boundary"
    exit 1
  fi
  monitor_subject_processes "$offline_pid" "$process_ledger" "$monitor_stop" "$monitor_ready" &
  monitor_pid=$!
  monitor_started=false
  for _ in {1..200}; do
    if [[ -f "$monitor_ready" ]]; then
      monitor_started=true
      break
    fi
    sleep 0.01
  done
  if ! $monitor_started; then
    : >"$monitor_stop"
    wait "$monitor_pid" 2>/dev/null || true
    kill -KILL "$offline_pid" 2>/dev/null || true
    wait "$offline_pid" 2>/dev/null || true
    exec 8>&-
    exec 9<&-
    set -e
    refuse OFFLINE_CHAOS_PROCESS_MONITOR_START_FAILED "$boundary"
    exit 1
  fi
  kill -CONT "$offline_pid"
  wait "$offline_pid"
  code=$?
  : >"$monitor_stop"
  wait "$monitor_pid"
  monitor_code=$?
  exec 8>&-
  exec 9<&-
  set -e

  [[ "$monitor_code" -eq 0 ]] \
    || { refuse OFFLINE_CHAOS_PROCESS_MONITOR_FAILED "$boundary returned $monitor_code"; exit 1; }
  [[ "$code" -ne 0 ]] \
    || { refuse OFFLINE_CHAOS_EXIT_INVALID "$boundary produced success"; exit 1; }
  rg -Fq "$expected_reason" "$stderr" \
    || { cat "$stderr" >&2; refuse OFFLINE_CHAOS_REASON_INVALID "$cell"; exit 1; }
  [[ ! -e "$receipt" && ! -L "$receipt" ]] \
    || { refuse OFFLINE_CHAOS_RECEIPT_CREATED "$receipt"; exit 1; }
  assert_no_promotion "$proof_root"
  assert_custody "$proof_root"
  assert_subjects_unchanged
  assert_recorded_subjects_reaped "$proof_root" "$process_ledger" "$boundary" "$cell"
  assert_authority_cleanup "$proof_root"
  if [[ "$cell" == *:* ]]; then
    assert_fault_process_groups_reaped "$proof_root" "$process_ledger"
  fi
  if [[ "$cell" == verifier-handoff:* ]]; then
    [[ -d "$artifact_root/preserve/generation/repo" \
      && ! -e "$artifact_root/effects/target.git" && ! -L "$artifact_root/effects/target.git" ]] \
      || { refuse OFFLINE_CHAOS_VERIFIER_FAULT_ORDER_INVALID "$cell"; exit 1; }
  fi
  if [[ "$cell" == runner-startup:* ]]; then
    [[ ! -e "$artifact_root/preserve" && ! -L "$artifact_root/preserve" \
      && ! -e "$artifact_root/effects" && ! -L "$artifact_root/effects" ]] \
      || { refuse OFFLINE_CHAOS_RUNNER_FAULT_ORDER_INVALID "$cell"; exit 1; }
  fi
  assert_no_survivors "$proof_root"
  if [[ "$cell" == *:* ]]; then
    log "process fault exercised: $cell root=$proof_root"
  else
    log "chaos boundary addressed: $boundary root=$proof_root"
  fi
done

log "offline boundary-addressability chaos diagnostics passed"
log "classification=$CHAOS_CLASSIFICATION boundary_addressability=12 process_fault_cells=4 fault_modes_complete=false"
