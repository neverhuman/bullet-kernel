#!/usr/bin/env bash
# Two distinct selected-Variant simulator lanes. This emits unsigned component
# evidence only; it cannot clear a transaction, live, release, or profile gate.
set -euo pipefail
umask 077
export LC_ALL=C
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
for tool in b3sum cargo find git jq realpath sha256sum sort sqlite3 stat uname xxd; do
  require_tool "$tool" || exit 1
done
le64() {
  local value="$1" offset octal
  for offset in 0 8 16 24 32 40 48 56; do
    printf -v octal '\\%03o' "$(((value >> offset) & 255))"
    printf '%b' "$octal"
  done
}
framed_blake3() {
  local domain="$1" bytes="$2"
  { printf '%s\0' bullet-wire.v1; le64 "${#domain}"; printf %s "$domain"
    le64 "${#bytes}"; printf %s "$bytes"; } | b3sum --no-names
}
[[ "$(uname -s)" == Linux ]] \
  || { refuse SYNTHETIC_DOGFOOD_LINUX_REQUIRED "Unix peer identity requires Linux"; exit 1; }
[[ -z "${CARGO_TARGET_DIR:-}" ]] \
  || { refuse CARGO_TARGET_DIR_UNSUPPORTED "unset CARGO_TARGET_DIR"; exit 1; }
credential_names=(
  ANTHROPIC_API_KEY OPENAI_API_KEY GH_TOKEN GITHUB_TOKEN GITLAB_TOKEN SSH_AUTH_SOCK
  AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN GOOGLE_APPLICATION_CREDENTIALS
  JERYU_TOKEN BULLET_CANARY_SECRET GIT_ASKPASS GIT_CONFIG_GLOBAL GIT_DIR GIT_WORK_TREE
)
for name in "${credential_names[@]}"; do
  [[ -z "${!name:-}" ]] \
    || { refuse SYNTHETIC_DOGFOOD_CREDENTIAL_REFUSED "$name"; exit 1; }
done
gitd_bin="${BULLET_GITD_BIN:-}"
gitd_digest="${BULLET_GITD_SHA256:-}"
[[ "$gitd_bin" == /* && -f "$gitd_bin" && -x "$gitd_bin" ]] \
  || { refuse SYNTHETIC_DOGFOOD_GITD_REQUIRED "exact absolute executable required"; exit 1; }
[[ "$(realpath -e -- "$gitd_bin")" == "$gitd_bin" ]] \
  || { refuse SYNTHETIC_DOGFOOD_GITD_NOT_CANONICAL "$gitd_bin"; exit 1; }
[[ "$gitd_digest" =~ ^[0-9a-f]{64}$ ]] \
  || { refuse SYNTHETIC_DOGFOOD_GITD_DIGEST_REQUIRED "lowercase SHA-256 required"; exit 1; }
[[ "$(sha256_file "$gitd_bin")" == "$gitd_digest" ]] \
  || { refuse SYNTHETIC_DOGFOOD_GITD_DIGEST_MISMATCH before-build; exit 1; }
log "building selected-Variant component subjects from locked offline dependencies"
cargo build --offline --locked -p bullet-farmd --features test-seams --bin bullet-farmd
cargo build --offline --locked -p bullet --features synthetic-dogfood --bin transaction_offline
cargo build --offline --locked -p bullet-verifier --bin bullet-verifier-fixture \
  --features fixture-executor
farmd_bin="$(realpath -e -- target/debug/bullet-farmd)"
dogfood_bin="$(realpath -e -- target/debug/transaction_offline)"
verifier_bin="$(realpath -e -- target/debug/bullet-verifier-fixture)"
farmd_digest="$(sha256_file "$farmd_bin")"
dogfood_digest="$(sha256_file "$dogfood_bin")"
verifier_digest="$(sha256_file "$verifier_bin")"
[[ -x "$farmd_bin" && -x "$dogfood_bin" && -x "$verifier_bin" ]] \
  || { refuse SYNTHETIC_DOGFOOD_SUBJECT_INVALID "built executable is absent"; exit 1; }
[[ "$(sha256_file "$gitd_bin")" == "$gitd_digest" ]] \
  || { refuse SYNTHETIC_DOGFOOD_GITD_DIGEST_MISMATCH after-build; exit 1; }
proof_root="$(mktemp -d /tmp/bullet-synthetic-selection.XXXXXXXX)"
case "$proof_root" in
  /tmp/bullet-synthetic-selection.*) ;;
  *) refuse SYNTHETIC_DOGFOOD_CUSTODY_INVALID "$proof_root"; exit 1 ;;
esac
[[ ! -L "$proof_root" \
  && "$(stat -Lc '%u:%a:%F' -- "$proof_root")" == "$(id -u):700:directory" ]] \
  || { refuse SYNTHETIC_DOGFOOD_CUSTODY_INVALID "$proof_root"; exit 1; }
completed=false
cleanup() {
  if [[ "$completed" != true ]]; then
    rm -rf -- "$proof_root"
  fi
}
trap cleanup EXIT
run_case() {
  local name="$1" fault="${2:-}" chaos="${3:-}" root="$proof_root/$1"
  [[ -z "$fault" || -z "$chaos" ]] \
    || { refuse SYNTHETIC_DOGFOOD_SELECTOR_CONFLICT "$name"; exit 1; }
  [[ "$(sha256_file "$farmd_bin")" == "$farmd_digest" \
    && "$(sha256_file "$dogfood_bin")" == "$dogfood_digest" \
    && "$(sha256_file "$verifier_bin")" == "$verifier_digest" \
    && "$(sha256_file "$gitd_bin")" == "$gitd_digest" ]] \
    || { refuse SYNTHETIC_DOGFOOD_SUBJECT_DRIFT "$name"; exit 1; }
  if [[ ! -e "$root" ]]; then
    mkdir -m 0700 -- "$root" "$root/home"
  elif [[ ! -d "$root/home" || -L "$root" || -L "$root/home" ]]; then
    refuse SYNTHETIC_DOGFOOD_CASE_CUSTODY_INVALID "$root"
    exit 1
  fi
  local -a fault_env=() chaos_env=()
  [[ -z "$fault" ]] || fault_env=(BULLET_SYNTHETIC_DOGFOOD_FAULT="$fault")
  [[ -z "$chaos" ]] || chaos_env=(BULLET_TRANSACTION_OFFLINE_CHAOS="$chaos")
  set +e
  exec 9<"$verifier_bin"
  env -i PATH=/usr/bin:/bin HOME="$root/home" \
    BULLET_FARMD_BIN="$farmd_bin" BULLET_FARMD_SHA256="$farmd_digest" \
    BULLET_GITD_BIN="$gitd_bin" BULLET_GITD_SHA256="$gitd_digest" \
    BULLET_VERIFIER_FIXTURE_FD=9 BULLET_VERIFIER_FIXTURE_SHA256="$verifier_digest" \
    TRANSACTION_OFFLINE_ARTIFACT_ROOT="$root/artifacts" \
    TRANSACTION_OFFLINE_RECEIPT="$root/DF_DOG1_SELECTION.receipt.json" \
    TRANSACTION_OFFLINE_EFFECT_RECEIPT="$root/DF_DOG1_EFFECT_CHAIN.receipt.json" \
    "${fault_env[@]}" "${chaos_env[@]}" "$dogfood_bin" --synthetic-selection --json \
    >"$root/stdout" 2>"$root/stderr"
  run_code=$?
  exec 9<&-
  set -e
  run_root="$root"
}
assert_selection_fault() {
  local name="$1" fault="$2" message="$3" receipt="$4"
  log "injecting $fault and proving receipt ordering"
  run_case "$name" "$fault"
  [[ "$run_code" -eq 1 && ! -s "$run_root/stdout" \
    && "$(<"$run_root/stderr")" == "bullet-transaction-offline: $message" ]] \
    || { cat "$run_root/stderr" >&2; refuse SYNTHETIC_DOGFOOD_FAULT_INVALID "$fault"; exit 1; }
  if [[ "$receipt" == absent ]]; then
    [[ ! -e "$run_root/DF_DOG1_SELECTION.receipt.json" ]] \
      || { refuse SYNTHETIC_DOGFOOD_PREMATURE_RECEIPT "$fault"; exit 1; }
  else
    [[ -s "$run_root/DF_DOG1_SELECTION.receipt.json" ]] \
      || { refuse SYNTHETIC_DOGFOOD_DURABLE_RECEIPT_ABSENT "$fault"; exit 1; }
  fi
  [[ ! -e "$run_root/DF_DOG1_EFFECT_CHAIN.receipt.json" ]] \
    || { refuse SYNTHETIC_DOGFOOD_PREMATURE_EFFECT_RECEIPT "$fault"; exit 1; }
}
assert_selection_fault fault-a after-acquire SYNTHETIC_DOGFOOD_FAULT_AFTER_ACQUIRE absent
assert_selection_fault fault-b lane-b-after-acquire SYNTHETIC_DOGFOOD_FAULT_LANE_B_AFTER_ACQUIRE absent
assert_selection_fault fault-selector before-selection SYNTHETIC_DOGFOOD_FAULT_BEFORE_SELECTION absent
assert_selection_fault fault-before-receipt before-receipt SYNTHETIC_DOGFOOD_FAULT_BEFORE_RECEIPT absent
assert_selection_fault fault-after-receipt after-receipt SYNTHETIC_DOGFOOD_FAULT_AFTER_RECEIPT present
after_receipt="$run_root/DF_DOG1_SELECTION.receipt.json"
after_digest="$(sha256_file "$after_receipt")"
ledger_digest="$(sha256_file "$run_root/data/ledger.sqlite")"
run_case fault-after-receipt ""
[[ "$run_code" -eq 1 && ! -s "$run_root/stdout" \
  && "$(sha256_file "$after_receipt")" == "$after_digest" \
  && "$(sha256_file "$run_root/data/ledger.sqlite")" == "$ledger_digest" \
  && ! -e "$run_root/DF_DOG1_EFFECT_CHAIN.receipt.json" ]] \
  || { refuse SYNTHETIC_DOGFOOD_EXISTING_RECEIPT_REPLAY "durable state changed"; exit 1; }
sql() {
  sqlite3 -batch -noheader "$run_root/data/ledger.sqlite" "$1"
}
load_selected() {
  selection_receipt="$run_root/DF_DOG1_SELECTION.receipt.json"
  selected_candidate="$(jq -r '.body.selection.selected_candidate_id' "$selection_receipt")"
  selected_base="$(jq -r --arg id "$selected_candidate" \
    '.body.lanes[] | select(.candidate_id == $id) | .candidate_base_oid | split(":")[1]' \
    "$selection_receipt")"
  selected_head="$(jq -r --arg id "$selected_candidate" \
    '.body.lanes[] | select(.candidate_id == $id) | .candidate_head_oid | split(":")[1]' \
    "$selection_receipt")"
  candidate_ref="refs/heads/bullet/candidate/$selected_candidate"
  forge="$run_root/artifacts/selected-effects/target.git"
}
state_file_count() {
  local directory="$1" paths=()
  if [[ -d "$directory" ]]; then
    shopt -s nullglob
    paths=("$directory"/*.json)
    shopt -u nullglob
  fi
  printf '%s' "${#paths[@]}"
}
git_ref() {
  env -i PATH=/usr/bin:/bin /usr/bin/git --git-dir="$forge" \
    rev-parse --verify "$1" 2>/dev/null || true
}
assert_effect_authority_terminal() {
  local expected="$1" summary
  summary="$(sql "SELECT (SELECT COUNT(*) FROM attempts) || ':' ||
    (SELECT COUNT(DISTINCT runner_id) FROM attempts) || ':' ||
    (SELECT COUNT(*) FROM attempts WHERE fence = 2) || ':' ||
    COALESCE((SELECT state FROM attempts WHERE fence = 2), '') || ':' ||
    (SELECT COUNT(*) FROM active_leases);")"
  [[ "$summary" == "3:3:1:$expected:0" ]] \
    || { refuse SYNTHETIC_DOGFOOD_EFFECT_AUTHORITY_INVALID "$summary"; exit 1; }
}
assert_effect_state() {
  local expected="$1" expected_receipts="$2" summary
  summary="$(sql "SELECT (SELECT COUNT(*) FROM effect_intents) || ':' ||
    COALESCE((SELECT state FROM effect_intents), '') || ':' ||
    (SELECT COUNT(*) FROM effect_receipts);")"
  [[ "$summary" == "1:$expected:$expected_receipts" ]] \
    || { refuse SYNTHETIC_DOGFOOD_EFFECT_LEDGER_INVALID "$summary"; exit 1; }
}
assert_forge_prefix() {
  local candidate="$1" check="$2" target="$3" integrations="$4" actual
  if [[ "$candidate" == absent ]]; then
    actual="$(git_ref "$candidate_ref")"
    [[ -z "$actual" ]] || { refuse SYNTHETIC_DOGFOOD_CANDIDATE_REF_PREMATURE "$actual"; exit 1; }
  else
    [[ "$(git_ref "$candidate_ref")" == "$selected_head" ]] \
      || { refuse SYNTHETIC_DOGFOOD_CANDIDATE_REF_INVALID "$candidate_ref"; exit 1; }
  fi
  [[ "$(state_file_count "$forge/bullet-effects-v1/checks")" == "$check" \
    && "$(state_file_count "$forge/bullet-effects-v1/integrations")" == "$integrations" ]] \
    || { refuse SYNTHETIC_DOGFOOD_FORGE_STATE_INVALID "$run_root"; exit 1; }
  actual="$(git_ref refs/heads/main)"
  case "$target" in
    absent) [[ -z "$actual" ]] ;;
    base) [[ "$actual" == "$selected_base" ]] ;;
    head) [[ "$actual" == "$selected_head" ]] ;;
    *) false ;;
  esac || { refuse SYNTHETIC_DOGFOOD_TARGET_STATE_INVALID "$target:$actual"; exit 1; }
}
assert_effect_failure() {
  local name="$1" fault="$2" chaos="$3" message="$4" state="$5" receipts="$6"
  local candidate="$7" check="$8" target="$9" integrations="${10}" terminal="${11}"
  log "injecting ${fault:-$chaos} and proving selected effect prefix"
  run_case "$name" "$fault" "$chaos"
  [[ "$run_code" -eq 1 && ! -s "$run_root/stdout" \
    && "$(<"$run_root/stderr")" == "bullet-transaction-offline: $message" \
    && -s "$run_root/DF_DOG1_SELECTION.receipt.json" \
    && ! -e "$run_root/DF_DOG1_EFFECT_CHAIN.receipt.json" ]] \
    || { cat "$run_root/stderr" >&2; refuse SYNTHETIC_DOGFOOD_EFFECT_FAULT_INVALID "${fault:-$chaos}"; exit 1; }
  load_selected
  assert_effect_authority_terminal "$terminal"
  if [[ "$state" == NONE ]]; then
    [[ "$(sql 'SELECT COUNT(*) FROM effect_intents;')" == 0 \
      && "$(sql 'SELECT COUNT(*) FROM effect_receipts;')" == 0 && ! -e "$forge" ]] \
      || { refuse SYNTHETIC_DOGFOOD_PREMATURE_EFFECT verifier-handoff; exit 1; }
  else
    assert_effect_state "$state" "$receipts"
    assert_forge_prefix "$candidate" "$check" "$target" "$integrations"
  fi
}
chaos_suffix='classification=COMPONENT_PROOF signing_trust=UNSIGNED_FIXTURE transaction_gate_eligible=false independent_evidence_eligible=false release_gate_eligible=false'
assert_effect_failure fault-grant-changed effect-grant-changed "" SYNTHETIC_DOGFOOD_FAULT_EFFECT_GRANT_CHANGED NONE 0 absent 0 absent 0 failed
assert_effect_failure fault-grant-readback effect-grant-readback-error "" "lease call refused: SYNTHETIC_EFFECT_AUTHORITY_REFUSED: SYNTHETIC_DOGFOOD_FAULT_EFFECT_GRANT_READBACK_ERROR" NONE 0 absent 0 absent 0 failed
assert_effect_failure chaos-verifier "" verifier-handoff "CHAOS_BOUNDARY_INJECTED: verifier-handoff; $chaos_suffix" NONE 0 absent 0 absent 0 failed
assert_effect_failure chaos-delivery "" candidate-delivery "CHAOS_BOUNDARY_INJECTED: candidate-delivery; $chaos_suffix" AUTHORIZED 0 absent 0 absent 0 failed
assert_effect_failure fault-delivery-unknown after-delivery-unknown "" SYNTHETIC_DOGFOOD_FAULT_AFTER_DELIVERY_UNKNOWN OUTCOME_UNKNOWN 0 present 0 absent 0 failed
assert_effect_failure chaos-check "" check-publication "CHAOS_BOUNDARY_INJECTED: check-publication; $chaos_suffix" COMMITTED 1 present 0 base 0 failed
assert_effect_failure chaos-integration "" integration "CHAOS_BOUNDARY_INJECTED: integration; $chaos_suffix" COMMITTED 1 present 1 base 0 failed
assert_effect_failure chaos-observation "" observation-cleanup "CHAOS_BOUNDARY_INJECTED: observation-cleanup; $chaos_suffix" COMMITTED 1 present 1 head 1 failed
assert_effect_failure fault-before-effect before-effect-receipt "" SYNTHETIC_DOGFOOD_FAULT_BEFORE_EFFECT_RECEIPT COMMITTED 1 present 1 head 1 superseded
forge_tree_digest() {
  (cd "$1" && find . -type f -print | sort | while IFS= read -r path; do
    sha256sum -- "$path"
  done | sha256sum)
}
log "injecting after-effect-receipt and proving create-once replay refusal"
run_case fault-after-effect after-effect-receipt
[[ "$run_code" -eq 1 && ! -s "$run_root/stdout" \
  && "$(<"$run_root/stderr")" == \
    "bullet-transaction-offline: SYNTHETIC_DOGFOOD_FAULT_AFTER_EFFECT_RECEIPT" ]] \
  || { cat "$run_root/stderr" >&2; refuse SYNTHETIC_DOGFOOD_EFFECT_FAULT_INVALID after-effect-receipt; exit 1; }
load_selected
effect_receipt="$run_root/DF_DOG1_EFFECT_CHAIN.receipt.json"
[[ "$(stat -Lc '%u:%a:%h:%F' -- "$selection_receipt")" == "$(id -u):600:1:regular file" \
  && "$(stat -Lc '%u:%a:%h:%F' -- "$effect_receipt")" == "$(id -u):600:1:regular file" \
  && "$(jq -cS . "$selection_receipt")" == "$(<"$selection_receipt")" \
  && "$(jq -cS . "$effect_receipt")" == "$(<"$effect_receipt")" ]] \
  || { refuse SYNTHETIC_DOGFOOD_EFFECT_RECEIPT_CUSTODY_INVALID after-effect-receipt; exit 1; }
assert_effect_authority_terminal superseded
assert_effect_state COMMITTED 1
assert_forge_prefix present 1 head 1
selection_before="$(sha256_file "$selection_receipt")"
effect_before="$(sha256_file "$effect_receipt")"
ledger_before="$(sha256_file "$run_root/data/ledger.sqlite")"
forge_before="$(forge_tree_digest "$forge")"
run_case fault-after-effect ""
[[ "$run_code" -eq 1 && ! -s "$run_root/stdout" \
  && "$(sha256_file "$selection_receipt")" == "$selection_before" \
  && "$(sha256_file "$effect_receipt")" == "$effect_before" \
  && "$(sha256_file "$run_root/data/ledger.sqlite")" == "$ledger_before" \
  && "$(forge_tree_digest "$forge")" == "$forge_before" ]] \
  || { refuse SYNTHETIC_DOGFOOD_EFFECT_RECEIPT_REPLAY_CHANGED_STATE "$run_root"; exit 1; }
log "running exact selected-Candidate local effect chain"
run_case positive ""
[[ "$run_code" -eq 0 && ! -s "$run_root/stderr" ]] \
  || { cat "$run_root/stderr" >&2; refuse SYNTHETIC_DOGFOOD_POSITIVE_FAILED "$run_code"; exit 1; }
load_selected
receipt="$selection_receipt"
effect_receipt="$run_root/DF_DOG1_EFFECT_CHAIN.receipt.json"
[[ "$(stat -Lc '%u:%a:%h:%F' -- "$receipt")" == "$(id -u):600:1:regular file" \
  && "$(stat -Lc '%u:%a:%h:%F' -- "$effect_receipt")" == "$(id -u):600:1:regular file" ]] \
  || { refuse SYNTHETIC_DOGFOOD_RECEIPT_IDENTITY_INVALID "$run_root"; exit 1; }
cmp -s -- "$effect_receipt" <(head -c -1 "$run_root/stdout") \
  || { refuse SYNTHETIC_DOGFOOD_STDOUT_RECEIPT_MISMATCH exact-bytes; exit 1; }
cmp -s -- "$receipt" <(jq -r '.body.selection_receipt_hex' "$effect_receipt" | xxd -r -p) \
  || { refuse SYNTHETIC_DOGFOOD_SELECTION_ORIGIN_MISMATCH exact-bytes; exit 1; }
[[ "$(jq -cS . "$receipt")" == "$(<"$receipt")" \
  && "$(jq -cS . "$effect_receipt")" == "$(<"$effect_receipt")" ]] \
  || { refuse SYNTHETIC_DOGFOOD_RECEIPT_NONCANONICAL jq-order; exit 1; }
selection_artifact="$(<"$receipt")"
selection_body="$(jq -cS '.body' "$receipt")"
selection_artifact_digest="$(framed_blake3 bullet.synthetic-selection-receipt.artifact.v1 "$selection_artifact")"
selection_body_digest="$(framed_blake3 bullet.synthetic-selection-receipt.body.v1 "$selection_body")"
settlement_id="$(jq -r '.body.effect_authority.settlement.settlement_id' "$effect_receipt")"
[[ "$settlement_id" =~ ^lts_[0-9a-f]{64}$ ]] \
  || { refuse SYNTHETIC_DOGFOOD_SETTLEMENT_ID_INVALID "$settlement_id"; exit 1; }
settlement_record="$(sql "SELECT record_json FROM lease_transport_settlements WHERE settlement_id = '$settlement_id';")"
[[ -n "$settlement_record" && "$(printf %s "$settlement_record" | jq -cS .)" == "$settlement_record" ]] \
  || { refuse SYNTHETIC_DOGFOOD_SETTLEMENT_RECORD_INVALID canonical-readback; exit 1; }
effect_body="$(jq -cS '.body' "$effect_receipt")"
settlement_request="$(printf %s "$settlement_record" | jq -cS '.request')"
settlement_subject="$(printf %s "$settlement_record" | jq -cS '.subject')"
effect_body_digest="$(framed_blake3 bullet.synthetic-effect-chain-receipt.body.v1 "$effect_body")"
settlement_request_digest="$(framed_blake3 authority.lease-transport-request.v1alpha1 "$settlement_request")"
settlement_subject_digest="$(framed_blake3 bullet.synthetic-effect-settlement-subject.v1 "$settlement_subject")"
jq -e --arg selection_body_digest "$selection_body_digest" '
  . as $root |
  keys == ["body", "body_digest", "schema_version"] and
  .schema_version == "bullet.synthetic-selection-receipt.component.v1" and
  .body_digest == $selection_body_digest and
  (.body | keys == ["eligibility", "evidence_class", "execution_schedule", "lanes", "selection", "shared", "signing_trust", "simulator"]) and
  .body.evidence_class == "COMPONENT_PROOF" and .body.signing_trust == "UNSIGNED_FIXTURE" and .body.execution_schedule == "SEQUENTIAL" and
  (.body.simulator | keys == ["external_effects", "live_credentials_used", "provider", "version"]) and
  .body.simulator.provider == "sim" and .body.simulator.version == "sim-1.0.0" and
  .body.simulator.live_credentials_used == false and .body.simulator.external_effects == false and
  (.body.shared | keys == ["base_oid", "gate_ids", "mission_id", "plan_digest", "plan_revision_id", "repository_id", "scope_paths", "selection_group_id", "work_package_id"]) and
  (.body.shared.base_oid | test("^(sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$")) and
  .body.shared.scope_paths == ["PONG.txt"] and (.body.shared.gate_ids | length == 1) and
  (.body.selection | keys == ["blinded_views", "decision", "input_digest", "revealed_run_salt", "selected_candidate_id", "unblinding"]) and
  .body.selection.decision.rubric == "NONQUALITY_TIEBREAK_V1" and
  (.body.selection.decision.ordered_handles | sort) == [.body.selection.blinded_views[].blinded_handle] and
  ([.body.selection.blinded_views[].blinded_handle] | sort) == [.body.selection.blinded_views[].blinded_handle] and
  (.body.selection.blinded_views | length == 2) and
  all(.body.selection.blinded_views[]; keys == ["base_oid", "blinded_handle", "component_gate_passed", "gate_ids", "head_oid", "patch_blake3", "tree_oid"] and .component_gate_passed == true and
    (.blinded_handle | test("^bvh_[0-9a-f]{64}$")) and (.patch_blake3 | test("^[0-9a-f]{64}$"))) and
  (.body.selection.unblinding | length == 2) and
  all(.body.selection.unblinding[]; keys == ["binding_digest", "blinded_handle", "candidate_id"] and
    (.binding_digest | test("^[0-9a-f]{64}$")) and (.candidate_id | test("^can_[0-9a-f]{64}$"))) and
  ([.body.selection.unblinding[] | select(.blinded_handle == $root.body.selection.decision.selected_handle) | .candidate_id] == [.body.selection.selected_candidate_id]) and
  (.body.lanes | length == 2) and
  all(.body.lanes[];
    keys == ["acquire_request_digest", "attempt_fence", "attempt_id", "authority_digest", "candidate_base_oid", "candidate_head_oid", "candidate_id", "candidate_patch_blake3", "candidate_row_digest", "candidate_tree_oid", "journal_blake3", "journal_relative", "raw_artifact_blake3", "raw_artifact_relative", "recovery_blake3", "recovery_relative", "repository_relative", "requeue", "runner_epoch", "runner_id", "settlement_id", "settlement_request_digest", "terminal_state", "variant_id", "workspace_id"] and
    .attempt_fence == 1 and .runner_epoch == 1 and .terminal_state == "Superseded" and .requeue == true and
    (.runner_id | test("^run_[0-9a-f]{64}$")) and (.variant_id | test("^var_[0-9a-f]{64}$")) and
    (.attempt_id | test("^atm_[0-9a-f]{64}$")) and (.candidate_id | test("^can_[0-9a-f]{64}$")) and
    (.settlement_id | test("^lts_[0-9a-f]{64}$"))) and
  ([.body.lanes[].runner_id] | unique | length) == 2 and ([.body.lanes[].variant_id] | unique | length) == 2 and
  ([.body.lanes[].attempt_id] | unique | length) == 2 and ([.body.lanes[].candidate_id] | unique | length) == 2 and
  ([.body.lanes[].settlement_id] | unique | length) == 2 and
  (.body.eligibility | keys == ["comparative_claim_eligible", "evolution_profile_eligible", "independent_evidence_eligible", "live_eligible", "provider_certification_eligible", "release_gate_eligible", "routing_activation_eligible", "team_recipe_eligible", "transaction_gate_eligible"]) and all(.body.eligibility[]; . == false)
' "$receipt" >/dev/null \
  || { refuse SYNTHETIC_DOGFOOD_RECEIPT_SHAPE_INVALID strict-closure; exit 1; }
jq -e --slurpfile selection "$receipt" --argjson durable "$settlement_record" \
  --arg effect_body_digest "$effect_body_digest" \
  --arg selection_artifact_digest "$selection_artifact_digest" --arg selection_body_digest "$selection_body_digest" \
  --arg settlement_request_digest "$settlement_request_digest" \
  --arg settlement_subject_digest "$settlement_subject_digest" '
  .body as $b | $selection[0] as $s |
  ($b.selected_candidate.candidate.head_oid | split(":")[1]) as $head |
  ($b.selected_candidate.candidate.base_oid | split(":")[1]) as $base |
  $b.effect_chain.signed_verification as $verification |
  $b.effect_chain.local_forge as $forge |
  $b.effect_authority.settlement as $closed | $durable.request.release as $request |
  $durable.outcome.released as $outcome |
  ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"] as $hex |
  keys == ["body", "body_digest", "schema_version"] and
  .schema_version == "bullet.synthetic-effect-chain-receipt.component.v1" and
  .body_digest == $effect_body_digest and
  ($b | keys == ["authority_class", "effect_authority", "effect_chain", "eligibility", "evidence_class", "execution_schedule", "grants", "selected_candidate", "selection_binding", "selection_receipt_hex", "signing_trust"]) and
  ($b.selection_receipt_hex | test("^([0-9a-f]{2})+$")) and
  $b.evidence_class == "COMPONENT_PROOF" and $b.signing_trust == "UNSIGNED_FIXTURE" and
  $b.execution_schedule == "SEQUENTIAL_SELECTED_COMPONENT" and
  $b.authority_class == "ACTIVE_SYNTHETIC_WRITER_LEASE_FIXTURE" and
  ($b.selection_binding | keys == ["candidate_row_digest", "canonical_blake3", "patch_digest", "plan_digest", "receipt_body_digest", "receipt_digest", "selected_handle", "subject_digest", "work_package_id"]) and
  ($b.selected_candidate | keys == ["author", "candidate", "repository", "schema_version", "selection", "shared"]) and
  ($b.selected_candidate.selection | keys == ["body_digest", "plan_digest", "receipt_digest", "rubric", "selected_handle"]) and
  ($b.selected_candidate.author | keys == ["attempt_fence", "attempt_id", "authority_digest", "policy_snapshot_digest", "runner_epoch", "runner_id", "variant_id", "workspace_id"]) and
  ($b.selected_candidate.candidate | keys == ["attempt_id", "base_oid", "candidate_id", "head_oid", "patch_digest", "row_digest", "tree_oid"]) and
  ($b.effect_authority | keys == ["attempt_fence", "attempt_id", "author_attempt_id", "author_fence", "authority_digest", "runner_epoch", "runner_id", "settlement", "terminal_state", "variant_id", "workspace_id", "workspace_nonce_hex"]) and
  ($b.effect_chain | keys == ["dispatch_state", "durable_intent", "durable_receipts", "effect_attempt_id", "effect_authority_digest", "effect_fence", "local_forge", "logical_effect_key", "provider", "reconciliation", "settled_state", "signed_verification", "target_ref"]) and
  ($b.effect_chain.durable_intent | keys == ["attempt_id", "created_at", "desired_state_hash", "expected_old_oid", "fence", "id", "logical_effect_key", "payload_hash", "policy_version", "provider", "provider_idempotency_key", "state", "target_identity", "unknown_retries"]) and
  ($b.effect_chain.durable_receipts | length == 1) and
  all($b.effect_chain.durable_receipts[]; keys == ["adopted_after_unknown", "effect_intent_id", "id", "observed_remote_identity", "observed_state_hash", "recorded_at", "verification_method", "verification_result"]) and
  ($verification | keys == ["canonical_chain_blake3", "chain", "chain_reverified", "independent_evidence_eligible", "intent_key", "signing_trust", "transaction_gate_eligible", "verifier_key", "verifier_outcome", "writer_proof_refused"]) and
  ($forge | keys == ["check_name", "check_readback_matches", "check_sha", "delivered_oid", "effect_candidate_bound", "integration_oid", "integration_previous_oid", "integration_subject_id", "observation_target_oid", "proof_root", "restart_readback_matches", "signed_observation"]) and
  ($b.grants | keys == ["check_grant_present", "delivery_grant_present", "distinct_observer_os_identity", "distinct_verifier_os_identity", "integration_grant_present"]) and all($b.grants[]; . == false) and
  ($b.eligibility | keys == ["comparative_claim_eligible", "evolution_profile_eligible", "five_plane_eligible", "independent_evidence_eligible", "live_eligible", "provider_certification_eligible", "release_gate_eligible", "restart_recovery_eligible", "routing_activation_eligible", "team_recipe_eligible", "transaction_gate_eligible"]) and
  all($b.eligibility[]; . == false) and
  $b.selection_binding.receipt_body_digest == $s.body_digest and
  $b.selection_binding.receipt_body_digest == $selection_body_digest and
  $b.selection_binding.receipt_digest == $selection_artifact_digest and
  $b.selection_binding.receipt_digest == $b.selected_candidate.selection.receipt_digest and
  $b.selection_binding.plan_digest == $b.selected_candidate.selection.plan_digest and
  $b.selection_binding.selected_handle == $s.body.selection.decision.selected_handle and
  $b.selected_candidate.candidate.candidate_id == $s.body.selection.selected_candidate_id and
  [$s.body.lanes[] | select(.candidate_id == $b.selected_candidate.candidate.candidate_id) |
    .attempt_id] == [$b.effect_authority.author_attempt_id] and
  ([$s.body.lanes[].runner_id, $b.effect_authority.runner_id] | unique | length) == 3 and
  $b.effect_authority.author_fence == 1 and $b.effect_authority.attempt_fence == 2 and
  $b.effect_authority.terminal_state == "Superseded" and
  $b.effect_authority.variant_id == $b.selected_candidate.author.variant_id and
  $b.effect_authority.author_attempt_id == $b.selected_candidate.author.attempt_id and
  ($closed | keys == ["acquire_request_digest", "attempt_fence", "attempt_id", "expected_state", "final_state", "idempotency_key", "outcome_attempt_id", "outcome_context_revision", "outcome_fence", "outcome_runner_epoch", "outcome_runner_id", "outcome_scope_revision", "outcome_state", "outcome_variant_id", "outcome_work_package_id", "outcome_workspace_id", "outcome_workspace_nonce_hex", "request_digest", "requeue", "runner_epoch", "runner_id", "settlement_id", "subject", "subject_digest", "variant_id", "version", "work_package_id"]) and
  ($closed.subject | keys == ["authority_epoch", "freeze_generation", "graph_revision", "incarnation", "policy_generation", "routing_generation", "scope_digest", "workspace_generation", "workspace_id", "workspace_nonce_digest"]) and
  ($closed.subject.incarnation | keys == ["attempt_id", "context_revision", "fence", "scope_revision", "variant_id"]) and
  ($durable | keys == ["outcome", "request", "request_digest", "settlement_id", "subject", "version"]) and
  ($durable.request | keys == ["release"]) and ($durable.outcome | keys == ["released"]) and
  $closed.version == "lease-transport-settlement.v1alpha1" and $closed.version == $durable.version and
  $closed.settlement_id == $durable.settlement_id and $closed.request_digest == $durable.request_digest and
  $closed.request_digest == $settlement_request_digest and $closed.subject_digest == $settlement_subject_digest and
  $closed.subject == $durable.subject and $closed.subject.workspace_id == $closed.outcome_workspace_id and
  $closed.subject.incarnation.attempt_id == $closed.attempt_id and $closed.subject.incarnation.variant_id == $closed.variant_id and
  $closed.subject.incarnation.fence == $closed.attempt_fence and $closed.subject.incarnation.scope_revision == $closed.outcome_scope_revision and
  $closed.subject.incarnation.context_revision == $closed.outcome_context_revision and
  $closed.settlement_id == ("lts_" + $closed.request_digest) and
  ($closed.acquire_request_digest | test("^[0-9a-f]{64}$")) and
  ($closed.subject_digest | test("^[0-9a-f]{64}$")) and
  $closed.acquire_request_digest == $request.acquire_request_digest and
  $closed.work_package_id == $request.work_package_id and $closed.runner_id == $request.runner_id and
  $closed.runner_epoch == $request.runner_epoch and $closed.idempotency_key == $request.idempotency_key and
  $closed.variant_id == $request.variant_id and $closed.attempt_id == $request.attempt_id and
  $closed.attempt_fence == $request.attempt_fence and $closed.expected_state == "Running" and
  $request.expected_state == "running" and $closed.final_state == "Superseded" and
  $request.final_state == "superseded" and $closed.requeue == true and $request.requeue == true and
  $closed.outcome_attempt_id == $outcome.id and $closed.outcome_variant_id == $outcome.variant_id and
  $closed.outcome_work_package_id == $outcome.work_package_id and $closed.outcome_fence == $outcome.fence and
  $closed.outcome_runner_id == $outcome.runner_id and $closed.outcome_runner_epoch == $outcome.runner_epoch and
  $closed.outcome_workspace_id == $outcome.workspace_id and
  $closed.outcome_workspace_nonce_hex == ($outcome.workspace_nonce | map(. as $b | $hex[($b/16|floor)] + $hex[$b%16]) | join("")) and
  $closed.outcome_scope_revision == $outcome.scope_revision and
  $closed.outcome_context_revision == $outcome.context_revision and $closed.outcome_state == "Superseded" and
  $outcome.state == "superseded" and $closed.attempt_id == $b.effect_authority.attempt_id and
  $closed.variant_id == $b.effect_authority.variant_id and $closed.runner_id == $b.effect_authority.runner_id and
  $closed.runner_epoch == $b.effect_authority.runner_epoch and $closed.attempt_fence == $b.effect_authority.attempt_fence and
  $closed.outcome_workspace_id == $b.effect_authority.workspace_id and
  $closed.outcome_workspace_nonce_hex == $b.effect_authority.workspace_nonce_hex and
  $closed.work_package_id == $b.selection_binding.work_package_id and
  $closed.outcome_attempt_id == $closed.attempt_id and $closed.outcome_variant_id == $closed.variant_id and
  $closed.outcome_work_package_id == $closed.work_package_id and $closed.outcome_fence == $closed.attempt_fence and
  $closed.outcome_runner_id == $closed.runner_id and $closed.outcome_runner_epoch == $closed.runner_epoch and
  $closed.outcome_scope_revision > 0 and $closed.outcome_context_revision > 0 and
  $b.effect_chain.provider == "local-bare" and $b.effect_chain.effect_fence == 2 and
  $b.effect_chain.effect_attempt_id == $b.effect_authority.attempt_id and
  $b.effect_chain.effect_authority_digest == $b.effect_authority.authority_digest and
  $b.effect_chain.dispatch_state == "OUTCOME_UNKNOWN" and
  $b.effect_chain.reconciliation == "ADOPTED" and $b.effect_chain.settled_state == "COMMITTED" and
  $b.effect_chain.durable_intent.state == "COMMITTED" and
  $b.effect_chain.durable_intent.target_identity == $b.effect_chain.target_ref and
  $b.effect_chain.durable_intent.desired_state_hash == $head and
  $b.effect_chain.durable_intent.attempt_id == $b.effect_authority.attempt_id and
  $b.effect_chain.durable_intent.fence == 2 and
  $b.effect_chain.durable_receipts[0].observed_remote_identity == $b.effect_chain.target_ref and
  $b.effect_chain.durable_receipts[0].observed_state_hash == $head and
  $b.effect_chain.durable_receipts[0].verification_result == "MATCH" and
  $b.effect_chain.durable_receipts[0].adopted_after_unknown == true and
  $verification.verifier_outcome == "PASS" and $verification.writer_proof_refused == true and
  $verification.signing_trust == "FIXTURE_KEY_ONLY" and $verification.chain_reverified == true and
  $verification.independent_evidence_eligible == false and
  $verification.transaction_gate_eligible == false and
  $verification.chain.intent.record.candidate_id == $b.selected_candidate.candidate.candidate_id and
  $verification.chain.intent.record.request.base_sha == $base and
  $verification.chain.intent.record.request.head_sha == $head and
  $verification.chain.intent.record.request.author_attempt_id == $b.effect_authority.author_attempt_id and
  $verification.chain.evidence.record.candidate_id == $b.selected_candidate.candidate.candidate_id and
  $verification.chain.proof_bundle.record.candidate_id == $b.selected_candidate.candidate.candidate_id and
  $verification.chain.proof_bundle.record.outcome == "PASS" and
  $forge.delivered_oid == $head and $forge.check_sha == $head and $forge.integration_oid == $head and
  $forge.observation_target_oid == $head and $forge.integration_previous_oid == $base and
  $forge.effect_candidate_bound == true and $forge.check_readback_matches == true and
  $forge.restart_readback_matches == true and
  $forge.signed_observation.signing_trust == "FIXTURE_KEY_ONLY" and
  $forge.signed_observation.independent_evidence_eligible == false and
  $forge.signed_observation.transaction_gate_eligible == false and
  $forge.signed_observation.release_gate_eligible == false and
  $forge.signed_observation.chain_reverified == true and
  $forge.signed_observation.signed.record.subject.candidate_id ==
    $b.selected_candidate.candidate.candidate_id and
  $forge.signed_observation.signed.record.subject.proof_bundle_id ==
    $verification.chain.proof_bundle.record.proof_bundle_id and
  $forge.signed_observation.signed.record.subject.integration_subject_id == $forge.integration_subject_id and
  $forge.signed_observation.signed.record.subject.integrated_oid == $head and
  $forge.signed_observation.signed.record.outcome == "MATCHED" and
  $forge.signed_observation.signed.record.integration_survived == true
' "$effect_receipt" >/dev/null \
  || { refuse SYNTHETIC_DOGFOOD_EFFECT_RECEIPT_SHAPE_INVALID strict-closure; exit 1; }
selected_canonical="$(jq -cS '.body.selected_candidate' "$effect_receipt")"
[[ "$(printf '%s' "$selected_canonical" | b3sum --no-names)" == \
  "$(jq -r '.body.selection_binding.canonical_blake3' "$effect_receipt")" ]] \
  || { refuse SYNTHETIC_DOGFOOD_SELECTED_SUBJECT_DIGEST_INVALID canonical-blake3; exit 1; }
assert_effect_authority_terminal superseded
assert_effect_state COMMITTED 1
assert_forge_prefix present 1 head 1
while IFS=$'\t' read -r path digest; do
  [[ "$(b3sum --no-names "$run_root/artifacts/$path")" == "$digest" ]] \
    || { refuse SYNTHETIC_DOGFOOD_ARTIFACT_DIGEST_MISMATCH "$path"; exit 1; }
done < <(jq -r '.body.lanes[] | [.raw_artifact_relative,.raw_artifact_blake3],
  [.journal_relative,.journal_blake3] | @tsv' "$receipt")
while IFS=$'\t' read -r path digest; do
  [[ "$(b3sum --no-names "$run_root/$path")" == "$digest" ]] \
    || { refuse SYNTHETIC_DOGFOOD_RECOVERY_DIGEST_MISMATCH "$path"; exit 1; }
done < <(jq -r '.body.lanes[] | [.recovery_relative,.recovery_blake3] | @tsv' "$receipt")
while IFS= read -r path; do
  [[ -d "$run_root/artifacts/$path" ]] \
    || { refuse SYNTHETIC_DOGFOOD_REPOSITORY_MISSING "$path"; exit 1; }
done < <(jq -r '.body.lanes[].repository_relative' "$receipt")

cat "$effect_receipt"
completed=true
log "retained synthetic selected-effect proof root: $proof_root"
log "synthetic dogfood effect chain passed (unsigned fixture; every higher eligibility false)"
