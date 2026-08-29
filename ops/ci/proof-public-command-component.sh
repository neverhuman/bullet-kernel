#!/usr/bin/env bash
# Watchable packaged-origin public-command proof. Every product executable is
# an already-built exact local subject; this wrapper grants no authority.
set -euo pipefail
umask 077
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

if [[ -n "${BULLET_PUBLIC_COMPONENT_PROOF_DIR:-}" \
  && ( "$BULLET_PUBLIC_COMPONENT_PROOF_DIR" != /* || -e "$BULLET_PUBLIC_COMPONENT_PROOF_DIR" ) ]]; then
  refuse PUBLIC_COMPONENT_PROOF_DIR_INVALID \
    "BULLET_PUBLIC_COMPONENT_PROOF_DIR must be an absolute path that does not exist"
  exit 1
fi
[[ "$(uname -s)" == Linux ]] \
  || { refuse PUBLIC_COMPONENT_LINUX_REQUIRED "sealed execution and SO_PEERCRED require Linux"; exit 1; }

declare -a subject_names=(FARMD COMMAND_WORKER TRANSACTION_OFFLINE RUNNER GITD VERIFIER_FIXTURE NODE)
declare -A subject_paths subject_digests
for name in "${subject_names[@]}"; do
  path_var="BULLET_${name}_BIN"
  digest_var="BULLET_${name}_SHA256"
  path_value="${!path_var:-}"
  digest_value="${!digest_var:-}"
  if [[ -z "$path_value" ]]; then
    refuse "PUBLIC_COMPONENT_${name}_BIN_REQUIRED" "set $path_var to one exact executable"
    exit 1
  fi
  [[ "$path_value" == /* ]] \
    || { refuse "PUBLIC_COMPONENT_${name}_BIN_NOT_ABSOLUTE" "$path_value"; exit 1; }
  [[ -f "$path_value" && -x "$path_value" ]] \
    || { refuse "PUBLIC_COMPONENT_${name}_BIN_INVALID" "$path_value"; exit 1; }
  resolved="$(realpath -e -- "$path_value")" \
    || { refuse "PUBLIC_COMPONENT_${name}_BIN_UNRESOLVED" "$path_value"; exit 1; }
  [[ "$resolved" == "$path_value" ]] \
    || { refuse "PUBLIC_COMPONENT_${name}_BIN_NOT_CANONICAL" "expected $resolved"; exit 1; }
  [[ "$digest_value" =~ ^[0-9a-f]{64}$ ]] \
    || { refuse "PUBLIC_COMPONENT_${name}_SHA256_REQUIRED" "$digest_var must be lowercase SHA-256"; exit 1; }
  subject_mode="$(stat -Lc '%u:%a:%F' -- "$path_value")"
  subject_perm="$(stat -Lc '%a' -- "$path_value")"
  [[ "$subject_mode" == "$(id -u):"*":regular file" \
    && $((8#$subject_perm & 8#22)) -eq 0 ]] \
    || { refuse "PUBLIC_COMPONENT_${name}_BIN_UNPROTECTED" "$subject_mode"; exit 1; }
  [[ "$(sha256_file "$path_value")" == "$digest_value" ]] \
    || { refuse "PUBLIC_COMPONENT_${name}_DIGEST_MISMATCH" before-proof; exit 1; }
  subject_paths[$name]="$path_value"
  subject_digests[$name]="$digest_value"
done
for tool in awk b3sum chmod cmp curl dd git id install jq mkdir realpath sed seq setsid \
  sha256sum stat tail timeout uname; do
  require_tool "$tool" || exit 1
done

portal_manifest="${BULLET_PORTAL_BUNDLE_MANIFEST:-}"
portal_manifest_sha="${BULLET_PORTAL_BUNDLE_MANIFEST_SHA256:-}"
[[ "$portal_manifest" == /* && -f "$portal_manifest" ]] \
  || { refuse PUBLIC_COMPONENT_PORTAL_MANIFEST_REQUIRED "$portal_manifest"; exit 1; }
[[ "$(realpath -e -- "$portal_manifest")" == "$portal_manifest" ]] \
  || { refuse PUBLIC_COMPONENT_PORTAL_MANIFEST_NOT_CANONICAL "$portal_manifest"; exit 1; }
portal_identity="$(stat -Lc '%u:%a:%F' -- "$portal_manifest")"
portal_perm="$(stat -Lc '%a' -- "$portal_manifest")"
[[ "$portal_identity" == "$(id -u):"*":regular file" && $((8#$portal_perm & 8#22)) -eq 0 ]] \
  || { refuse PUBLIC_COMPONENT_PORTAL_MANIFEST_UNPROTECTED "$portal_identity"; exit 1; }
[[ "$portal_manifest_sha" =~ ^[0-9a-f]{64}$ ]] \
  || { refuse PUBLIC_COMPONENT_PORTAL_MANIFEST_SHA256_REQUIRED "$portal_manifest_sha"; exit 1; }
[[ "$(sha256_file "$portal_manifest")" == "$portal_manifest_sha" ]] \
  || { refuse PUBLIC_COMPONENT_PORTAL_MANIFEST_DIGEST_MISMATCH before-proof; exit 1; }
jq -e '
  .schema_version == "bullet.portal.bundle.v1" and
  .source.repository == "bullet-portal" and
  (.source.commit_oid | test("^(sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$")) and
  (.source.tree_oid | test("^(sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$")) and
  (.root | test("^blake3:[0-9a-f]{64}$")) and
  (.files | type == "array" and length > 0)
' "$portal_manifest" >/dev/null \
  || { refuse PUBLIC_COMPONENT_PORTAL_MANIFEST_INVALID "$portal_manifest"; exit 1; }
portal_root="$(jq -r .root "$portal_manifest")"
portal_commit="$(jq -r .source.commit_oid "$portal_manifest")"
portal_tree="$(jq -r .source.tree_oid "$portal_manifest")"

playwright_root="${BULLET_PLAYWRIGHT_ROOT:-}"
playwright_lock_sha="${BULLET_PLAYWRIGHT_LOCK_SHA256:-}"
[[ "$playwright_root" == /* && -d "$playwright_root/node_modules/playwright" \
  && -f "$playwright_root/package-lock.json" \
  && "$(realpath -e -- "$playwright_root")" == "$playwright_root" ]] \
  || { refuse PUBLIC_COMPONENT_PLAYWRIGHT_ROOT_INVALID "$playwright_root"; exit 1; }
[[ "$playwright_lock_sha" =~ ^[0-9a-f]{64}$ \
  && "$(sha256_file "$playwright_root/package-lock.json")" == "$playwright_lock_sha" ]] \
  || { refuse PUBLIC_COMPONENT_PLAYWRIGHT_LOCK_MISMATCH "$playwright_root/package-lock.json"; exit 1; }

if [[ -n "${BULLET_PUBLIC_COMPONENT_PROOF_DIR:-}" ]]; then
  mkdir -m 0700 -- "$BULLET_PUBLIC_COMPONENT_PROOF_DIR"
  proof_root="$(realpath -e -- "$BULLET_PUBLIC_COMPONENT_PROOF_DIR")"
else
  proof_root="$(mktemp -d /tmp/bullet-public-command-component.XXXXXXXX)"
fi
[[ "$proof_root" != / && "$proof_root" != "$REPO_ROOT" && ! -L "$proof_root" \
  && "$(stat -Lc '%u:%a:%F' -- "$proof_root")" == "$(id -u):700:directory" ]] \
  || { refuse PUBLIC_COMPONENT_PROOF_DIR_UNTRUSTED "$proof_root"; exit 1; }

farmd_pid=""
browser_pid=""
stop_group() {
  local pid="$1"
  [[ -n "$pid" ]] || return 0
  kill -TERM -- "-$pid" 2>/dev/null || true
  for _ in $(seq 1 100); do
    kill -0 "$pid" 2>/dev/null || { wait "$pid" 2>/dev/null || true; return 0; }
    sleep 0.05
  done
  kill -KILL -- "-$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
cleanup() {
  stop_group "$browser_pid"
  stop_group "$farmd_pid"
}
trap cleanup EXIT

mkdir -m 0700 -- "$proof_root/data" "$proof_root/custody" "$proof_root/worker"
mkdir -m 0710 -- "$proof_root/socket-one" "$proof_root/socket-two"
portal_copy="$proof_root/portal-bundle-manifest.json"
install -m 0600 -- "$portal_manifest" "$portal_copy"

uid="$(id -u)"
gid="$(id -g)"
runner_id="run_1111111111111111111111111111111111111111111111111111111111111111"
runner_epoch=1
registry="$proof_root/custody/peer-registry.json"
key="$proof_root/custody/lease-transport.key"
jq -cS -n --argjson uid "$uid" --argjson gid "$gid" --arg runner "$runner_id" '
  {farmd_uid:$uid,socket_gid:$gid,runners:[{runner_id:$runner,runner_epoch:1,service_uid:$uid}]}
' >"$registry"
chmod 0600 "$registry"
"${subject_paths[FARMD]}" --provision-lease-transport-key "$key" \
  >"$proof_root/key-provision.stdout" 2>"$proof_root/key-provision.stderr"
[[ "$(<"$proof_root/key-provision.stdout")" == "LEASE_TRANSPORT_KEY_PROVISIONED: $key" \
  && ! -s "$proof_root/key-provision.stderr" ]] \
  || { refuse PUBLIC_COMPONENT_KEY_PROVISION_INVALID "$key"; exit 1; }
[[ ! -L "$key" \
  && "$(stat -Lc '%u:%a:%s:%F' -- "$key")" == "$uid:600:64:regular file" ]] \
  || { refuse PUBLIC_COMPONENT_KEY_CUSTODY_INVALID provisioned; exit 1; }

binary_manifest="$proof_root/command-worker-binaries.json"
jq -cS -n \
  --arg transaction_path "${subject_paths[TRANSACTION_OFFLINE]}" \
  --arg transaction_sha "${subject_digests[TRANSACTION_OFFLINE]}" \
  --arg farmd_path "${subject_paths[FARMD]}" --arg farmd_sha "${subject_digests[FARMD]}" \
  --arg runner_path "${subject_paths[RUNNER]}" --arg runner_sha "${subject_digests[RUNNER]}" \
  --arg gitd_path "${subject_paths[GITD]}" --arg gitd_sha "${subject_digests[GITD]}" \
  --arg verifier_path "${subject_paths[VERIFIER_FIXTURE]}" --arg verifier_sha "${subject_digests[VERIFIER_FIXTURE]}" '
  {schema_version:"bullet.command-worker-binary-manifest.v1",
   transaction_offline:{path:$transaction_path,sha256:$transaction_sha},
   farmd:{path:$farmd_path,sha256:$farmd_sha},runner:{path:$runner_path,sha256:$runner_sha},
   gitd:{path:$gitd_path,sha256:$gitd_sha},verifier:{path:$verifier_path,sha256:$verifier_sha}}
' >"$binary_manifest"
manifest_last_byte="$(tail -c 1 "$binary_manifest" | od -An -tuC | tr -d ' ')"
if [[ "$manifest_last_byte" == 10 ]]; then
  truncate -s -1 "$binary_manifest"
else
  refuse PUBLIC_COMPONENT_MANIFEST_ENCODER_INVALID missing-terminal-lf
  exit 1
fi
[[ "$(tail -c 1 "$binary_manifest" | od -An -tuC | tr -d ' ')" != 10 ]] \
  || { refuse PUBLIC_COMPONENT_MANIFEST_ENCODER_INVALID retained-terminal-lf; exit 1; }
chmod 0600 "$binary_manifest"
binary_manifest_sha="$(sha256_file "$binary_manifest")"

subjects="$proof_root/prebuilt-subjects.json"
jq -cS -n --arg portal_commit "$portal_commit" --arg portal_tree "$portal_tree" \
  --arg portal_root "$portal_root" --arg portal_manifest_sha "$portal_manifest_sha" \
  --arg farmd "${subject_digests[FARMD]}" --arg worker "${subject_digests[COMMAND_WORKER]}" \
  --arg transaction "${subject_digests[TRANSACTION_OFFLINE]}" --arg runner "${subject_digests[RUNNER]}" \
  --arg gitd "${subject_digests[GITD]}" --arg verifier "${subject_digests[VERIFIER_FIXTURE]}" \
  --arg node "${subject_digests[NODE]}" '
  {schema_version:"bullet.public-command-prebuilt-subjects.v1",portal:{commit_oid:$portal_commit,
   tree_oid:$portal_tree,bundle_root:$portal_root,manifest_sha256:$portal_manifest_sha},
   sha256:{farmd:$farmd,command_worker:$worker,transaction_offline:$transaction,
   runner:$runner,gitd:$gitd,verifier_fixture:$verifier,node:$node},evidence_class:"COMPONENT_PROOF",
   signing_trust:"UNSIGNED_FIXTURE",transaction_gate_eligible:false,
   independent_evidence_eligible:false,release_gate_eligible:false}
' >"$subjects"
chmod 0600 "$subjects"

start_farmd() {
  local label="$1"
  local socket="$2"
  local log_file="$proof_root/farmd-$label.log"
  setsid "${subject_paths[FARMD]}" --data-dir "$proof_root/data" --bind 127.0.0.1:0 \
    --lease-transport-socket "$socket" --lease-peer-registry "$registry" \
    --lease-transport-key "$key" >"$log_file" 2>&1 &
  farmd_pid=$!
  local origin=""
  for _ in $(seq 1 300); do
    origin="$(sed -n 's/.*bullet-farmd listening on \(127\.0\.0\.1:[0-9][0-9]*\)$/http:\/\/\1/p' "$log_file" | tail -n 1)"
    if [[ "$origin" =~ ^http://127\.0\.0\.1:[0-9]+$ ]] \
      && curl --fail --silent "$origin/health" >"$proof_root/health-$label.json"; then
      break
    fi
    kill -0 "$farmd_pid" 2>/dev/null \
      || { sed -n '1,160p' "$log_file" >&2; refuse PUBLIC_COMPONENT_FARMD_EXITED "$label"; exit 1; }
    sleep 0.05
  done
  [[ "$origin" =~ ^http://127\.0\.0\.1:[0-9]+$ && -S "$socket" ]] \
    || { refuse PUBLIC_COMPONENT_FARMD_NOT_READY "$label"; exit 1; }
  jq -e --arg root "$portal_root" '.status == "ok" and .portal == $root' \
    "$proof_root/health-$label.json" >/dev/null \
    || { refuse PUBLIC_COMPONENT_PACKAGED_PORTAL_MISMATCH "$label"; exit 1; }
  farmd_origin="$origin"
  bootstrap_token="$(sed -n 's/^Bullet Farm one-time bootstrap: //p' "$log_file" | head -n 1)"
  [[ "$bootstrap_token" =~ ^boot_[0-9a-f]{64}$ ]] \
    || { refuse PUBLIC_COMPONENT_BOOTSTRAP_INVALID "$label"; exit 1; }
}

stop_farmd() {
  stop_group "$farmd_pid"
  farmd_pid=""
}

envelope='{"idempotency_key":"public_component_watchable_v1","kind":"run_demo","payload":{}}'
socket_one="$proof_root/socket-one/lease.sock"
start_farmd one "$socket_one"
cookie_jar="$proof_root/session-one.cookies"
bootstrap_body="$proof_root/bootstrap-one.json"
curl --fail-with-body --silent --show-error -c "$cookie_jar" \
  -H "Origin: $farmd_origin" -H 'content-type: application/json' \
  --data "{\"bootstrap_token\":\"$bootstrap_token\"}" \
  "$farmd_origin/api/v1/auth/bootstrap" >"$bootstrap_body"
csrf="$(jq -r .csrf_token "$bootstrap_body")"
[[ "$csrf" =~ ^csrf_[0-9a-f]{64}$ ]] \
  || { refuse PUBLIC_COMPONENT_CSRF_INVALID initial; exit 1; }
for attempt in first duplicate; do
  code="$(curl --silent --show-error -b "$cookie_jar" -o "$proof_root/admission-$attempt.json" \
    -w '%{http_code}' -H "Origin: $farmd_origin" -H "x-bullet-csrf: $csrf" \
    -H 'content-type: application/json' --data "$envelope" "$farmd_origin/api/v1/commands")"
  [[ "$code" == 202 ]] || { refuse PUBLIC_COMPONENT_POST_FAILED "$attempt HTTP $code"; exit 1; }
done
cmp "$proof_root/admission-first.json" "$proof_root/admission-duplicate.json" \
  || { refuse PUBLIC_COMPONENT_DUPLICATE_DRIFT "exact POST replay changed"; exit 1; }
jq -e '.status == "PENDING" and .kind == "run_demo" and .result == null and
  (.id | test("^cmd_[0-9a-f]{64}$")) and (.payload_digest | test("^[0-9a-f]{64}$"))' \
  "$proof_root/admission-first.json" >/dev/null
command_id="$(jq -r .id "$proof_root/admission-first.json")"
request_digest="$(jq -r .payload_digest "$proof_root/admission-first.json")"
stop_farmd

socket_two="$proof_root/socket-two/lease.sock"
start_farmd two "$socket_two"
browser_ready="$proof_root/browser-ready.json"
browser_result="$proof_root/browser-result.json"
setsid env -i PATH=/usr/bin:/bin \
  BULLET_PUBLIC_ORIGIN="$farmd_origin" BULLET_PUBLIC_BOOTSTRAP="$bootstrap_token" \
  BULLET_PUBLIC_BROWSER_READY="$browser_ready" BULLET_PUBLIC_BROWSER_RESULT="$browser_result" \
  BULLET_PUBLIC_COMMAND_ENVELOPE="$envelope" BULLET_PUBLIC_BROWSER_TIMEOUT_MS=900000 \
  BULLET_PLAYWRIGHT_ROOT="$playwright_root" BULLET_PORTAL_BUNDLE_ROOT="$portal_root" \
  "${subject_paths[NODE]}" "$REPO_ROOT/ops/ci/proof-public-command-component-browser.mjs" \
  >"$proof_root/browser.stdout" 2>"$proof_root/browser.stderr" &
browser_pid=$!
for _ in $(seq 1 600); do
  [[ -f "$browser_ready" ]] && break
  kill -0 "$browser_pid" 2>/dev/null \
    || { cat "$proof_root/browser.stderr" >&2; refuse PUBLIC_COMPONENT_BROWSER_EXITED before-worker; exit 1; }
  sleep 0.1
done
[[ -f "$browser_ready" ]] \
  || { refuse PUBLIC_COMPONENT_BROWSER_NOT_READY "$browser_ready"; exit 1; }
jq -e --arg id "$command_id" --arg digest "$request_digest" \
  '.admission.id == $id and .duplicate.id == $id and .admission.payload_digest == $digest and
   .duplicate.payload_digest == $digest and .admission.status == "PENDING"' "$browser_ready" >/dev/null \
  || { refuse PUBLIC_COMPONENT_PORTAL_REPLAY_MISMATCH "$browser_ready"; exit 1; }

worker_args=(--lease-socket "$socket_two" --farmd-uid "$uid" --socket-gid "$gid"
  --runner-id "$runner_id" --runner-epoch "$runner_epoch" --state-dir "$proof_root/worker"
  --binary-manifest "$binary_manifest" --deadline-ms 600000)
if ! timeout --signal=TERM --kill-after=5s 700s \
  "${subject_paths[COMMAND_WORKER]}" "${worker_args[@]}" \
  >"$proof_root/worker-first.stdout" 2>"$proof_root/worker-first.stderr"; then
  cat "$proof_root/worker-first.stderr" >&2
  refuse PUBLIC_COMPONENT_WORKER_EXITED first
  exit 1
fi
[[ "$(<"$proof_root/worker-first.stdout")" == COMMAND_UNKNOWN \
  && ! -s "$proof_root/worker-first.stderr" ]] \
  || { refuse PUBLIC_COMPONENT_WORKER_RESULT_INVALID first; exit 1; }
if ! timeout --signal=TERM --kill-after=5s 30s \
  "${subject_paths[COMMAND_WORKER]}" "${worker_args[@]}" \
  >"$proof_root/worker-restart.stdout" 2>"$proof_root/worker-restart.stderr"; then
  cat "$proof_root/worker-restart.stderr" >&2
  refuse PUBLIC_COMPONENT_WORKER_EXITED restart
  exit 1
fi
[[ "$(<"$proof_root/worker-restart.stdout")" == NO_COMMAND \
  && ! -s "$proof_root/worker-restart.stderr" ]] \
  || { refuse PUBLIC_COMPONENT_WORKER_RESTART_INVALID restart; exit 1; }

for _ in $(seq 1 9000); do
  kill -0 "$browser_pid" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$browser_pid" 2>/dev/null; then
  refuse PUBLIC_COMPONENT_BROWSER_TIMEOUT after-worker
  exit 1
fi
wait "$browser_pid" || { cat "$proof_root/browser.stderr" >&2; refuse PUBLIC_COMPONENT_BROWSER_FAILED after-worker; exit 1; }
browser_pid=""
[[ "$(<"$proof_root/browser.stdout")" == PORTAL_UNKNOWN && -f "$browser_result" ]] \
  || { refuse PUBLIC_COMPONENT_BROWSER_RESULT_INVALID "$browser_result"; exit 1; }
stop_farmd

state="$proof_root/worker/current.json"
claim_id="$(jq -r .claim.claim_id "$state")"
receipt="$proof_root/worker/$claim_id/run/COMPONENT_PROOF.receipt.json"
receipt_sha="$(sha256_file "$receipt")"
receipt_blake3="$(b3sum "$receipt" | awk '{print $1}')"
jq -e --arg id "$command_id" --arg request "$request_digest" --arg receipt_sha "$receipt_sha" \
  --arg receipt_digest "$receipt_blake3" \
  --arg manifest "$binary_manifest_sha" '
  .stage == "SETTLED_UNKNOWN" and .claim.command_id == $id and .claim.request_digest == $request and
  .claim.request.kind == "run_demo" and .receipt_sha256 == $receipt_sha and
  .receipt_digest == $receipt_digest and
  (.receipt_admitted_at_unix_ms | type == "number" and . > 0 and . <= 9007199254740991) and
  .binary_manifest_sha256 == $manifest
' "$state" >/dev/null || { refuse PUBLIC_COMPONENT_STATE_MISMATCH "$state"; exit 1; }
jq -e --arg id "$command_id" --arg request "$request_digest" --arg receipt "$receipt_blake3" \
  --arg manifest "$binary_manifest_sha" '
  .get.status == "UNKNOWN" and .get.id == $id and .get.payload_digest == $request and
  .get.result.command_id == $id and .get.result.request_digest == $request and
  .get.result.receipt_digest == $receipt and
  .get.result.code == "COMPONENT_PROOF_NOT_TRANSACTION_ELIGIBLE" and
  .get.result.evidence_class == "COMPONENT_PROOF" and .get.result.signing_trust == "UNSIGNED_FIXTURE" and
  .get.result.transaction_gate_eligible == false and .get.result.independent_evidence_eligible == false and
  .transaction_gate_eligible == false and .independent_evidence_eligible == false and
  .release_gate_eligible == false
' "$browser_result" >/dev/null || { refuse PUBLIC_COMPONENT_GET_PORTAL_MISMATCH "$browser_result"; exit 1; }
jq -e --arg key "$key" '
  keys == ["admission","brief_after","brief_before","duplicate","envelope","evidence_class",
    "get","independent_evidence_eligible","portal_bundle_root","release_gate_eligible",
    "rendered_command","schema_version","signing_trust","transaction_gate_eligible"] and
  ([.. | strings] | index($key)) == null
' "$browser_result" >/dev/null || { refuse PUBLIC_COMPONENT_BROWSER_RESULT_CUSTODY_MISMATCH "$browser_result"; exit 1; }
jq -e --arg id "$command_id" --arg request "$request_digest" --arg manifest "$binary_manifest_sha" '
  .evidence_class == "COMPONENT_PROOF" and .signing_trust == "UNSIGNED_FIXTURE" and
  .transaction_gate_eligible == false and .independent_evidence_eligible == false and
  .command_dispatch.source == "SEALED_CLAIM" and .command_dispatch.command_id == $id and
  .command_dispatch.request_digest == $request and .command_dispatch.binary_manifest_sha256 == $manifest and
  .command_dispatch.transaction_gate_eligible == false and
  .command_dispatch.independent_evidence_eligible == false and
  .signed_verification.signing_trust == "FIXTURE_KEY_ONLY" and
  .signed_verification.chain_reverified == true and
  .signed_verification.transaction_gate_eligible == false and
  .signed_verification.independent_evidence_eligible == false and
  .local_forge.signed_observation.signing_trust == "FIXTURE_KEY_ONLY" and
  .local_forge.signed_observation.chain_reverified == true and
  .local_forge.signed_observation.signed.record.outcome == "MATCHED" and
  .local_forge.signed_observation.transaction_gate_eligible == false and
  .local_forge.signed_observation.independent_evidence_eligible == false and
  .local_forge.signed_observation.release_gate_eligible == false
' "$receipt" >/dev/null || { refuse PUBLIC_COMPONENT_RECEIPT_MISMATCH "$receipt"; exit 1; }
[[ ! -L "$key" \
  && "$(stat -Lc '%u:%a:%s:%F' -- "$key")" == "$uid:600:64:regular file" ]] \
  || { refuse PUBLIC_COMPONENT_KEY_CUSTODY_INVALID post-exit; exit 1; }
jq -e --arg key "$key" '([.. | strings] | index($key)) == null' "$receipt" >/dev/null \
  || { refuse PUBLIC_COMPONENT_RECEIPT_KEY_CUSTODY_MISMATCH "$receipt"; exit 1; }

run_root="$(dirname "$receipt")"
source_repo="$run_root/artifacts/source"
candidate_repo="$run_root/artifacts/preserve/generation/repo"
target_repo="$run_root/artifacts/effects/target.git"
ledger="$run_root/data/ledger.sqlite"
for protected_dir in "$run_root" "$run_root/artifacts" "$run_root/data"; do
  [[ ! -L "$protected_dir" \
    && "$(stat -Lc '%u:%a:%F' -- "$protected_dir")" == "$uid:700:directory" ]] \
    || { refuse PUBLIC_COMPONENT_POST_EXIT_CUSTODY_MISMATCH "$protected_dir"; exit 1; }
done
for protected_file in "$state" "$receipt" "$ledger"; do
  [[ ! -L "$protected_file" \
    && "$(stat -Lc '%u:%a:%F' -- "$protected_file")" == "$uid:600:regular file" ]] \
    || { refuse PUBLIC_COMPONENT_POST_EXIT_CUSTODY_MISMATCH "$protected_file"; exit 1; }
done
for artifact_dir in "$source_repo" "$candidate_repo" "$target_repo"; do
  [[ ! -L "$artifact_dir" \
    && "$(stat -Lc '%u:%F' -- "$artifact_dir")" == "$uid:directory" ]] \
    || { refuse PUBLIC_COMPONENT_POST_EXIT_CUSTODY_MISMATCH "$artifact_dir"; exit 1; }
done
base_oid="$(jq -r .base_oid "$receipt")"
head_oid="$(jq -r .head_oid "$receipt")"
tree_oid="$(jq -r .tree_oid "$receipt")"
[[ "$(git -C "$source_repo" rev-parse HEAD)" == "$base_oid" \
  && "$(git -C "$candidate_repo" rev-parse HEAD)" == "$head_oid" \
  && "$(git -C "$candidate_repo" rev-parse 'HEAD^{tree}')" == "$tree_oid" \
  && "$(git --git-dir="$target_repo" rev-parse refs/heads/main)" == "$head_oid" ]] \
  || { refuse PUBLIC_COMPONENT_POST_EXIT_ARTIFACT_MISMATCH "$receipt"; exit 1; }

for name in "${subject_names[@]}"; do
  [[ "$(sha256_file "${subject_paths[$name]}")" == "${subject_digests[$name]}" ]] \
    || { refuse "PUBLIC_COMPONENT_${name}_DIGEST_MISMATCH" after-proof; exit 1; }
done
[[ "$(sha256_file "$portal_manifest")" == "$portal_manifest_sha" ]] \
  || { refuse PUBLIC_COMPONENT_PORTAL_MANIFEST_DIGEST_MISMATCH after-proof; exit 1; }

log "public command watchable component proof passed"
log "proof_root=$proof_root"
log "portal_commit=$portal_commit portal_tree=$portal_tree portal_bundle=$portal_root"
log "farmd_sha256=${subject_digests[FARMD]} worker_sha256=${subject_digests[COMMAND_WORKER]}"
log "command_id=$command_id request_digest=$request_digest receipt_digest=$receipt_blake3"
log "receipt=$receipt receipt_sha256=$receipt_sha"
log "classification=COMPONENT_PROOF signing_trust=UNSIGNED_FIXTURE transaction=false release=false"
