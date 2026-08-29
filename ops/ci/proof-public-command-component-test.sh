#!/usr/bin/env bash
# Hostile admission checks for the prebuilt public-command component proof.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT
mkdir -m 0700 -- "$test_root/bin"

# Any attempted subject execution leaves a marker. Admission failures must
# happen while every supplied path is still inert.
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  ": >\"\${PUBLIC_COMPONENT_EXEC_MARKER:?}\"" \
  'exit 93' \
  >"$test_root/bin/subject"
chmod 0500 "$test_root/bin/subject"
subject="$(realpath -e -- "$test_root/bin/subject")"
subject_digest="$(sha256_file "$subject")"

base_env=(
  PUBLIC_COMPONENT_EXEC_MARKER="$test_root/executed"
  BULLET_FARMD_BIN="$subject"
  BULLET_FARMD_SHA256="$subject_digest"
  BULLET_COMMAND_WORKER_BIN="$subject"
  BULLET_COMMAND_WORKER_SHA256="$subject_digest"
  BULLET_TRANSACTION_OFFLINE_BIN="$subject"
  BULLET_TRANSACTION_OFFLINE_SHA256="$subject_digest"
  BULLET_RUNNER_BIN="$subject"
  BULLET_RUNNER_SHA256="$subject_digest"
  BULLET_GITD_BIN="$subject"
  BULLET_GITD_SHA256="$subject_digest"
  BULLET_VERIFIER_FIXTURE_BIN="$subject"
  BULLET_VERIFIER_FIXTURE_SHA256="$subject_digest"
  BULLET_NODE_BIN="$subject"
  BULLET_NODE_SHA256="$subject_digest"
)

assert_refusal() {
  local name="$1"
  local reason="$2"
  shift 2
  local proof_dir="$test_root/proof-$name"
  rm -f -- "$test_root/executed" "$test_root/$name.stdout" "$test_root/$name.stderr"
  set +e
  env -i PATH=/usr/bin:/bin "${base_env[@]}" \
    BULLET_PUBLIC_COMPONENT_PROOF_DIR="$proof_dir" \
    "$@" /usr/bin/bash ops/ci/proof-public-command-component.sh \
    >"$test_root/$name.stdout" 2>"$test_root/$name.stderr"
  local code=$?
  set -e
  [[ "$code" -eq 1 ]] \
    || { refuse PUBLIC_COMPONENT_HOSTILE_EXIT "$name returned $code"; exit 1; }
  rg -Fq "[ci] $reason:" "$test_root/$name.stderr" \
    || { cat "$test_root/$name.stderr" >&2; refuse PUBLIC_COMPONENT_HOSTILE_REASON "$name"; exit 1; }
  [[ ! -e "$test_root/executed" && ! -e "$proof_dir" ]] \
    || { refuse PUBLIC_COMPONENT_HOSTILE_MUTATION "$name executed or created output"; exit 1; }
}

assert_refusal missing-farmd PUBLIC_COMPONENT_FARMD_BIN_REQUIRED \
  BULLET_FARMD_BIN= BULLET_FARMD_SHA256=
assert_refusal relative-farmd PUBLIC_COMPONENT_FARMD_BIN_NOT_ABSOLUTE \
  BULLET_FARMD_BIN=relative/farmd
assert_refusal malformed-farmd-digest PUBLIC_COMPONENT_FARMD_SHA256_REQUIRED \
  BULLET_FARMD_SHA256=ABCDEF
assert_refusal mismatched-farmd PUBLIC_COMPONENT_FARMD_DIGEST_MISMATCH \
  BULLET_FARMD_SHA256=0000000000000000000000000000000000000000000000000000000000000000

preexisting="$test_root/preexisting"
mkdir -m 0700 -- "$preexisting"
printf 'do-not-touch\n' >"$preexisting/sentinel"
identity="$(stat -Lc '%d:%i:%u:%a:%F' -- "$preexisting")"
set +e
env -i PATH=/usr/bin:/bin "${base_env[@]}" \
  BULLET_PUBLIC_COMPONENT_PROOF_DIR="$preexisting" \
  /usr/bin/bash ops/ci/proof-public-command-component.sh \
  >"$test_root/preexisting.stdout" 2>"$test_root/preexisting.stderr"
code=$?
set -e
[[ "$code" -eq 1 ]] || { refuse PUBLIC_COMPONENT_HOSTILE_EXIT "preexisting returned $code"; exit 1; }
rg -Fq '[ci] PUBLIC_COMPONENT_PROOF_DIR_INVALID:' "$test_root/preexisting.stderr"
[[ ! -e "$test_root/executed" \
  && "$(stat -Lc '%d:%i:%u:%a:%F' -- "$preexisting")" == "$identity" \
  && "$(<"$preexisting/sentinel")" == do-not-touch ]] \
  || { refuse PUBLIC_COMPONENT_HOSTILE_MUTATION "preexisting output changed"; exit 1; }

wrapper=ops/ci/proof-public-command-component.sh
browser=ops/ci/proof-public-command-component-browser.mjs
for forbidden in 'cargo build' 'npm run' 'npm ci' 'git archive'; do
  ! rg -Fq "$forbidden" "$wrapper" \
    || { refuse PUBLIC_COMPONENT_PREBUILT_ONLY "$forbidden"; exit 1; }
done
rg -Fq -- '--provision-lease-transport-key "$key"' "$wrapper" \
  || { refuse PUBLIC_COMPONENT_PRODUCT_KEY_PROVISION_GUARD_MISSING "$wrapper"; exit 1; }
! rg -Fq '/dev/urandom' "$wrapper" \
  || { refuse PUBLIC_COMPONENT_RANDOM_KEY_NOT_STRUCTURED "$wrapper"; exit 1; }
for predicate in \
  '.get.status == "UNKNOWN"' \
  '.result.code == "COMPONENT_PROOF_NOT_TRANSACTION_ELIGIBLE"' \
  '.result.transaction_gate_eligible == false' \
  '.result.independent_evidence_eligible == false' \
  '.command_dispatch.transaction_gate_eligible == false' \
  '.command_dispatch.independent_evidence_eligible == false' \
  '.local_forge.signed_observation.release_gate_eligible == false'; do
  rg -Fq "$predicate" "$wrapper" \
    || { refuse PUBLIC_COMPONENT_GUARD_MISSING "$predicate"; exit 1; }
done
for guard in 'COMMAND_UNKNOWN' 'NO_COMMAND' 'PUBLIC_COMPONENT_WORKER_EXITED' 'HEAD^{tree}' 'refs/heads/main'; do
  rg -Fq "$guard" "$wrapper" \
    || { refuse PUBLIC_COMPONENT_GUARD_MISSING "$guard"; exit 1; }
done
rg -Fq "stat -Lc '%u:%a:%s:%F'" "$wrapper" \
  || { refuse PUBLIC_COMPONENT_KEY_CUSTODY_GUARD_MISSING "$wrapper"; exit 1; }
rg -Fq 'RECEIPT_KEY_CUSTODY_MISMATCH' "$wrapper" \
  || { refuse PUBLIC_COMPONENT_KEY_NONDISCLOSURE_GUARD_MISSING "$wrapper"; exit 1; }
for canonical_guard in "truncate -s -1 \"\$binary_manifest\"" 'missing-terminal-lf' 'retained-terminal-lf'; do
  rg -Fq "$canonical_guard" "$wrapper" \
    || { refuse PUBLIC_COMPONENT_CANONICAL_MANIFEST_GUARD_MISSING "$canonical_guard"; exit 1; }
done
rg -Fq 'locator(".verified")' "$browser" \
  || { refuse PUBLIC_COMPONENT_PORTAL_GREEN_GUARD_MISSING "$browser"; exit 1; }

log "public command component proof guardrails passed"
