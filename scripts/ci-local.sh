#!/usr/bin/env bash
set -euo pipefail

# bullet-member-proof-custody-v1
CI_PROOF_INHERITED_PRESENT=false
CI_PROOF_INHERITED_RECORD=""
if [[ ${BULLET_CI_PROOF_CUSTODY+x} ]]; then
  CI_PROOF_INHERITED_PRESENT=true
  CI_PROOF_INHERITED_RECORD="$BULLET_CI_PROOF_CUSTODY"
fi
unset BULLET_CI_PROOF_CUSTODY

umask 077
[[ "$(umask)" == "0077" ]] || {
  printf '[ci] SECURE_UMASK_UNAVAILABLE: expected 0077, found %s\n' "$(umask)" >&2
  exit 1
}
cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO_ROOT="$PWD"
CI_PROOF_LOCK_DIR="$REPO_ROOT/.git/bullet-ci.lock.d"
CI_PROOF_LOCK_OWNER="$CI_PROOF_LOCK_DIR/owner"
CI_PROOF_LOCK_RECORD=""
CI_PROOF_LOCK_LANE=""
CI_PROOF_LOCK_OWNS=false
CI_PROOF_RECORD_SCOPE=""
CI_PROOF_RECORD_PID=""
CI_PROOF_RECORD_LANE=""

proof_lock_refusal() {
  printf '%s\n' \
    "[ci] CI_PROOF_LOCKED_OR_STALE: $CI_PROOF_LOCK_DIR is occupied or cannot be trusted" \
    "[ci] verify the exact owning process, then explicitly reconcile only $CI_PROOF_LOCK_DIR" >&2
  return 75
}

exact_lock_directory() {
  local path="$1" uid
  uid="$(id -u)" || return 1
  [[ -d "$path" && ! -L "$path" \
    && "$(find "$path" -maxdepth 0 -type d -uid "$uid" -perm 0700 -print 2>/dev/null)" == "$path" ]]
}

exact_owner_file() {
  local path="$1" uid
  uid="$(id -u)" || return 1
  [[ -f "$path" && ! -L "$path" \
    && "$(find "$path" -maxdepth 0 -type f -uid "$uid" -perm 0600 -print 2>/dev/null)" == "$path" ]]
}

parse_proof_record() {
  local record="$1"
  local pattern='^schema=2 repository=([a-z0-9-]+) scope=(standalone|family) pid=([1-9][0-9]*) lane=([a-z0-9-]+) nonce=([0-9]+-[0-9]+-[0-9]+-[0-9]+)$'
  [[ "$record" =~ $pattern ]] || return 1
  [[ "${BASH_REMATCH[1]}" == bullet-kernel ]] || return 1
  CI_PROOF_RECORD_SCOPE="${BASH_REMATCH[2]}"
  CI_PROOF_RECORD_PID="${BASH_REMATCH[3]}"
  CI_PROOF_RECORD_LANE="${BASH_REMATCH[4]}"
}

owner_matches_record() {
  local record="$1" first="" extra="" second_status descriptor byte_count expected_bytes
  exec {descriptor}<"$CI_PROOF_LOCK_OWNER" || return 1
  IFS= read -r -u "$descriptor" first || {
    exec {descriptor}<&-
    return 1
  }
  if IFS= read -r -u "$descriptor" extra; then
    second_status=0
  else
    second_status=$?
  fi
  exec {descriptor}<&-
  byte_count="$(LC_ALL=C wc -c <"$CI_PROOF_LOCK_OWNER")" || return 1
  expected_bytes=$((${#record} + 1))
  [[ "$first" == "$record" && "$second_status" -ne 0 && -z "$extra" \
    && "$byte_count" -eq "$expected_bytes" ]]
}

verify_proof_lock() {
  [[ -d "$REPO_ROOT/.git" && ! -L "$REPO_ROOT/.git" \
    && -f "$REPO_ROOT/.git/HEAD" && ! -L "$REPO_ROOT/.git/HEAD" \
    && -n "$CI_PROOF_LOCK_RECORD" ]] || {
    proof_lock_refusal
    return 75
  }
  if ! exact_lock_directory "$CI_PROOF_LOCK_DIR" \
      || ! exact_owner_file "$CI_PROOF_LOCK_OWNER" \
      || ! owner_matches_record "$CI_PROOF_LOCK_RECORD" \
      || ! parse_proof_record "$CI_PROOF_LOCK_RECORD"; then
    proof_lock_refusal
    return 75
  fi
  if $CI_PROOF_LOCK_OWNS; then
    [[ "$CI_PROOF_RECORD_SCOPE" == standalone \
      && "$CI_PROOF_RECORD_PID" == "$$" \
      && "$CI_PROOF_RECORD_LANE" == "$CI_PROOF_LOCK_LANE" ]] || {
      proof_lock_refusal
      return 75
    }
  else
    [[ "$CI_PROOF_RECORD_SCOPE" == family \
      && "$CI_PROOF_RECORD_PID" == "$PPID" \
      && "$CI_PROOF_RECORD_LANE" =~ ^family(-contract)?$ ]] || {
      proof_lock_refusal
      return 75
    }
  fi
}

acquire_proof_lock() {
  local lane="$1"
  CI_PROOF_LOCK_LANE="$lane"
  if $CI_PROOF_INHERITED_PRESENT; then
    CI_PROOF_LOCK_RECORD="$CI_PROOF_INHERITED_RECORD"
    CI_PROOF_LOCK_OWNS=false
    verify_proof_lock || return $?
    return 0
  fi
  [[ "$lane" =~ ^[a-z0-9-]+$ \
    && -d "$REPO_ROOT/.git" && ! -L "$REPO_ROOT/.git" \
    && -f "$REPO_ROOT/.git/HEAD" && ! -L "$REPO_ROOT/.git/HEAD" ]] || {
    proof_lock_refusal
    return 75
  }
  if ! (umask 077; mkdir -- "$CI_PROOF_LOCK_DIR") 2>/dev/null; then
    proof_lock_refusal
    return 75
  fi
  CI_PROOF_LOCK_OWNS=true
  CI_PROOF_LOCK_RECORD="schema=2 repository=bullet-kernel scope=standalone pid=$$ lane=$lane nonce=$$-${BASHPID:-$$}-$RANDOM-$RANDOM"
  if ! (umask 077; set -o noclobber; printf '%s\n' "$CI_PROOF_LOCK_RECORD" \
      >"$CI_PROOF_LOCK_OWNER") 2>/dev/null; then
    proof_lock_refusal
    return 75
  fi
  verify_proof_lock || return $?
}

release_proof_lock() {
  verify_proof_lock || return $?
  $CI_PROOF_LOCK_OWNS || return 0
  rm -- "$CI_PROOF_LOCK_OWNER" || {
    proof_lock_refusal
    return 75
  }
  rmdir -- "$CI_PROOF_LOCK_DIR" || {
    proof_lock_refusal
    return 75
  }
}

run_lane() {
  local lane="$1"
  case "$lane" in
    required) bash ops/ci/required.sh ;;
    fast)     bash ops/ci/fast.sh ;;
    lint)     bash ops/ci/lint.sh ;;
    contract) bash ops/ci/contract.sh ;;
    security) bash ops/ci/security.sh ;;
    docs)     bash ops/ci/docs.sh ;;
    family)   bash ops/ci/family.sh ;;
    preflight) bash ops/ci/preflight.sh ;;
    links)    bash ops/ci/links.sh ;;
    coverage) bash ops/ci/coverage.sh ;;
    history-secrets) bash ops/ci/history-secrets.sh ;;
    portable-refusal) bash ops/ci/portable-refusal.sh ;;
    nightly)  bash ops/ci/nightly.sh ;;
    audit)    bash ops/ci/audit.sh ;;
    egress)   bash ops/ci/egress.sh ;;
    toolchain-msrv) bash ops/ci/toolchain-msrv.sh ;;
    gates|all) bash ops/ci/required.sh ;;
    *)
      echo "usage: $0 {required|fast|lint|contract|security|docs|family|preflight|links|coverage|history-secrets|portable-refusal|audit|egress|nightly|toolchain-msrv|all}" >&2
      return 2
      ;;
  esac
}

run_with_proof_custody() {
  local lane="$1" status
  acquire_proof_lock "$lane" || return $?
  set +e
  run_lane "$lane"
  status=$?
  set -e
  verify_proof_lock || return $?
  release_proof_lock || return $?
  return "$status"
}

run_with_proof_custody "${1:-all}"
