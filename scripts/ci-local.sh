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
CI_PROOF_TARGET=""
CI_PROOF_TARGET_ID=""
CI_PROOF_TARGET_FD=""
CI_PROOF_TARGET_OWNS=false
CI_PROOF_INHERITED_TARGET=false
if [[ ${CARGO_TARGET_DIR+x} || ${BULLET_CI_CARGO_TARGET_DIR+x} \
    || ${BULLET_CI_CARGO_TARGET_ID+x} ]]; then
  CI_PROOF_INHERITED_TARGET=true
fi
unset CARGO_TARGET_DIR BULLET_CI_CARGO_TARGET_DIR BULLET_CI_CARGO_TARGET_ID

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

proof_target_refusal() {
  printf '[ci] CI_PROOF_TARGET_UNTRUSTED: private Cargo target custody is ambiguous\n' >&2
  return 75
}

target_identity() {
  stat -Lc '%d:%i:%u:%a:%F' -- "$1" 2>/dev/null
}

verify_proof_target() {
  local canonical suffix uid
  uid="$(id -u)" || return 1
  suffix="${CI_PROOF_TARGET#"$REPO_ROOT/.git/bullet-ci-target."}"
  [[ -n "$CI_PROOF_TARGET" && -n "$CI_PROOF_TARGET_ID" \
    && "$CI_PROOF_TARGET" == "$REPO_ROOT/.git"/bullet-ci-target.* \
    && "$suffix" =~ ^[A-Za-z0-9]{10}$ \
    && "$CI_PROOF_TARGET" != / && "$CI_PROOF_TARGET" != "$REPO_ROOT" \
    && "$CI_PROOF_TARGET" != "$REPO_ROOT/target" \
    && ( -z "${HOME:-}" || "$CI_PROOF_TARGET" != "$HOME" ) \
    && -d "$CI_PROOF_TARGET" && ! -L "$CI_PROOF_TARGET" \
    && "$(find "$CI_PROOF_TARGET" -maxdepth 0 -type d -uid "$uid" -perm 0700 -print 2>/dev/null)" \
      == "$CI_PROOF_TARGET" ]] || {
    proof_target_refusal
    return 75
  }
  canonical="$(cd "$CI_PROOF_TARGET" && pwd -P)" || {
    proof_target_refusal
    return 75
  }
  [[ "$canonical" == "$CI_PROOF_TARGET" \
    && "$(target_identity "$CI_PROOF_TARGET")" == "$CI_PROOF_TARGET_ID" ]] || {
    proof_target_refusal
    return 75
  }
}

create_proof_target() {
  $CI_PROOF_INHERITED_TARGET && {
    proof_target_refusal
    return 75
  }
  if ! command -v mktemp >/dev/null 2>&1 || ! command -v stat >/dev/null 2>&1; then
    proof_target_refusal
    return 75
  fi
  CI_PROOF_TARGET="$(mktemp -d "$REPO_ROOT/.git/bullet-ci-target.XXXXXXXXXX")" || {
    proof_target_refusal
    return 75
  }
  CI_PROOF_TARGET_OWNS=true
  CI_PROOF_TARGET="$(cd "$CI_PROOF_TARGET" && pwd -P)" || return 75
  CI_PROOF_TARGET_ID="$(target_identity "$CI_PROOF_TARGET")" || return 75
  verify_proof_target || return $?
  exec {CI_PROOF_TARGET_FD}<"$CI_PROOF_TARGET" || {
    proof_target_refusal
    return 75
  }
  [[ "$(target_identity "/proc/self/fd/$CI_PROOF_TARGET_FD")" == "$CI_PROOF_TARGET_ID" ]] || {
    proof_target_refusal
    return 75
  }
  export CARGO_TARGET_DIR="$CI_PROOF_TARGET"
  export BULLET_CI_CARGO_TARGET_DIR="$CI_PROOF_TARGET"
  export BULLET_CI_CARGO_TARGET_ID="$CI_PROOF_TARGET_ID"
}

sanitized_outputs_hide_target() {
  local artifact
  [[ ! -e "$REPO_ROOT/.ci-artifacts" ]] && return 0
  [[ -d "$REPO_ROOT/.ci-artifacts" && ! -L "$REPO_ROOT/.ci-artifacts" ]] || {
    proof_target_refusal
    return 75
  }
  while IFS= read -r -d '' artifact; do
    if grep -F -q -- "$CI_PROOF_TARGET" "$artifact"; then
      proof_target_refusal
      return 75
    fi
  done < <(find "$REPO_ROOT/.ci-artifacts" -type f -print0)
}

release_proof_target() {
  local device inode owner mode kind quarantine suffix sealed_identity
  $CI_PROOF_TARGET_OWNS || return 0
  verify_proof_target || return $?
  [[ -n "$CI_PROOF_TARGET_FD" \
    && "$(target_identity "/proc/self/fd/$CI_PROOF_TARGET_FD")" == "$CI_PROOF_TARGET_ID" ]] || {
    proof_target_refusal
    return 75
  }
  suffix="${CI_PROOF_TARGET##*.}"
  IFS=: read -r device inode owner mode kind <<<"$CI_PROOF_TARGET_ID"
  [[ "$device" =~ ^[0-9]+$ && "$inode" =~ ^[0-9]+$ && "$owner" =~ ^[0-9]+$ \
    && "$mode" == 700 && "$kind" == directory ]] || {
    proof_target_refusal
    return 75
  }
  quarantine="$REPO_ROOT/.git/bullet-ci-target-quarantine.$device.$inode.$suffix"
  [[ ! -e "$quarantine" && ! -L "$quarantine" ]] || {
    proof_target_refusal
    return 75
  }
  mv -T -n -- "$CI_PROOF_TARGET" "$quarantine" || return 75
  [[ ! -e "$CI_PROOF_TARGET" && ! -L "$CI_PROOF_TARGET" \
    && -d "$quarantine" && ! -L "$quarantine" \
    && "$(target_identity "$quarantine")" == "$CI_PROOF_TARGET_ID" \
    && "$(target_identity "/proc/self/fd/$CI_PROOF_TARGET_FD")" == "$CI_PROOF_TARGET_ID" ]] || {
    proof_target_refusal
    return 75
  }
  find -H "/proc/self/fd/$CI_PROOF_TARGET_FD" -xdev -depth -mindepth 1 -delete \
    || return 75
  [[ -z "$(find -H "/proc/self/fd/$CI_PROOF_TARGET_FD" -xdev -mindepth 1 -print -quit)" \
    && "$(target_identity "$quarantine")" == "$CI_PROOF_TARGET_ID" \
    && "$(target_identity "/proc/self/fd/$CI_PROOF_TARGET_FD")" == "$CI_PROOF_TARGET_ID" ]] || {
    proof_target_refusal
    return 75
  }
  chmod 000 "/proc/self/fd/$CI_PROOF_TARGET_FD" || return 75
  sealed_identity="$(target_identity "/proc/self/fd/$CI_PROOF_TARGET_FD")" || return 75
  [[ "$sealed_identity" == "$device:$inode:$owner:0:directory" \
    && "$(target_identity "$quarantine")" == "$sealed_identity" ]] || {
    proof_target_refusal
    return 75
  }
  exec {CI_PROOF_TARGET_FD}<&-
  CI_PROOF_TARGET_OWNS=false
  unset CARGO_TARGET_DIR BULLET_CI_CARGO_TARGET_DIR BULLET_CI_CARGO_TARGET_ID
  printf '[ci] CI_PROOF_TARGET_QUARANTINED: sealed empty target retained for exact reconciliation\n'
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
    faults)   bash ops/ci/faults.sh ;;
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
      echo "usage: $0 {required|fast|lint|contract|security|docs|family|faults|preflight|links|coverage|history-secrets|portable-refusal|audit|egress|nightly|toolchain-msrv|all}" >&2
      return 2
      ;;
  esac
}

finalize_proof_custody() {
  local lane_status="$1" target_status=0
  verify_proof_lock || return $?
  verify_proof_target || return $?
  sanitized_outputs_hide_target || target_status=$?
  release_proof_target || return $?
  release_proof_lock || return $?
  [[ "$target_status" -eq 0 ]] || return "$target_status"
  return "$lane_status"
}

proof_custody_signal() {
  local signal_status="$1" status
  trap - HUP INT TERM
  set +e
  finalize_proof_custody "$signal_status"
  status=$?
  set -e
  exit "$status"
}

run_with_proof_custody() {
  local lane="$1" status
  acquire_proof_lock "$lane" || return $?
  if create_proof_target; then
    :
  else
    status=$?
    release_proof_lock || true
    return "$status"
  fi
  trap 'proof_custody_signal 129' HUP
  trap 'proof_custody_signal 130' INT
  trap 'proof_custody_signal 143' TERM
  set +e
  run_lane "$lane"
  status=$?
  set -e
  set +e
  finalize_proof_custody "$status"
  status=$?
  set -e
  trap - HUP INT TERM
  return "$status"
}

run_with_proof_custody "${1:-all}"
