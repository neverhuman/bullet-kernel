#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

for tool in bash chmod cp find id ln mkdir mktemp mv rm sleep wc; do
  require_tool "$tool" || exit 1
done

test_root="$(mktemp -d)"
fixture="$test_root/repository"
outside="$test_root/outside"
holder_pid=""

cleanup() {
  local child_pid=""
  if [[ -f "$fixture/child.pid" ]]; then
    child_pid="$(<"$fixture/child.pid")"
  fi
  if [[ -n "$child_pid" && "$child_pid" =~ ^[0-9]+$ ]]; then
    kill "$child_pid" 2>/dev/null || true
  fi
  if [[ -n "$holder_pid" ]]; then
    kill "$holder_pid" 2>/dev/null || true
    wait "$holder_pid" 2>/dev/null || true
  fi
  rm -rf -- "$test_root"
}
trap cleanup EXIT

fail_test() {
  printf '[ci] proof-custody fixture failed: %s\n' "$*" >&2
  exit 1
}

wait_for_path() {
  local path="$1" attempt
  attempt=0
  while ((attempt < 250)); do
    ((attempt += 1))
    [[ -e "$path" ]] && return 0
    sleep 0.02
  done
  fail_test "timed out waiting for $path"
}

expect_refusal() {
  local label="$1" status="$2" output="$3"
  [[ "$status" -eq 75 ]] || fail_test "$label returned $status instead of 75"
  rg -q 'CI_PROOF_LOCKED_OR_STALE' "$output" \
    || fail_test "$label omitted the typed refusal"
}

reset_fixture_log() {
  : >"$fixture/children.log"
  rm -f -- "$fixture/child.pid" "$fixture/nested.status" \
    "$fixture/nested.output" "$fixture/token-leak" "$fixture/token-clean"
}

remove_parent_lock() {
  rm -f -- "$fixture/.git/bullet-ci.lock.d/owner"
  rmdir -- "$fixture/.git/bullet-ci.lock.d" 2>/dev/null || true
}

make_parent_lock() {
  local record="$1"
  mkdir -- "$fixture/.git/bullet-ci.lock.d"
  chmod 0700 "$fixture/.git/bullet-ci.lock.d"
  (umask 077; printf '%s\n' "$record" >"$fixture/.git/bullet-ci.lock.d/owner")
  chmod 0600 "$fixture/.git/bullet-ci.lock.d/owner"
}

run_standalone() {
  local output="$1"
  shift
  set +e
  (
    cd "$fixture"
    env "$@" bash scripts/ci-local.sh fast
  ) >"$output" 2>&1
  LAST_STATUS=$?
  set -e
}

run_inherited() {
  local record="$1" output="$2"
  shift 2
  local saved_root="$PWD"
  cd "$fixture"
  set +e
  BULLET_CI_PROOF_CUSTODY="$record" env "$@" bash scripts/ci-local.sh fast \
    >"$output" 2>&1
  LAST_STATUS=$?
  set -e
  cd "$saved_root"
}

mkdir -p -- "$fixture/.git" "$fixture/scripts" "$fixture/ops/ci" "$outside"
printf 'ref: refs/heads/main\n' >"$fixture/.git/HEAD"
cp -- scripts/ci-local.sh "$fixture/scripts/ci-local.sh"
cat >"$fixture/ops/ci/fast.sh" <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$$" >child.pid
printf 'child\n' >>children.log
if [[ ${BULLET_CI_PROOF_CUSTODY+x} ]]; then
  printf 'leaked\n' >token-leak
  exit 91
fi
printf 'clean\n' >token-clean
if [[ "${CI_FIXTURE_NESTED:-0}" == 1 ]]; then
  set +e
  bash scripts/ci-local.sh fast >nested.output 2>&1
  printf '%s\n' "$?" >nested.status
  set -e
fi
if [[ "${CI_FIXTURE_SUBSTITUTE:-0}" == 1 ]]; then
  printf 'forged\n' >.git/bullet-ci.lock.d/owner
fi
if [[ "${CI_FIXTURE_HOLD:-0}" == 1 ]]; then
  : >holder.started
  while [[ ! -e holder.release ]]; do sleep 0.02; done
fi
exit "${CI_FIXTURE_STATUS:-0}"
FIXTURE
chmod 0700 "$fixture/scripts/ci-local.sh" "$fixture/ops/ci/fast.sh"
printf 'outside-safe\n' >"$outside/sentinel"
printf 'protected\n' >"$fixture/protected"
reset_fixture_log

# A standalone dispatcher owns exact current-user 0700/0600 subjects even
# under a hostile caller umask. A contender refuses before a second child or
# protected-write opportunity, while normal PASS releases the reservation.
(
  cd "$fixture"
  umask 000
  exec env CI_FIXTURE_HOLD=1 bash scripts/ci-local.sh fast
) >"$test_root/holder.output" 2>&1 &
holder_pid=$!
wait_for_path "$fixture/holder.started"
uid="$(id -u)"
[[ "$(find "$fixture/.git/bullet-ci.lock.d" -maxdepth 0 -type d -uid "$uid" -perm 0700 -print)" \
  == "$fixture/.git/bullet-ci.lock.d" ]] || fail_test 'standalone lock mode or owner drifted'
[[ "$(find "$fixture/.git/bullet-ci.lock.d/owner" -maxdepth 0 -type f -uid "$uid" -perm 0600 -print)" \
  == "$fixture/.git/bullet-ci.lock.d/owner" ]] || fail_test 'standalone owner mode or owner drifted'
run_standalone "$test_root/contender.output"
expect_refusal contention "$LAST_STATUS" "$test_root/contender.output"
[[ "$(wc -l <"$fixture/children.log")" -eq 1 ]] || fail_test 'contender launched a child'
[[ "$(<"$fixture/protected")" == protected ]] || fail_test 'contender changed protected bytes'
: >"$fixture/holder.release"
wait "$holder_pid"
holder_pid=""
[[ ! -e "$fixture/.git/bullet-ci.lock.d" ]] || fail_test 'PASS retained standalone custody'

# Lane failure is returned exactly and still releases trusted standalone state.
reset_fixture_log
run_standalone "$test_root/failure.output" CI_FIXTURE_STATUS=19
[[ "$LAST_STATUS" -eq 19 ]] || fail_test "lane failure became $LAST_STATUS"
[[ ! -e "$fixture/.git/bullet-ci.lock.d" ]] || fail_test 'FAIL retained standalone custody'

# Family custody belongs to the immediate parent, may name a different family
# lane, never leaks to the child, refuses nested re-entry, and is never released
# by the member dispatcher.
reset_fixture_log
family_record="schema=2 repository=bullet-kernel scope=family pid=$$ lane=family-contract nonce=$$-${BASHPID:-$$}-101-202"
make_parent_lock "$family_record"
run_inherited "$family_record" "$test_root/inherited.output" CI_FIXTURE_NESTED=1
[[ "$LAST_STATUS" -eq 0 ]] || fail_test "inherited dispatch returned $LAST_STATUS"
[[ -f "$fixture/token-clean" && ! -e "$fixture/token-leak" ]] \
  || fail_test 'inherited token reached the lane child'
[[ "$(<"$fixture/nested.status")" -eq 75 ]] || fail_test 'nested dispatcher did not refuse'
rg -q 'CI_PROOF_LOCKED_OR_STALE' "$fixture/nested.output" \
  || fail_test 'nested dispatcher omitted typed refusal'
[[ "$(<"$fixture/.git/bullet-ci.lock.d/owner")" == "$family_record" ]] \
  || fail_test 'member changed parent-owned custody'
remove_parent_lock

# A consumed custody token cannot be replayed after the parent reservation is
# gone, and wrong repository/scope/PID records never start a child.
reset_fixture_log
run_inherited "$family_record" "$test_root/replay.output"
expect_refusal replay "$LAST_STATUS" "$test_root/replay.output"
[[ ! -s "$fixture/children.log" ]] || fail_test 'replay launched a child'

run_inherited "" "$test_root/empty-inherited.output"
expect_refusal empty-inherited "$LAST_STATUS" "$test_root/empty-inherited.output"
[[ ! -s "$fixture/children.log" ]] || fail_test 'empty inherited custody launched a child'

for hostile_record in \
  "schema=2 repository=bullet-git scope=family pid=$$ lane=family nonce=$$-${BASHPID:-$$}-707-808" \
  "schema=2 repository=bullet-kernel scope=standalone pid=$$ lane=fast nonce=$$-${BASHPID:-$$}-303-404" \
  "schema=2 repository=bullet-kernel scope=family pid=1 lane=family nonce=1-1-505-606" \
  "schema=2 repository=bullet-kernel scope=family pid=$$ lane=required nonce=$$-${BASHPID:-$$}-909-010" \
  "schema=2 repository=bullet-kernel scope=family pid=$$ lane=family nonce=nonnumeric"; do
  make_parent_lock "$hostile_record"
  run_inherited "$hostile_record" "$test_root/forged.output"
  expect_refusal forged "$LAST_STATUS" "$test_root/forged.output"
  remove_parent_lock
done
[[ ! -s "$fixture/children.log" ]] || fail_test 'forged record launched a child'

make_parent_lock "$family_record"
printf '\n' >>"$fixture/.git/bullet-ci.lock.d/owner"
run_inherited "$family_record" "$test_root/trailing-newline.output"
expect_refusal trailing-newline "$LAST_STATUS" "$test_root/trailing-newline.output"
remove_parent_lock
[[ ! -s "$fixture/children.log" ]] || fail_test 'non-exact owner bytes launched a child'

make_parent_lock "$family_record"
printf '%s\0\n' "$family_record" >"$fixture/.git/bullet-ci.lock.d/owner"
run_inherited "$family_record" "$test_root/nul-owner.output"
expect_refusal nul-owner "$LAST_STATUS" "$test_root/nul-owner.output"
remove_parent_lock
[[ ! -s "$fixture/children.log" ]] || fail_test 'NUL owner bytes launched a child'

# Wrong modes, record substitution, and symlinked authority subjects fail
# closed. The outside sentinel is never used as a cleanup target.
reset_fixture_log
make_parent_lock "$family_record"
chmod 0755 "$fixture/.git/bullet-ci.lock.d"
run_inherited "$family_record" "$test_root/wrong-mode.output"
expect_refusal wrong-mode "$LAST_STATUS" "$test_root/wrong-mode.output"
remove_parent_lock

make_parent_lock "$family_record"
chmod 0644 "$fixture/.git/bullet-ci.lock.d/owner"
run_inherited "$family_record" "$test_root/wrong-owner-mode.output"
expect_refusal wrong-owner-mode "$LAST_STATUS" "$test_root/wrong-owner-mode.output"
[[ "$(<"$fixture/.git/bullet-ci.lock.d/owner")" == "$family_record" \
  && "$(find "$fixture/.git/bullet-ci.lock.d" -maxdepth 0 -type d -uid "$uid" -perm 0700 -print)" \
    == "$fixture/.git/bullet-ci.lock.d" \
  && "$(find "$fixture/.git/bullet-ci.lock.d/owner" -maxdepth 0 -type f -uid "$uid" -perm 0644 -print)" \
    == "$fixture/.git/bullet-ci.lock.d/owner" \
  && ! -s "$fixture/children.log" ]] \
  || fail_test 'wrong owner mode changed custody bytes or launched a child'
chmod 0600 "$fixture/.git/bullet-ci.lock.d/owner"
remove_parent_lock

make_parent_lock "$family_record"
run_inherited "$family_record" "$test_root/substitution.output" CI_FIXTURE_SUBSTITUTE=1
expect_refusal substitution "$LAST_STATUS" "$test_root/substitution.output"
[[ "$(<"$fixture/.git/bullet-ci.lock.d/owner")" == forged ]] \
  || fail_test 'dispatcher rewrote substituted parent owner'
remove_parent_lock

mv -- "$fixture/.git" "$fixture/.git.real"
ln -s -- "$outside" "$fixture/.git"
run_standalone "$test_root/git-symlink.output"
expect_refusal git-symlink "$LAST_STATUS" "$test_root/git-symlink.output"
rm -- "$fixture/.git"
mv -- "$fixture/.git.real" "$fixture/.git"

reset_fixture_log
mv -- "$fixture/.git/HEAD" "$fixture/.git/HEAD.real"
run_standalone "$test_root/head-missing.output"
expect_refusal head-missing "$LAST_STATUS" "$test_root/head-missing.output"
ln -s -- "$outside/sentinel" "$fixture/.git/HEAD"
run_standalone "$test_root/head-symlink.output"
expect_refusal head-symlink "$LAST_STATUS" "$test_root/head-symlink.output"
rm -- "$fixture/.git/HEAD"
mv -- "$fixture/.git/HEAD.real" "$fixture/.git/HEAD"
[[ ! -s "$fixture/children.log" ]] || fail_test 'hostile HEAD launched a child'

mkdir -- "$outside/lock-target"
chmod 0700 "$outside/lock-target"
ln -s -- "$outside/lock-target" "$fixture/.git/bullet-ci.lock.d"
run_standalone "$test_root/lock-symlink.output"
expect_refusal lock-symlink "$LAST_STATUS" "$test_root/lock-symlink.output"
rm -- "$fixture/.git/bullet-ci.lock.d"

mkdir -- "$fixture/.git/bullet-ci.lock.d"
chmod 0700 "$fixture/.git/bullet-ci.lock.d"
printf '%s\n' "$family_record" >"$outside/owner-target"
chmod 0600 "$outside/owner-target"
ln -s -- "$outside/owner-target" "$fixture/.git/bullet-ci.lock.d/owner"
run_inherited "$family_record" "$test_root/owner-symlink.output"
expect_refusal owner-symlink "$LAST_STATUS" "$test_root/owner-symlink.output"
rm -- "$fixture/.git/bullet-ci.lock.d/owner"
rmdir -- "$fixture/.git/bullet-ci.lock.d"

[[ "$(<"$outside/sentinel")" == outside-safe ]] || fail_test 'outside sentinel changed'
[[ "$(<"$outside/owner-target")" == "$family_record" ]] \
  || fail_test 'symlink target changed'
log 'proof-custody fixture passed'
