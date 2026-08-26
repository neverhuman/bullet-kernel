#!/usr/bin/env bash
# Meta-test for ops/ci/nightly.sh. It replaces `cargo` with a logger so it can
# assert the nightly emits, for every provider, both the frozen feature-gated
# refusal test AND the guarded live-conformance CLI run — and that a failing
# refusal test makes the whole lane fail. This keeps a zero-test nightly from
# passing: the exact `--exact` refusal test lines must be present.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

test_root="$(mktemp -d)"
cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT

fail() {
  printf 'nightly-test: %s\n' "$1" >&2
  exit 1
}

log_file="$test_root/cargo.log"
for binary in claude codex cursor-agent agy; do
  printf '#!/usr/bin/env bash\nexit 0\n' >"$test_root/$binary"
  chmod 700 "$test_root/$binary"
done
cat >"$test_root/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${BULLET_NIGHTLY_TEST_LOG:?}"
if [[ -n "${BULLET_NIGHTLY_FAIL_CRATE:-}" && "$*" == *"-p ${BULLET_NIGHTLY_FAIL_CRATE} "* ]]; then
  exit 17
fi
# The product returns 78 for either policy or runtime-observation refusal.
if [[ "$*" == *"provider live-conformance"* ]]; then
  if [[ -n "${BULLET_NIGHTLY_PONG_PROVIDER:-}" && "$*" == *"--provider ${BULLET_NIGHTLY_PONG_PROVIDER} "* ]]; then
    exit 0
  fi
  exit "${BULLET_NIGHTLY_POSITIVE_CODE:-78}"
fi
EOF
chmod 700 "$test_root/cargo"

set +e
PATH="$test_root:/usr/bin:/bin" \
  BULLET_NIGHTLY_TEST_LOG="$log_file" \
  BULLET_LIVE_PROVIDERS="claude,codex,cursor,agy" \
  bash ops/ci/nightly.sh
neutral_code=$?
set -e
if [[ "$neutral_code" -ne 78 ]]; then
  fail "four typed refusals must return neutral 78, got $neutral_code"
fi

mapfile -t calls <"$log_file"
providers=(claude codex cursor agy)
refusal=(
  "test --locked -p bullet-harness-claude --features live --test live -- live_feature_still_fails_closed_without_authority --exact"
  "test --locked -p bullet-harness-codex --features live --test live -- live_feature_still_fails_closed_without_authority --exact"
  "test --locked -p bullet-harness-cursor --features live --test live -- live_feature_fails_closed_and_creates_zero_artifacts --exact"
  "test --locked -p bullet-harness-antigravity --features live --test live -- live_feature_still_fails_closed_without_authority --exact"
)
if [[ "${#calls[@]}" -ne 8 ]]; then
  fail "expected 8 cargo calls (refusal + positive per provider), got ${#calls[@]}"
fi
for i in 0 1 2 3; do
  refusal_line="${calls[$((i * 2))]}"
  positive_line="${calls[$((i * 2 + 1))]}"
  if [[ "$refusal_line" != "${refusal[$i]}" ]]; then
    fail "refusal call $i mismatch: $refusal_line"
  fi
  if [[ "$positive_line" != "run --locked -q -p bullet --bin bullet -- provider live-conformance "* ]]; then
    fail "positive call $i is not a live-conformance run: $positive_line"
  fi
  if [[ "$positive_line" != *"--provider ${providers[$i]} "* ]]; then
    fail "positive call $i names the wrong provider: $positive_line"
  fi
done

# --- Real mode: requires an absolute BULLET_POLICY_PATH and targets the resolved real binary.
set +e
PATH="$test_root:/usr/bin:/bin" BULLET_NIGHTLY_TEST_LOG="$log_file" BULLET_LIVE_PROVIDERS="claude" \
  BULLET_LIVE_REAL=1 bash ops/ci/nightly.sh >/dev/null 2>&1
code=$?
set -e
if [[ "$code" -ne 1 ]]; then
  fail "real mode without BULLET_POLICY_PATH must exit 1, got $code"
fi
printf '{}\n' >"$test_root/policy.json"
: >"$log_file"
set +e
PATH="$test_root:/usr/bin:/bin" BULLET_NIGHTLY_TEST_LOG="$log_file" BULLET_LIVE_PROVIDERS="claude,agy" \
  BULLET_LIVE_REAL=1 BULLET_POLICY_PATH="$test_root/policy.json" bash ops/ci/nightly.sh >/dev/null
real_code=$?
set -e
if [[ "$real_code" -ne 78 ]]; then
  fail "real-mode typed refusals must return neutral 78, got $real_code"
fi
mapfile -t real_calls <"$log_file"
if [[ "${#real_calls[@]}" -ne 4 ]]; then
  fail "real mode: expected 4 cargo calls for two providers, got ${#real_calls[@]}"
fi
resolved_root="$(readlink -f "$test_root")"
if [[ "${real_calls[1]}" != *"--executable $resolved_root/claude"* ]]; then
  fail "real mode must target the resolved real claude binary: ${real_calls[1]}"
fi
if [[ "${real_calls[3]}" != *"--executable $resolved_root/agy"* ]]; then
  fail "real mode must target the resolved real agy binary: ${real_calls[3]}"
fi
if [[ "${real_calls[1]}" != *"--data-dir $REPO_ROOT/target/live/claude/"* ]]; then
  fail "real mode must keep receipts under target/live/<provider>: ${real_calls[1]}"
fi
rm -rf "$REPO_ROOT/target/live/claude" "$REPO_ROOT/target/live/agy"

# Every positive half must be PONG for green; one refusal keeps a mixed run neutral.
: >"$log_file"
PATH="$test_root:/usr/bin:/bin" BULLET_NIGHTLY_TEST_LOG="$log_file" \
  BULLET_NIGHTLY_POSITIVE_CODE=0 BULLET_LIVE_PROVIDERS="claude,codex" \
  bash ops/ci/nightly.sh >/dev/null
set +e
PATH="$test_root:/usr/bin:/bin" BULLET_NIGHTLY_TEST_LOG="$log_file" \
  BULLET_NIGHTLY_PONG_PROVIDER=claude BULLET_LIVE_PROVIDERS="claude,codex" \
  bash ops/ci/nightly.sh >/dev/null
mixed_code=$?
set -e
if [[ "$mixed_code" -ne 78 ]]; then
  fail "one PONG plus one refusal must return neutral 78, got $mixed_code"
fi

: >"$log_file"
if PATH="$test_root:/usr/bin:/bin" \
  BULLET_NIGHTLY_TEST_LOG="$log_file" \
  BULLET_NIGHTLY_FAIL_CRATE="bullet-harness-codex" \
  BULLET_LIVE_PROVIDERS="codex" \
  bash ops/ci/nightly.sh; then
  echo "nightly-test: a failing refusal test returned success" >&2
  exit 1
fi

log "nightly selection, failure precedence, PONG, and neutral outcomes passed"
