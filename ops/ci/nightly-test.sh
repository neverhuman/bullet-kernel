#!/usr/bin/env bash
# Meta-test for ops/ci/nightly.sh. It replaces `cargo` with a logger so it can
# assert the nightly emits, for every provider, both the frozen feature-gated
# refusal test AND the positive live-conformance CLI run — and that a failing
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
# The positive live-conformance half refuses (78) under the v1alpha1 policy.
if [[ "$*" == *"provider live-conformance"* ]]; then
  exit 78
fi
EOF
chmod 700 "$test_root/cargo"

PATH="$test_root:/usr/bin:/bin" \
  BULLET_NIGHTLY_TEST_LOG="$log_file" \
  BULLET_LIVE_PROVIDERS="claude,codex,cursor,agy" \
  bash ops/ci/nightly.sh

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
  if [[ "$positive_line" != "run --locked -q -p bullet -- provider live-conformance "* ]]; then
    fail "positive call $i is not a live-conformance run: $positive_line"
  fi
  if [[ "$positive_line" != *"--provider ${providers[$i]} "* ]]; then
    fail "positive call $i names the wrong provider: $positive_line"
  fi
done

: >"$log_file"
if PATH="$test_root:/usr/bin:/bin" \
  BULLET_NIGHTLY_TEST_LOG="$log_file" \
  BULLET_NIGHTLY_FAIL_CRATE="bullet-harness-codex" \
  BULLET_LIVE_PROVIDERS="codex" \
  bash ops/ci/nightly.sh; then
  echo "nightly-test: a failing refusal test returned success" >&2
  exit 1
fi

log "nightly exact live-test selection plus positive-half wiring passed"
