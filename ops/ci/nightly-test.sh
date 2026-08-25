#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

test_root="$(mktemp -d)"
cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT

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
EOF
chmod 700 "$test_root/cargo"

PATH="$test_root:/usr/bin:/bin" \
  BULLET_NIGHTLY_TEST_LOG="$log_file" \
  BULLET_LIVE_PROVIDERS="claude,codex,cursor,agy" \
  bash ops/ci/nightly.sh

mapfile -t calls <"$log_file"
expected=(
  "test --locked -p bullet-harness-claude --features live --test live -- live_feature_still_fails_closed_without_authority --exact"
  "test --locked -p bullet-harness-codex --features live --test live -- live_feature_still_fails_closed_without_authority --exact"
  "test --locked -p bullet-harness-cursor --features live --test live -- live_feature_fails_closed_and_creates_zero_artifacts --exact"
  "test --locked -p bullet-harness-antigravity --features live --test live -- live_feature_still_fails_closed_without_authority --exact"
)
if [[ "${#calls[@]}" -ne "${#expected[@]}" ]]; then
  printf 'nightly-test: expected %s cargo calls, got %s\n' "${#expected[@]}" "${#calls[@]}" >&2
  exit 1
fi
for index in "${!expected[@]}"; do
  if [[ "${calls[$index]}" != "${expected[$index]}" ]]; then
    printf 'nightly-test: call %s mismatch\nexpected: %s\nactual:   %s\n' \
      "$index" "${expected[$index]}" "${calls[$index]}" >&2
    exit 1
  fi
done

: >"$log_file"
if PATH="$test_root:/usr/bin:/bin" \
  BULLET_NIGHTLY_TEST_LOG="$log_file" \
  BULLET_NIGHTLY_FAIL_CRATE="bullet-harness-codex" \
  BULLET_LIVE_PROVIDERS="codex" \
  bash ops/ci/nightly.sh; then
  echo "nightly-test: selected live-test failure returned success" >&2
  exit 1
fi

log "nightly exact live-test selection passed"
