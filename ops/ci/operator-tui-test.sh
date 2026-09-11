#!/usr/bin/env bash
# Component route/refusal tests only. This does not execute Cargo or Tuiwright.
set -euo pipefail
umask 077
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
evidence="$(mktemp -d "${TMPDIR:-/tmp}/bullet-operator-tui-route.XXXXXXXX")"
fixture="$evidence/repository"
mkdir -p "$fixture/scripts" "$fixture/ops/ci" "$fixture/.git" "$fixture/ops/qualification"
: >"$fixture/.git/HEAD"
cp "$root/scripts/ci-local.sh" "$fixture/scripts/"
cp "$root/ops/ci/"{operator-tui.sh,lib.sh,inventory.sh} "$fixture/ops/ci/"
cp -R "$root/ops/qualification/tuiwright" "$fixture/ops/qualification/"
sha256sum "$root/scripts/ci-local.sh" "$root/ops/ci/operator-tui.sh" \
  "$root/ops/ci/operator-tui-test.sh" >"$evidence/source.sha256"
trap 'printf "operator-tui-test: evidence=%s\n" "$evidence"' EXIT

fail() { printf 'OPERATOR_TUI_ROUTE_TEST_FAILED: %s\n' "$*" >&2; exit 1; }
assert_refusal() {
  local name="$1" expected_status="$2" reason="$3" status=0
  shift 3
  env -u CI -u GITHUB_ACTIONS -u CARGO_TARGET_DIR -u BULLET_CI_CARGO_TARGET_DIR \
    -u BULLET_CI_CARGO_TARGET_ID -u BULLET_CI_PROOF_CUSTODY \
    -u BULLET_TUIWRIGHT_CARGO_BIN -u BULLET_TUIWRIGHT_CARGO_SHA256 \
    -u BULLET_TUIWRIGHT_RUSTC_BIN -u BULLET_TUIWRIGHT_RUSTC_SHA256 \
    -u BULLET_TUIWRIGHT_BULLET_BIN -u BULLET_TUIWRIGHT_BULLET_SHA256 \
    -u BULLET_TUIWRIGHT_OUTPUT -u BULLET_TUIWRIGHT_SOURCE_SHA256 "$@" \
    >"$evidence/$name.stdout" 2>"$evidence/$name.stderr" || status=$?
  [[ "$status" -eq "$expected_status" ]] || fail "$name exit=$status expected=$expected_status"
  grep -Fq "$reason" "$evidence/$name.stderr" || fail "$name missing $reason"
  ! grep -Fq 'OPERATOR_TUI_COMPONENT_PASS' "$evidence/$name.stdout" || fail "$name claimed component pass"
  printf '%s\t%s\t%s\n' "$name" "$status" "$reason" >>"$evidence/refusals.tsv"
}

# Presence is what matters, including empty and false strings. Exercise the
# copied canonical dispatcher so a missing route is a failure, never a skip.
for variable in CI GITHUB_ACTIONS; do
  for value in '' false true; do
    assert_refusal "$variable-${value:-empty}" 78 OPERATOR_TUI_HOSTED_RUN_REFUSED \
      "$variable=$value" bash "$fixture/scripts/ci-local.sh" operator-tui
  done
done
# Direct execution cannot bypass wrapper-owned target admission. This case is
# host-dependent only in refusal reason and invokes no qualified child.
if [[ "$(uname -s)" == Linux && "$(</proc/sys/kernel/hostname)" == xbabe2 ]]; then
  assert_refusal direct-without-custody 78 OPERATOR_TUI_WRAPPER_REQUIRED bash "$fixture/ops/ci/operator-tui.sh"
else
  assert_refusal off-host 78 OPERATOR_TUI_HOST_NOT_ADMITTED bash "$fixture/scripts/ci-local.sh" operator-tui
fi

# Inspect the closed executor path on every host. The full suite runs only on
# its admitted host and is never replaced by these diagnostic checks.
grep -Fq 'operator-tui) bash ops/ci/operator-tui.sh ;;' "$fixture/scripts/ci-local.sh" || fail 'canonical route absent'
# shellcheck disable=SC2016 # Match literal source, not test environment expansions.
grep -Fq '"$cargo_bin" build --frozen --release' "$fixture/ops/ci/operator-tui.sh" || fail 'frozen build absent'
# shellcheck disable=SC2016 # Match literal source, not test environment expansions.
grep -Fq '"$output/harness" component --bullet "$bullet_bin" --sha256 "$bullet_sha"' "$fixture/ops/ci/operator-tui.sh" || fail 'real component invocation absent'
# shellcheck disable=SC2016 # Match literal source, not test environment expansions.
grep -Fq '.selected == $selected[0] and [.completed[].id] == $selected[0]' "$fixture/ops/ci/operator-tui.sh" || fail 'selection/completion equality absent'

# Admission-negative fixtures: explicit host observation is real, never spoofed
# to execute a positive suite. No selected input can reach a compiler here.
if [[ "$(uname -s)" == Linux && "$(</proc/sys/kernel/hostname)" == xbabe2 ]]; then
  native="$(realpath -e -- "$(type -P true)")"
  native_sha="$(sha256sum "$native" | cut -d ' ' -f1)"
  options=("BULLET_TUIWRIGHT_CARGO_BIN=$native" "BULLET_TUIWRIGHT_CARGO_SHA256=$native_sha"
    "BULLET_TUIWRIGHT_RUSTC_BIN=$native" "BULLET_TUIWRIGHT_RUSTC_SHA256=$native_sha"
    "BULLET_TUIWRIGHT_BULLET_BIN=$native" "BULLET_TUIWRIGHT_BULLET_SHA256=$native_sha")
  zeros="$(printf '%064d' 0)"
  assert_refusal missing-inputs 1 OPERATOR_TUI_BINARY_INPUT_INVALID \
    bash "$fixture/scripts/ci-local.sh" operator-tui
  assert_refusal wrong-native-digest 1 OPERATOR_TUI_BINARY_DIGEST_MISMATCH \
    "${options[@]}" "BULLET_TUIWRIGHT_CARGO_SHA256=$zeros" bash "$fixture/scripts/ci-local.sh" operator-tui
  printf '#!/bin/sh\nprintf executed >"%s"\n' "$evidence/must-not-execute" >"$evidence/probe.sh"
  chmod 0500 "$evidence/probe.sh"
  probe_sha="$(sha256sum "$evidence/probe.sh" | cut -d ' ' -f1)"
  assert_refusal script-probe-refused 1 OPERATOR_TUI_NATIVE_BINARY_REQUIRED \
    "${options[@]}" "BULLET_TUIWRIGHT_CARGO_BIN=$evidence/probe.sh" \
    "BULLET_TUIWRIGHT_CARGO_SHA256=$probe_sha" bash "$fixture/scripts/ci-local.sh" operator-tui
  [[ ! -e "$evidence/must-not-execute" ]] || fail 'script probe executed'
  mkdir "$evidence/prior-observation"
  printf 'historical receipt bytes\n' >"$evidence/prior-observation/manifest.json"
  assert_refusal stale-receipt 1 OPERATOR_TUI_OUTPUT_NOT_FRESH "${options[@]}" \
    "BULLET_TUIWRIGHT_OUTPUT=$evidence/prior-observation" bash "$fixture/scripts/ci-local.sh" operator-tui
  [[ "$(<"$evidence/prior-observation/manifest.json")" == 'historical receipt bytes' ]] || fail 'prior receipt overwritten'
  assert_refusal wrong-source 1 OPERATOR_TUI_SOURCE_DIGEST_MISMATCH "${options[@]}" \
    "BULLET_TUIWRIGHT_OUTPUT=$evidence/wrong-source" "BULLET_TUIWRIGHT_SOURCE_SHA256=$zeros" \
    bash "$fixture/scripts/ci-local.sh" operator-tui
  suite_sha="$(cd "$fixture" && find ops/qualification/tuiwright -type f -print0 \
    | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d ' ' -f1)"
  # A native zero-exit noncompiler cannot qualify the lane: no fresh compiled
  # harness exists. This intentionally uses true, never Cargo or a fake suite.
  assert_refusal zero-exit-without-build 1 OPERATOR_TUI_BUILD_ARTIFACT_MISSING "${options[@]}" \
    "BULLET_TUIWRIGHT_OUTPUT=$evidence/zero-exit" "BULLET_TUIWRIGHT_SOURCE_SHA256=$suite_sha" \
    bash "$fixture/scripts/ci-local.sh" operator-tui
fi
printf 'operator-tui-test: PASS (route/refusals only; actual Tuiwright unexecuted)\n'
