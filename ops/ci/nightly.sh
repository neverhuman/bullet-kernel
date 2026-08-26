#!/usr/bin/env bash
# Nightly provider lane. For each provider it (a) runs the frozen feature-gated
# refusal test and (b) runs the guarded live-conformance half through the CLI.
# Under the checked-in v1alpha1 policy every positive half refuses at
# POLICY_LIVE_ADMISSION_DISABLED. With a valid v1alpha2 policy, every current
# production adapter instead refuses at RUNTIME_PROBE_UNAVAILABLE before
# operator-key read, authority writes, egress, or spawn. Both are neutral 78.
# The lane is green only if every provider's future positive half produces a
# PONG-matching receipt (exit 0). Any typed refusal makes the lane neutral, and
# any refusal-test/execution/spawn failure wins as exit 1.
# BULLET_LIVE_PROVIDERS unset returns 78 to distinguish unregistered from success.
#
# Real mode (operator only): BULLET_LIVE_REAL=1 together with BULLET_POLICY_PATH
# naming an operator-ratified policy runs the positive half against the real,
# absolute provider binary and keeps every receipt under target/live/<provider>/.
# Without BULLET_LIVE_REAL=1 the positive half always targets a marker script, so
# a spawn under the checked-in policy is detected and fails the lane.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "nightly lane"
if [[ -z "${BULLET_LIVE_PROVIDERS:-}" ]]; then
  log "BULLET_LIVE_PROVIDERS unset; no live lane registered"
  exit 78
fi
real_mode=0
if [[ "${BULLET_LIVE_REAL:-0}" == "1" ]]; then
  if [[ -z "${BULLET_POLICY_PATH:-}" || "${BULLET_POLICY_PATH}" != /* ]]; then
    echo "[ci] BULLET_LIVE_REAL=1 requires BULLET_POLICY_PATH (absolute path to an operator-ratified policy)" >&2
    exit 1
  fi
  real_mode=1
  policy="$BULLET_POLICY_PATH"
  log "REAL MODE: positive halves target real provider binaries under policy $policy"
else
  policy="$REPO_ROOT/crates/application/tests/fixtures/policy-v1alpha1.json"
fi
status=0
neutral=0
IFS=',' read -ra providers <<< "$BULLET_LIVE_PROVIDERS"
for provider in "${providers[@]}"; do
  provider="${provider// /}"
  case "$provider" in
    claude)
      crate=bullet-harness-claude
      binary=claude
      test_name=live_feature_still_fails_closed_without_authority
      ;;
    codex)
      crate=bullet-harness-codex
      binary=codex
      test_name=live_feature_still_fails_closed_without_authority
      ;;
    cursor)
      crate=bullet-harness-cursor
      binary=cursor-agent
      test_name=live_feature_fails_closed_and_creates_zero_artifacts
      ;;
    agy)
      crate=bullet-harness-antigravity
      binary=agy
      test_name=live_feature_still_fails_closed_without_authority
      ;;
    *) echo "[ci] unknown live provider: $provider" >&2; exit 1 ;;
  esac
  require_tool "$binary" || exit 1
  log "live-feature refusal: $provider ($crate)"
  cargo test --locked -p "$crate" --features live --test live -- "$test_name" --exact || status=1

  bin_dir="$(mktemp -d)"
  if (( real_mode )); then
    # Real mode: the absolute, symlink-resolved provider binary; receipts are kept.
    executable="$(readlink -f "$(command -v "$binary")")"
    data_dir="$REPO_ROOT/target/live/$provider/$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$data_dir"
  else
    # Positive half: never point at the real binary. The marker records any spawn.
    data_dir="$(mktemp -d)"
    executable="$bin_dir/$binary"
    printf '#!/usr/bin/env bash\necho spawned >> %q\n' "$data_dir/SPAWNED" >"$executable"
    chmod 700 "$executable"
  fi
  log "live-conformance positive half: $provider"
  set +e
  BULLET_POLICY_PATH="$policy" \
    cargo run --locked -q -p bullet --bin bullet -- provider live-conformance \
      --data-dir "$data_dir" --provider "$provider" --executable "$executable"
  code=$?
  set -e
  case "$code" in
    0) log "positive half $provider: PONG receipt (data dir $data_dir)" ;;
    78)
      log "positive half $provider: typed neutral refusal (policy or runtime observation unavailable)"
      neutral=1
      ;;
    *) echo "[ci] positive half $provider failed (exit $code)" >&2; status=1 ;;
  esac
  if (( real_mode == 0 )); then
    if [[ -f "$data_dir/SPAWNED" ]]; then
      echo "[ci] provider $provider was spawned under the checked-in policy" >&2
      status=1
    fi
    rm -rf "$data_dir"
  fi
  rm -rf "$bin_dir"
done
if (( status != 0 )); then
  exit 1
fi
if (( neutral != 0 )); then
  exit 78
fi
exit 0
