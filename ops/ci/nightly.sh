#!/usr/bin/env bash
# Nightly provider lane. For each provider it (a) runs the frozen feature-gated
# refusal test and (b) runs the positive live-conformance half through the CLI.
# Under the checked-in v1alpha1 policy every positive half refuses at
# POLICY_LIVE_ADMISSION_DISABLED (exit 78) before any provider is spawned; that
# is a neutral outcome. The lane stays green only if every provider's positive
# half either produced a PONG-matching receipt (exit 0) or was policy-refused
# (exit 78) and no provider process was ever spawned; any other outcome fails.
# BULLET_LIVE_PROVIDERS unset returns 78 to distinguish unregistered from success.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "nightly lane"
if [[ -z "${BULLET_LIVE_PROVIDERS:-}" ]]; then
  log "BULLET_LIVE_PROVIDERS unset; no live lane registered"
  exit 78
fi
policy="$REPO_ROOT/crates/application/tests/fixtures/policy-v1alpha1.json"
status=0
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

  # Positive half: never point at the real binary. The marker records any spawn.
  data_dir="$(mktemp -d)"
  bin_dir="$(mktemp -d)"
  marker="$bin_dir/$binary"
  printf '#!/usr/bin/env bash\necho spawned >> %q\n' "$data_dir/SPAWNED" >"$marker"
  chmod 700 "$marker"
  log "live-conformance positive half: $provider"
  set +e
  BULLET_POLICY_PATH="$policy" \
    cargo run --locked -q -p bullet -- provider live-conformance \
      --data-dir "$data_dir" --provider "$provider" --executable "$marker"
  code=$?
  set -e
  case "$code" in
    0) log "positive half $provider: PONG receipt" ;;
    78) log "positive half $provider: POLICY_LIVE_ADMISSION_DISABLED (neutral refusal)" ;;
    *) echo "[ci] positive half $provider failed (exit $code)" >&2; status=1 ;;
  esac
  if [[ -f "$data_dir/SPAWNED" ]]; then
    echo "[ci] provider $provider was spawned under v1alpha1 policy" >&2
    status=1
  fi
  rm -rf "$data_dir" "$bin_dir"
done
exit "$status"
