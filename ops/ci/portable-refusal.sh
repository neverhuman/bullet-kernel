#!/usr/bin/env bash
# Read-only portability proof: compile every target and execute the policy
# refusal that must happen before key probing or provider spawn.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

unset BULLET_GITD_BIN BULLET_GITD_SHA256
cargo check --locked --workspace --all-targets
cargo test --locked -p bullet-application \
  live_conformance::tests::v1alpha1_policy_refuses_before_key_probe_or_spawn -- --exact
log "portable compile + typed refusal passed"
