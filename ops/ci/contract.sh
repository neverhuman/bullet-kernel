#!/usr/bin/env bash
# Mock-only contract lane. No live models, GitHub, or MCP network.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "contract lane: harness tapes + simulators"
run_tests contract
cargo test --locked -p bullet-test-simulation -- --nocapture
log "contract lane passed"
