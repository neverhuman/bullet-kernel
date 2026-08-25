#!/usr/bin/env bash
# Mock-only contract lane. No live models, GitHub, or MCP network.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "contract lane: four offline provider protocols + simulations"
deny_sibling_gitd
run_partition_tests contract contract "$EXPECTED_CONTRACT_TESTS" "$CONTRACT_FILTER"
log "contract lane passed"
