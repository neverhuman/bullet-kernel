#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "fast lane: fmt + nextest"
cargo fmt --all --check
run_tests fast
python3 scripts/generate-types.py --check
log "fast lane passed"
