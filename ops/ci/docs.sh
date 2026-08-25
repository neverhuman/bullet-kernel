#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

log "docs lane: contract drift + rustdoc + repository-relative links"
cargo run --locked -q -p bullet --bin bullet -- contracts check
RUSTDOCFLAGS=-Dwarnings cargo doc --locked --workspace --no-deps
bash ops/ci/docs-check.sh
log "docs lane passed"
