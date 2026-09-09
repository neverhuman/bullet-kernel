#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

log "docs lane: freshness + contract drift + rustdoc + repository-relative links"
bash ops/ci/docs-freshness-test.sh
bash ops/ci/docs-freshness.sh
cargo run --locked -q -p bullet --bin bullet -- contracts check
cargo test --locked -q -p bullet-farmd --lib \
  api::routes::tests::route_inventory_binds_router_readme_and_openapi -- --exact
RUSTDOCFLAGS=-Dwarnings cargo doc --locked --workspace --no-deps
bash ops/ci/docs-check.sh
log "docs lane passed"
