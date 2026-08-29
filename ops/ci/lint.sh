#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

log "lint lane: fmt + clippy + workflow/shell/meta policy"
require_tool actionlint || exit 1
require_tool shellcheck || exit 1
require_tool rg || exit 1
require_tool python3 || exit 1
require_exact_output "1.7.8" actionlint -version
shellcheck_version="$(shellcheck --version | awk '$1 == "version:" { print $2 }')"
[[ "$shellcheck_version" == "0.10.0" ]] \
  || { refuse TOOL_VERSION_MISMATCH "expected ShellCheck 0.10.0, found $shellcheck_version"; exit 1; }

cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
actionlint
mapfile -t shell_files < <(rg --files -g '*.sh' | sort)
[[ "${#shell_files[@]}" -gt 0 ]] || { refuse SHELL_INVENTORY_EMPTY "no shell files found"; exit 1; }
shellcheck -x -P ops/ci "${shell_files[@]}"
bash ops/ci/proof-custody-test.sh
bash ops/ci/nextest-groups-test.sh
bash ops/ci/policy-metadata-test.sh
bash ops/ci/workflow-policy.sh
bash ops/ci/required-test.sh
bash ops/ci/aggregate-test.sh
bash ops/ci/proof-transaction-offline-test.sh
bash ops/ci/proof-transaction-offline-chaos-test.sh
bash ops/ci/proof-synthetic-dogfood-test.sh
bash ops/ci/inventory-test.sh
bash ops/ci/junit-test.sh
bash ops/ci/observation-test.sh
bash ops/ci/nightly-test.sh
bash ops/ci/source-secret-test.sh
log "lint lane passed"
