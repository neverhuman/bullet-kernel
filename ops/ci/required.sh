#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "required lane: preflight + fast + lint + contract + security + docs"
bash ops/ci/preflight.sh
bash ops/ci/fast.sh
bash ops/ci/lint.sh
bash ops/ci/contract.sh
bash ops/ci/security.sh
bash ops/ci/docs.sh
log "required lane passed"
