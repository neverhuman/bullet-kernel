#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
lane="${1:-all}"
case "$lane" in
  required) bash ops/ci/required.sh ;;
  fast)     bash ops/ci/fast.sh ;;
  lint)     bash ops/ci/lint.sh ;;
  contract) bash ops/ci/contract.sh ;;
  security) bash ops/ci/security.sh ;;
  docs)     bash ops/ci/docs.sh ;;
  family)   bash ops/ci/family.sh ;;
  preflight) bash ops/ci/preflight.sh ;;
  links)    bash ops/ci/links.sh ;;
  coverage) bash ops/ci/coverage.sh ;;
  history-secrets) bash ops/ci/history-secrets.sh ;;
  portable-refusal) bash ops/ci/portable-refusal.sh ;;
  nightly)  bash ops/ci/nightly.sh ;;
  audit)    bash ops/ci/audit.sh ;;
  egress)   bash ops/ci/egress.sh ;;
  toolchain-msrv) bash ops/ci/toolchain-msrv.sh ;;
  gates|all) bash ops/ci/required.sh ;;
  *) echo "usage: $0 {required|fast|lint|contract|security|docs|family|preflight|links|coverage|history-secrets|portable-refusal|audit|egress|nightly|toolchain-msrv|all}" >&2; exit 2 ;;
esac
