#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
lane="${1:-all}"
case "$lane" in
  required) bash ops/ci/required.sh ;;
  fast)     bash ops/ci/fast.sh ;;
  contract) bash ops/ci/contract.sh ;;
  security) bash ops/ci/security.sh ;;
  nightly)  bash ops/ci/nightly.sh ;;
  audit)    bash ops/ci/audit.sh ;;
  gates|all) bash ops/ci/required.sh && bash ops/ci/contract.sh ;;
  *) echo "usage: $0 {required|fast|contract|security|audit|nightly|all}" >&2; exit 2 ;;
esac
