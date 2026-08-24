#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
lane="${1:-all}"
case "$lane" in
  required) bash ops/ci/required.sh ;;
  fast)     bash ops/ci/fast.sh ;;
  gates|all) bash ops/ci/required.sh ;;
  *) echo "usage: $0 {required|fast|all}" >&2; exit 2 ;;
esac
