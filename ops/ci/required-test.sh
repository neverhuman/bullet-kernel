#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT
calls="$test_root/calls"
mkdir "$test_root/bin"
printf '%s\n' \
  '#!/bin/sh' \
  "printf '%s\\n' \"\$1\" >>\"\$CI_REQUIRED_CALLS\"" \
  >"$test_root/bin/bash"
chmod +x "$test_root/bin/bash"

CI_REQUIRED_CALLS="$calls" PATH="$test_root/bin:$PATH" /usr/bin/bash ops/ci/required.sh >/dev/null
printf '%s\n' \
  ops/ci/preflight.sh \
  ops/ci/fast.sh \
  ops/ci/lint.sh \
  ops/ci/contract.sh \
  ops/ci/security.sh \
  ops/ci/docs.sh \
  >"$test_root/expected"
if ! cmp -s "$test_root/expected" "$calls"; then
  diff -u "$test_root/expected" "$calls" >&2 || true
  refuse REQUIRED_ORDER_INVALID "required must run preflight once before every dependency-consuming lane"
  exit 1
fi

printf '%s\n' \
  '#!/bin/sh' \
  "printf '%s\\n' \"\$(umask)\" >\"\$CI_OBSERVED_UMASK\"" \
  >"$test_root/bin/bash"
chmod +x "$test_root/bin/bash"
(
  umask 0002
  CI_OBSERVED_UMASK="$test_root/umask" PATH="$test_root/bin:$PATH" \
    /usr/bin/bash scripts/ci-local.sh fast >/dev/null
)
[[ "$(<"$test_root/umask")" == "0077" ]] \
  || { refuse SECURE_UMASK_INVALID "lane inherited $(<"$test_root/umask")"; exit 1; }

[[ "$(rg -c '^setup: preflight$' Justfile)" -eq 1 ]] \
  || { refuse SETUP_PREFLIGHT_MISSING "Justfile setup must depend on preflight exactly once"; exit 1; }
rg -Fxq '    cargo fetch --locked' Justfile \
  || { refuse SETUP_FETCH_MISSING "Justfile setup must retain locked dependency fetch"; exit 1; }
rg -Fxq '    bash scripts/ci-local.sh preflight' Justfile \
  || { refuse PREFLIGHT_RECIPE_MISSING "Justfile preflight must delegate to the local preflight lane"; exit 1; }

log "required and setup source-admission ordering passed"
