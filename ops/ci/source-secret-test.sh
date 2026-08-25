#!/usr/bin/env bash
# Prove current-source scanning includes cached and nonignored untracked bytes,
# excludes ignored build output, and never follows a source symlink.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT

git -C "$test_root" init -q
printf '/target\n' >"$test_root/.gitignore"
printf 'ordinary source\n' >"$test_root/source.txt"
git -C "$test_root" add -- .gitignore source.txt

scan_current_source_secrets "$test_root"

mkdir -p "$test_root/target"
printf '%s%s\n' 'ghp_' 'abcdefghijklmnopqrstuvwxyz0123456789' >"$test_root/target/ignored.txt"
scan_current_source_secrets "$test_root"

printf '%s%s\n' 'ghp_' 'abcdefghijklmnopqrstuvwxyz0123456789' >"$test_root/untracked.txt"
if scan_current_source_secrets "$test_root"; then
  refuse SECRET_SCAN_UNTRACKED_BYPASS "a nonignored untracked canary passed"
  exit 1
fi
rm -f -- "$test_root/untracked.txt"

ln -s /etc/passwd "$test_root/escape"
if scan_current_source_secrets "$test_root"; then
  refuse SECRET_SCAN_SYMLINK_BYPASS "a nonignored symlink passed"
  exit 1
fi

log "current-source secret manifest and hostile boundaries passed"
