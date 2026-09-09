#!/usr/bin/env bash
# The source-scan lane runs before any dependency installation and greps with
# ripgrep, which the ubuntu-24.04 runner image does not carry. Installed the
# same way as gitleaks: pinned version, pinned digest, no package manager.
set -euo pipefail
version=14.1.1
target=x86_64-unknown-linux-musl
archive="${RUNNER_TEMP:?RUNNER_TEMP is required}/ripgrep-${version}-${target}.tar.gz"
tools_dir="$RUNNER_TEMP/bullet-tools"
expected='4cf9f2741e6c465ffdb7c26f38056a59e2a2544b51f7cc128ef28337eeae4d8e'
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  "https://github.com/BurntSushi/ripgrep/releases/download/${version}/ripgrep-${version}-${target}.tar.gz" \
  --output "$archive"
printf '%s  %s\n' "$expected" "$archive" | sha256sum --check --status
mkdir -p "$tools_dir"
tar -xzf "$archive" -C "$tools_dir" --strip-components=1 \
  "ripgrep-${version}-${target}/rg"
# `rg --version` reports `ripgrep 14.1.1 (rev ...)`, so match the prefix.
[[ "$("$tools_dir/rg" --version | head -n1)" == "ripgrep ${version}"* ]]
printf '%s\n' "$tools_dir" >>"${GITHUB_PATH:?GITHUB_PATH is required}"
