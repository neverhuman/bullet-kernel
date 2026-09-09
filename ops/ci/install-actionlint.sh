#!/usr/bin/env bash
set -euo pipefail
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_PATH:?GITHUB_PATH is required}"
version=1.7.8
sha256=be92c2652ab7b6d08425428797ceabeb16e31a781c07bc388456b4e592f3e36a
archive="$RUNNER_TEMP/actionlint_${version}_linux_amd64.tar.gz"
tools="$RUNNER_TEMP/bullet-tools-actionlint"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  "https://github.com/rhysd/actionlint/releases/download/v${version}/actionlint_${version}_linux_amd64.tar.gz" --output "$archive"
printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --status
mkdir -p "$tools"
tar -xzf "$archive" -C "$tools" actionlint
printf '%s\n' "$tools" >>"$GITHUB_PATH"
