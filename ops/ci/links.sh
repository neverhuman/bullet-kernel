#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

require_tool lychee || exit 1
require_tool rg || exit 1
require_exact_output "lychee 0.24.0" lychee --version
mapfile -t markdown_files < <(rg --files -g '*.md' | sort)
[[ "${#markdown_files[@]}" -gt 0 ]] || { refuse DOC_INVENTORY_EMPTY "no Markdown files found"; exit 1; }
lychee --no-progress --max-retries 2 --timeout 20 \
  --accept '200..=399,429' \
  --exclude '^https?://(127\.0\.0\.1|localhost)([:/]|$)' \
  "${markdown_files[@]}"
log "external links passed"
