#!/usr/bin/env bash
# Security lane: secret scan, supply-chain policy, and workflow policy scan.
# Every step fails closed. A missing tool, a missing deny.toml, or an
# unfetchable advisory database fails the lane rather than reducing it to the
# checks that happen to be runnable.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "security lane"
require_tool gitleaks || exit 1
require_tool cargo-deny || exit 1
require_tool zizmor || exit 1
require_tool git || exit 1
require_exact_output "8.21.2" gitleaks version
require_exact_output "cargo-deny 0.19.8" cargo-deny --version
require_exact_output "zizmor 1.25.2" zizmor --version
[[ -f deny.toml ]] || { echo "[ci] deny.toml missing: no committed supply-chain policy" >&2; exit 1; }
scan_current_source_secrets
# The advisory database is refreshed and then independently proved fresh.
# cargo-deny 0.19.8 fetches it through the git CLI, and its capture() helper
# reads a non-zero git exit as success (upstream src/advisories/helpers/db.rs),
# so on a host that already has a database a failed fetch cannot fail the check.
# `maximum-db-staleness` in deny.toml does not close that hole either: a failed
# `git fetch` still rewrites FETCH_HEAD, so its timestamp looks current. The
# lane therefore reads the database's own newest commit. A missing, unreadable,
# or stale database is a typed refusal, never a skipped check.
cargo deny fetch db
advisory_db_max_age_days=14
advisory_db=""
for candidate in target/advisory-db/advisory-db-*; do
  [[ -d "$candidate/.git" ]] || continue
  advisory_db="$candidate"
  break
done
if [[ -z "$advisory_db" ]]; then
  echo "[ci] ADVISORY_DB_ABSENT: no advisory database under target/advisory-db" >&2
  echo "[ci] run 'cargo deny fetch db' on a host with network access" >&2
  exit 1
fi
if ! advisory_db_commit="$(git -C "$advisory_db" log -1 --format=%ct)"; then
  echo "[ci] ADVISORY_DB_UNREADABLE: $advisory_db has no readable git history" >&2
  exit 1
fi
advisory_db_age_days=$(( ( $(date -u +%s) - advisory_db_commit ) / 86400 ))
if (( advisory_db_age_days > advisory_db_max_age_days )); then
  printf '[ci] ADVISORY_DB_STALE: %s newest commit is %sd old, limit %sd\n' \
    "$advisory_db" "$advisory_db_age_days" "$advisory_db_max_age_days" >&2
  echo "[ci] refresh it on a host with network access; the scan is not trusted" >&2
  exit 1
fi
log "advisory database $advisory_db newest commit ${advisory_db_age_days}d old (limit ${advisory_db_max_age_days}d)"

# licenses/advisories/bans/sources are gated by the committed deny.toml policy.
cargo deny --locked check licenses advisories bans sources
# Audit the repository's GitHub automation bytes without traversing runtime
# state under .git. Offline mode is explicit, every ignore is forbidden, and
# collection warnings fail the command.
zizmor --offline --no-ignores --strict-collection .github
log "security lane passed"
