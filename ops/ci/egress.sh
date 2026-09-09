#!/usr/bin/env bash
# Egress isolation lane: proves the user+net namespace, slirp4netns uplink,
# in-namespace nftables ruleset, and host CONNECT proxy live on this machine.
# The required lane ratchets these three identities but does not execute them:
# only this explicitly invoked, capability-admitted lane may run ignored tests.
# Exits 78 (typed neutral) when a required host tool or unprivileged namespaces
# are absent; it never reports green without running all three probes.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
export PATH="$PATH:/usr/sbin:/sbin"
log "egress lane: provider egress isolation proofs"
require_tool cargo-nextest || exit 1
require_tool jq || exit 1
neutral() {
  local reason="$1"
  shift
  log "neutral (78): $reason: $*"
  exit 78
}
missing=()
for tool in unshare nsenter slirp4netns nft curl cat kill; do
  type -P "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if ((${#missing[@]} > 0)); then
  neutral EGRESS_TOOLS_UNAVAILABLE "missing tool(s): ${missing[*]}"
fi
if ! unshare --user --map-root-user --net true >/dev/null 2>&1; then
  neutral EGRESS_NAMESPACES_UNAVAILABLE "unprivileged user+net namespaces are unavailable"
fi
selected="$(partition_count "$EGRESS_FILTER")"
if [[ "$selected" -ne "$EXPECTED_EGRESS_TESTS" || "$selected" -eq 0 ]]; then
  refuse TEST_PARTITION_DRIFT "egress selected $selected tests; expected $EXPECTED_EGRESS_TESTS"
  exit 1
fi
log "egress tests via nextest selected=$selected"
cargo nextest run --locked --workspace "${NEXTEST_FEATURES[@]}" --run-ignored all --no-tests fail -E "$EGRESS_FILTER"
log "egress lane passed"
