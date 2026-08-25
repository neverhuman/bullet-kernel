#!/usr/bin/env bash
# Egress isolation lane: proves the user+net namespace, slirp4netns uplink,
# in-namespace nftables ruleset, and host CONNECT proxy live on this machine.
# Exits 78 (neutral) when a required tool or unprivileged namespaces are
# absent; it never reports green without running the probes.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
export PATH="$PATH:/usr/sbin:/sbin"
log "egress lane: provider egress isolation proofs"
missing=()
for tool in unshare nsenter slirp4netns nft curl cat kill; do
  type -P "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if ((${#missing[@]} > 0)); then
  log "neutral (78): missing tool(s): ${missing[*]}"
  exit 78
fi
if ! unshare --user --map-root-user --net true >/dev/null 2>&1; then
  log "neutral (78): unprivileged user+net namespaces are unavailable"
  exit 78
fi
cargo test --locked -p bullet-harness-egress --test sandbox -- --ignored
log "egress lane passed"
