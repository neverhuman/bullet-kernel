#!/usr/bin/env bash
# Local environment check: does this machine have what the ops/ci lanes need?
#
# It answers one question per lane -- "would this lane fail for an environment
# reason rather than a code reason?" -- and it answers it before you spend a
# build. It runs nothing from the lanes themselves and mutates nothing.
#
# Lanes mirror `scripts/ci-local.sh`. When a lane is added there, add its tool
# row here in the same change; a lane with no row is a usage error, never a
# silent pass.
set -euo pipefail

lane="${1:-all}"
case "$lane" in
  fast)     tools=(bash cargo cargo-nextest dirname git jq rustc) ;;
  contract) tools=(bash cargo cargo-nextest dirname git jq rustc) ;;
  security) tools=(bash cargo cargo-deny date dirname git gitleaks jq rustc zizmor) ;;
  required) tools=(bash cargo cargo-clippy cargo-deny cargo-nextest date dirname git gitleaks jq rustc rustfmt zizmor) ;;
  audit)    tools=(bash dirname git jankurai jq mkdir) ;;
  egress)   tools=(bash cargo cat curl dirname git jq kill nft nsenter rustc slirp4netns unshare) ;;
  nightly)  tools=(bash cargo dirname git jq rustc) ;;
  toolchain-msrv) tools=(b3sum bash cargo dirname git jq rustup) ;;
  all)      tools=(b3sum bash cargo cargo-clippy cargo-deny cargo-nextest cat curl date dirname git gitleaks jankurai jq kill mkdir rustc rustfmt rustup zizmor) ;;
  *)
    echo "ci-doctor: expected fast|contract|security|required|audit|nightly|egress|toolchain-msrv|all" >&2
    exit 2
    ;;
esac

missing=0
for tool in "${tools[@]}"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'ci-doctor: missing %s for %s\n' "$tool" "$lane" >&2
    missing=1
  fi
done
# The egress lane is allowed to be neutral (exit 78) on a host without
# namespaces, so report its tools but do not fail the doctor for them alone.
if [[ "$missing" -ne 0 && "$lane" != "egress" ]]; then
  exit 1
fi
if [[ "$missing" -ne 0 ]]; then
  echo "ci-doctor: egress lane will report neutral (78) on this host" >&2
fi

# Version pins. These are the exact versions the lanes and rust-toolchain.toml
# already depend on; a mismatch is reported here rather than as a confusing
# failure three minutes into a build.
if [[ "$lane" =~ ^(fast|contract|security|required|nightly|egress|all)$ ]]; then
  rust_version="$(rustc --version)"
  [[ "$rust_version" == "rustc 1.97.1 "* ]] || {
    printf 'ci-doctor: expected rustc 1.97.1 (rust-toolchain.toml), found %s\n' "$rust_version" >&2
    exit 1
  }
fi
if [[ "$lane" =~ ^(fast|contract|required|all)$ ]]; then
  nextest_version="$(cargo-nextest --version)"
  [[ "$nextest_version" == "cargo-nextest 0.9.137 "* ]] || {
    printf 'ci-doctor: expected cargo-nextest 0.9.137, found %s\n' "$nextest_version" >&2
    exit 1
  }
fi
if [[ "$lane" =~ ^(security|required|all)$ ]]; then
  [[ "$(gitleaks version)" == "8.21.2" ]] || {
    printf 'ci-doctor: expected gitleaks 8.21.2, found %s\n' "$(gitleaks version)" >&2
    exit 1
  }
  [[ "$(cargo-deny --version)" == "cargo-deny 0.19.8" ]] || {
    printf 'ci-doctor: expected cargo-deny 0.19.8, found %s\n' "$(cargo-deny --version)" >&2
    exit 1
  }
  [[ "$(zizmor --version)" == "zizmor 1.25.2" ]] || {
    printf 'ci-doctor: expected zizmor 1.25.2, found %s\n' "$(zizmor --version)" >&2
    exit 1
  }
fi
if [[ "$lane" == audit || "$lane" == all ]]; then
  [[ "$(jankurai --version)" == "jankurai 1.6.11" ]] || {
    printf 'ci-doctor: expected jankurai 1.6.11, found %s\n' "$(jankurai --version)" >&2
    exit 1
  }
fi
if [[ "$lane" == toolchain-msrv || "$lane" == all ]]; then
  [[ "$(b3sum --version)" == "b3sum 1.8.2" ]] || {
    printf 'ci-doctor: expected b3sum 1.8.2, found %s\n' "$(b3sum --version)" >&2
    exit 1
  }
  export RUSTUP_AUTO_INSTALL=0
  rustup toolchain list | grep -q '^1\.95\.0-' || {
    echo "ci-doctor: expected rustup toolchain 1.95.0 for toolchain-msrv; run: rustup toolchain install 1.95.0 --profile minimal" >&2
    exit 1
  }
fi
printf 'ci-doctor: %s lane tools present\n' "$lane"
