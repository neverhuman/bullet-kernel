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
  required|gates|all) tools=(actionlint awk basename bash cargo cargo-clippy cargo-deny cargo-nextest cat cmp cp date dirname find git gitleaks grep jq ln mkdir mktemp mv python3 realpath rg rm rustc rustfmt sed seq sha256sum shellcheck sort sync xargs zizmor) ;;
  fast)     tools=(awk basename bash cargo cargo-nextest dirname git jq mkdir mktemp mv rm rustc sync) ;;
  lint)     tools=(actionlint awk bash cargo cargo-clippy cmp cp dirname git jq ln mktemp python3 rg rm rustc rustfmt sha256sum shellcheck sort) ;;
  contract) tools=(awk basename bash cargo cargo-nextest dirname git jq mkdir mktemp mv rm rustc sync) ;;
  security) tools=(bash cargo cargo-deny cat date dirname git gitleaks jq mktemp rm rustc xargs zizmor) ;;
  docs)     tools=(awk bash cargo dirname git grep ln mkdir mktemp realpath rg rm rustc sed seq sort) ;;
  family)   tools=(bash cargo cargo-nextest dirname git jq realpath rustc sha256sum) ;;
  faults)   tools=(awk basename bash cargo cargo-nextest chmod cmp diff dirname git grep head jq mkdir mktemp mv rm rmdir rustc sha256sum sort stat sync) ;;
  preflight) tools=(awk bash cat dirname find git gitleaks mktemp rg rm sort xargs) ;;
  links)    tools=(bash dirname lychee rg sort) ;;
  coverage) tools=(bash cargo cargo-llvm-cov cargo-nextest dirname git jq mkdir rm rustc) ;;
  history-secrets) tools=(bash dirname git gitleaks) ;;
  portable-refusal) tools=(bash cargo dirname git rustc) ;;
  nightly)  tools=(bash cargo chmod date dirname git jq mkdir mktemp readlink rm rustc) ;;
  audit)    tools=(bash dirname git jankurai jq mkdir) ;;
  egress)   tools=(bash cargo cargo-nextest cat curl dirname git jq kill nft nsenter rustc slirp4netns unshare) ;;
  toolchain-msrv) tools=(awk b3sum bash cargo date dirname git grep jq rustup tee tr wc) ;;
  *)
    echo "ci-doctor: expected required|fast|lint|contract|security|docs|family|faults|preflight|links|coverage|history-secrets|portable-refusal|nightly|audit|egress|toolchain-msrv|gates|all" >&2
    exit 2
    ;;
esac

# Proof custody runs before the selected lane and needs these on every path.
tools+=(find id wc)

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
if [[ "$lane" =~ ^(required|fast|lint|contract|security|docs|family|faults|coverage|portable-refusal|nightly|egress|gates|all)$ ]]; then
  rust_version="$(rustc --version)"
  [[ "$rust_version" == "rustc 1.97.1 "* ]] || {
    printf 'ci-doctor: expected rustc 1.97.1 (rust-toolchain.toml), found %s\n' "$rust_version" >&2
    exit 1
  }
fi
if [[ "$lane" =~ ^(required|lint|gates|all)$ ]]; then
  actionlint_version="$(actionlint -version | awk 'NR == 1 { print; exit }')"
  [[ "$actionlint_version" == "1.7.8" ]] || {
    printf 'ci-doctor: expected actionlint 1.7.8, found %s\n' "$actionlint_version" >&2
    exit 1
  }
  shellcheck_version="$(shellcheck --version | awk '$1 == "version:" { print $2 }')"
  [[ "$shellcheck_version" == "0.10.0" ]] || {
    printf 'ci-doctor: expected ShellCheck 0.10.0, found %s\n' "$shellcheck_version" >&2
    exit 1
  }
fi
if [[ "$lane" =~ ^(required|fast|contract|family|faults|coverage|egress|gates|all)$ ]]; then
  nextest_version="$(cargo-nextest --version)"
  [[ "$nextest_version" == "cargo-nextest 0.9.137 "* ]] || {
    printf 'ci-doctor: expected cargo-nextest 0.9.137, found %s\n' "$nextest_version" >&2
    exit 1
  }
fi
if [[ "$lane" =~ ^(required|security|gates|all)$ ]]; then
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
if [[ "$lane" == audit ]]; then
  [[ "$(jankurai --version)" == "jankurai 1.6.11" ]] || {
    printf 'ci-doctor: expected jankurai 1.6.11, found %s\n' "$(jankurai --version)" >&2
    exit 1
  }
fi
if [[ "$lane" == links ]]; then
  [[ "$(lychee --version)" == "lychee 0.24.0" ]] || {
    printf 'ci-doctor: expected lychee 0.24.0, found %s\n' "$(lychee --version)" >&2
    exit 1
  }
fi
if [[ "$lane" == coverage ]]; then
  [[ "$(cargo llvm-cov --version)" == "cargo-llvm-cov 0.8.7" ]] || {
    printf 'ci-doctor: expected cargo-llvm-cov 0.8.7, found %s\n' "$(cargo llvm-cov --version)" >&2
    exit 1
  }
fi
if [[ "$lane" == preflight || "$lane" == history-secrets ]]; then
  [[ "$(gitleaks version)" == "8.21.2" ]] || {
    printf 'ci-doctor: expected gitleaks 8.21.2, found %s\n' "$(gitleaks version)" >&2
    exit 1
  }
fi
if [[ "$lane" == toolchain-msrv ]]; then
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
