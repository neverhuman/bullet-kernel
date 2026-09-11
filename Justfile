default:
    @just --list

setup: preflight
    umask 077 && rustup component add rustfmt clippy
    umask 077 && cargo fetch --locked

fast:
    @cargo nextest --version >/dev/null
    bash scripts/ci-local.sh fast

lint:
    bash scripts/ci-local.sh lint

check:
    bash scripts/ci-local.sh required

contract:
    bash scripts/ci-local.sh contract

security:
    bash scripts/ci-local.sh security

docs:
    bash scripts/ci-local.sh docs

family:
    bash scripts/ci-local.sh family

faults:
    bash scripts/ci-local.sh faults

proof-transaction-offline:
    bash ops/ci/proof-transaction-offline.sh

proof-transaction-offline-chaos:
    bash ops/ci/proof-transaction-offline-chaos.sh

proof-synthetic-dogfood:
    bash ops/ci/proof-synthetic-dogfood.sh

verify: check

demo:
    BULLET_DATA_DIR=./target/demo cargo run --locked -p bullet --bin bullet -- demo

audit:
    bash scripts/ci-local.sh audit

score:
    mkdir -p .jankurai
    rm -f .jankurai/repo-score.json .jankurai/repo-score.md .jankurai/repair-queue.jsonl
    jankurai audit . --full --no-score-history --json .jankurai/repo-score.json --md .jankurai/repo-score.md

nextest-fast:
    cargo nextest run --locked --workspace

check-types:
    cargo check -p bullet-domain

nextest-types:
    cargo nextest run -p bullet-domain

egress:
    bash scripts/ci-local.sh egress

nightly:
    bash scripts/ci-local.sh nightly

toolchain-msrv:
    bash scripts/ci-local.sh toolchain-msrv

preflight:
    bash scripts/ci-local.sh preflight

links:
    bash scripts/ci-local.sh links

coverage:
    bash scripts/ci-local.sh coverage

history-secrets:
    bash scripts/ci-local.sh history-secrets

portable-refusal:
    bash scripts/ci-local.sh portable-refusal

# Local Linux xbabe2 only, with CI/GITHUB_ACTIONS absent. Inputs:
# BULLET_TUIWRIGHT_{CARGO,RUSTC,BULLET}_{BIN,SHA256},
# BULLET_TUIWRIGHT_SOURCE_SHA256 (hash of sorted suite-file sha256sum lines),
# BULLET_TUIWRIGHT_OUTPUT (new absolute directory below a private 0700 parent).
# The lane builds --frozen and validates all fresh external artifacts itself.
operator-tui:
    bash scripts/ci-local.sh operator-tui
