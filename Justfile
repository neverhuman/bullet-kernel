default:
    @just --list

setup:
    rustup component add rustfmt clippy
    cargo fetch

fast:
    bash scripts/ci-local.sh fast

check:
    bash scripts/ci-local.sh required

contract:
    bash scripts/ci-local.sh contract

security:
    bash scripts/ci-local.sh security

verify: check

demo:
    BULLET_DATA_DIR=./target/demo cargo run -p bullet -- demo

audit:
    bash scripts/ci-local.sh audit

nightly:
    bash scripts/ci-local.sh nightly
